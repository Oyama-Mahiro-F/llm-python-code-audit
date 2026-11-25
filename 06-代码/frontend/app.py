# -*- coding: utf-8 -*-
"""可验证的大模型代码审计系统 —— 演示前端(Streamlit)。

设计目标(老师 2026-11-22 反馈第 2 条):让评审**亲手看到**每一步证据,而不是
只听一句结论。页面结构对应流水线:

    ① 选择案例 → ② 运行审计(SAST/LLM 候选 → 提取 → mock → 沙箱 → 判定)
    → ③ 统计摘要 → ④ 逐条 finding:具体描述 / 代码与证据链 / 截获实参 /
       CVE 参照 / 复现命令

运行:
    cd 06-代码
    .venv/Scripts/python.exe -m streamlit run frontend/app.py

说明:前端不重复实现业务逻辑,只调用既有 CLI(orchestrator prepare/collect),
因此界面展示的内容与落盘记录、报告完全一致(同一批 records)。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]      # 06-代码
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auditor import narrative  # noqa: E402

PY = sys.executable

# ---------------------------------------------------------------- 案例清单
DEMOS = {
    "案例 1:PHP SQL 注入(CWE-89)": {
        "project": "demos/case1_php_sqli",
        "alerts": "records/demos/case1_php_sqli/llm_candidates.json",
        "channel": "LLM 候选发现通道",
        "note": "官方规则集 p/default / p/php 对该样本均零命中,候选由 LLM 通道产出",
    },
    "案例 2:PHP 命令注入(CWE-78)": {
        "project": "demos/case2_php_cmd",
        "alerts": "records/demos/case2_php_cmd/sast_alerts.json",
        "channel": "SAST 规则扫描(p/default)",
        "note": "Semgrep 规则 metadata 记为 CWE-94,已按显式规则归一为 CWE-78(原值保留在 cwe_reported)",
    },
    "案例 3:Python 路径穿越(CWE-22)": {
        "project": "demos/case3_python_path",
        "alerts": "records/demos/case3_python_path/llm_candidates.json",
        "channel": "LLM 候选发现通道",
        "note": "官方规则集零命中;同时演示模块级常量 REPORT_DIR 被一并提取",
    },
    "综合样本集:4 文件 5 告警": {
        "project": "samples",
        "alerts": "records/sast_alerts_multi.json records/llm_candidates_multi.json",
        "channel": "SAST + LLM 双通道合并",
        "note": "含 CWE-89/78/22,以及参数化查询的安全对照样本(零告警)",
    },
}

BADGE = {"TP": "✅ 已确认 TP", "FP": "❌ 已排除 FP", "Unconfirmed": "⚠️ 未确认"}


def run_cmd(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(args, cwd=str(ROOT), capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def run_pipeline(demo: dict, mock_backend: str) -> tuple[bool, str]:
    run_id = "ui_" + Path(demo["project"]).name
    alerts = demo["alerts"].split()
    logs = []
    code, out = run_cmd([PY, "-m", "auditor.orchestrator", "prepare",
                         "--alerts", *alerts, "--project", demo["project"],
                         "--run-id", run_id, "--out",
                         f"records/demos/{Path(demo['project']).name}",
                         "--mock-backend", mock_backend])
    logs.append(f"[prepare] exit={code}\n{out[-1200:]}")
    if code != 0:
        return False, "\n".join(logs)

    cmd_file = (ROOT / "records" / "demos" / Path(demo["project"]).name
                / f"run_{run_id}" / "sandbox_cmds.sh")
    # 容器步骤经 shell 执行(与两阶段模式一致;标准终端下等价于 docker 直连)
    proc = subprocess.run(["bash", str(cmd_file)], cwd=str(ROOT),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    logs.append(f"[sandbox] exit={proc.returncode}\n{(proc.stdout or '')[-600:]}")

    # 沙箱是否真的执行:以落盘产物为准(命令无法写盘即未执行)
    run_dir = cmd_file.parent
    if not all((run_dir / n).exists()
               for n in ("stdout.txt", "exit_code.txt")):
        logs.append(
            "[sandbox] 容器步骤未执行:启动本界面的进程无法访问 Docker 命名管道。"
            "请在标准终端(WSL2 / PowerShell)启动界面,或手动执行 "
            f"{cmd_file} 后点「重新加载结果」。")
        return False, "\n".join(logs)

    code, out = run_cmd([PY, "-m", "auditor.orchestrator", "collect",
                         "--alerts", *alerts, "--project", demo["project"],
                         "--run-id", run_id, "--out",
                         f"records/demos/{Path(demo['project']).name}"])
    logs.append(f"[collect] exit={code}\n{out[-1200:]}")
    return code == 0, "\n".join(logs)


def load_report(project: str, run_id: str | None = None) -> dict | None:
    """优先读指定 run 的报告(多次运行互不覆盖),否则读最新一份。"""
    base = ROOT / "records" / "demos" / Path(project).name
    candidates = []
    if run_id:
        candidates.append(base / f"run_{run_id}" / "audit_report.json")
    candidates.append(base / "audit_report.json")
    for cand in candidates:
        if cand.exists():
            return json.loads(cand.read_text(encoding="utf-8"))
    return None


def read_text(path: str | None) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def render_finding(f: dict) -> None:
    nar = f.get("narrative") or {}
    v = f.get("verdict") or {}
    label = v.get("verdict", "Unconfirmed")
    title = nar.get("title") or f.get("cwe")
    st.markdown(f"### {f['alert_id']} · {title}")
    st.markdown(f"**{BADGE.get(label, label)}** ｜ 判定模式 {v.get('mode')} "
                f"｜ 依据:{v.get('confirmed_by', '-')}")

    if nar.get("text"):
        st.info(nar["text"])
    else:
        st.warning(v.get("reason", ""))

    # ---- 证据链 ----
    st.markdown("**证据链**")
    rows = [
        ("① 污点源", nar.get("source", {}).get("desc", "-")),
        ("② 传播", (nar.get("propagation") or {}).get("code") or "-"),
        ("③ sink", f"{nar.get('sink', {}).get('api', '-')}  "
                    f"@ 第 {(nar.get('sink') or {}).get('line', '-')} 行"),
        ("④ 沙箱截获实参", nar.get("captured_arg") or "(未截获)"),
        ("⑤ payload", nar.get("payload") or "-"),
    ]
    for k, val in rows:
        st.markdown(f"- **{k}**:`{val}`")

    cve = nar.get("cve_ref")
    if cve:
        st.markdown(f"**CVE 参照**:[{cve['cve_id']}]({cve.get('nvd_url')}) — "
                    f"{cve.get('summary_zh', '')}"
                    + (f"(CVSS {cve['cvss']})" if cve.get("cvss") else "")
                    + "(经 NVD API 核验;匹配不到时此处留空,不臆造)")

    # ---- 代码 + 运行产物 ----
    ev = f.get("evidence") or {}
    run_dir = Path(ev.get("run_dir") or "")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**被提取的业务代码(snippet)**")
        snippet_file = (f.get("extract") or {}).get("snippet_file") or "snippet.py"
        st.code(read_text(str(run_dir / snippet_file)) or "(缺失)",
                language="php" if snippet_file.endswith(".php") else "python")
    with c2:
        st.markdown("**mock 桩(危险操作被拦截)**")
        mock_file = (f.get("mock") or {}).get("mock_file") or "mock_patch.py"
        st.code(read_text(str(run_dir / mock_file)) or "(缺失)",
                language="php" if mock_file.endswith(".php") else "python")

    with st.expander("harness 组装产物(业务片段 + mock + payload 注入)"):
        harness_file = (f.get("harness") or {}).get("harness_file") or "harness.py"
        st.code(read_text(str(run_dir / harness_file)) or "(缺失)",
                language="php" if harness_file.endswith(".php") else "python")
        applied = (f.get("harness") or {}).get("redirects_applied") or []
        if applied:
            st.caption("接缝重定向(把 sink 调用改到 __mock_*):"
                       + ", ".join(f"{a['name']}×{a['count']}" for a in applied))

    with st.expander("沙箱运行日志(stdout / stderr / 退出码)"):
        st.code((f.get("run") or {}).get("stdout_tail", ""), language="json")
        err = (f.get("run") or {}).get("stderr_tail", "")
        if err.strip():
            st.code(err, language="text")
        st.caption(f"exit_code={(f.get('run') or {}).get('exit_code')} ｜ "
                   f"env_ok={(f.get('run') or {}).get('env_ok')} ｜ "
                   f"镜像 {(f.get('run') or {}).get('env_snapshot', {}).get('image')} "
                   f"digest {(f.get('run') or {}).get('env_snapshot', {}).get('image_id')}")

    st.markdown("**第三方复现命令**(换一台机器执行,应得到同一结论)")
    st.code(ev.get("replay_command") or "(缺失)", language="bash")


# ---------------------------------------------------------------- 页面
st.set_page_config(page_title="可验证的大模型代码审计系统",
                   page_icon="🛡️", layout="wide")

st.title("🛡️ 可验证的大模型代码审计系统")
st.caption("判定依据不是模型的自述,而是代码在隔离沙箱里**真的跑出来的执行结果** ｜ "
           "每组结论附可执行 harness、payload、环境快照与运行日志")

with st.sidebar:
    st.header("运行设置")
    demo_key = st.selectbox("选择案例", list(DEMOS.keys()))
    demo = DEMOS[demo_key]
    mock_backend = st.radio("mock 生成方式",
                            ["template", "deepseek"],
                            help="template=内置模板(确定性、零 API 成本);"
                                 "deepseek=大模型生成(需环境变量 DEEPSEEK_API_KEY)")
    st.caption(demo["note"])
    go = st.button("▶ 运行审计", type="primary", use_container_width=True)
    st.divider()
    st.markdown("**流水线**\n\n候选(SAST/LLM)→ 提取函数 → 生成 mock → "
                "Docker 沙箱执行 → 判定(三分类)→ 报告")

project = demo["project"]
ui_run_id = "ui_" + Path(project).name
if go:
    with st.spinner("正在运行:候选 → 提取 → mock → 沙箱执行 → 判定 …"):
        ok, log = run_pipeline(demo, mock_backend)
    if ok:
        st.success("审计完成:全部产物已落盘 records/")
        st.session_state["last_run_id"] = ui_run_id
    else:
        if "容器步骤未执行" in log:
            st.warning(
                "本次容器步骤被宿主策略拒绝(无法访问 Docker),**没有产生新的判定**。"
                "可选:① 在标准终端(WSL2 / PowerShell)启动本界面;"
                "② 手动执行上一步生成的 `sandbox_cmds.sh`,再点「重新加载结果」;"
                "③ 直接查看下方已落盘的历史运行结果(证据完整、可复现)。")
        else:
            st.error("流水线执行失败,详见下方日志")
    with st.expander("运行日志", expanded=not ok):
        st.code(log, language="text")

if st.button("🔄 重新加载结果"):
    st.rerun()

report = load_report(project, st.session_state.get("last_run_id"))
if report is None:
    st.info("尚无结果。请在左侧选择案例并点击「运行审计」。")
    st.stop()

summary = report.get("summary") or {}
counts = summary.get("counts") or {}
findings = report.get("findings") or []

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("候选告警", summary.get("total", 0))
c2.metric("已确认 TP", counts.get("TP", 0))
c3.metric("已排除 FP", counts.get("FP", 0))
c4.metric("未确认", counts.get("Unconfirmed", 0),
          help="环境问题或未得出确定结论,不计入误报——方法局限如实单列")
c5.metric("LLM 调用", summary.get("llm_calls", 0))

st.caption(f"运行编号 {summary.get('run_id')} ｜ 生成时间 {summary.get('generated_at')}"
           f" ｜ 候选来源:{demo['channel']}")
st.divider()

for f in findings:
    render_finding(f)
    st.divider()

with st.expander("原始审计报告(audit_report.json)"):
    st.json(report)
