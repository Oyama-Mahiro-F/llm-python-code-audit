# -*- coding: utf-8 -*-
"""编排器(对应《项目方案》4.3 整体调度 + 开题 4.6 接口契约)。

外层编排程序是唯一控制流:提取、组装、执行、判定、重试计数与分支
判决全部由本模块的确定性代码完成;大模型(LLM_BACKEND)未接入,
不参与任何分支决策。

三种运行方式(subcommand):
  run       一体化模式:编排器直接调用 docker(标准环境,如 Linux/WSL2)
  prepare   两阶段模式第 1 步:完成提取/组装,生成 sandbox_cmds.sh
            (容器步骤交由 shell 执行——本机 ZCode 会话沙箱不允许
            Python 子进程访问 Docker 命名管道,故采用此路径)
  collect   两阶段模式第 3 步:回收沙箱产物,判定并产出报告

示例(本机,两阶段):
    python -m auditor.orchestrator prepare --alerts records/sast_alerts.json \
        --project samples --run-id demo --out records
    bash records/run_demo/sandbox_cmds.sh
    python -m auditor.orchestrator collect --alerts records/sast_alerts.json \
        --project samples --run-id demo --out records

产出:records/run_<run_id>/<alert_id>/ 各阶段产物、
      records/alerts_result.jsonl、records/audit_report.json / .md
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import extract, harness, mock_gen, sandbox, verdict

MAX_RETRIES = 3          # 重试上限(方案 4.3.5)
MAX_LLM_CALLS = 12       # 单告警 LLM 调用预算上限(预算控制)


def _alert_relpath(alert: dict, project_dir: Path) -> Path:
    """容器内扫描路径 /src/<name> 映射回宿主机 project_dir/<name>。"""
    return project_dir / Path(alert.get("path", "")).name


def _mock_kwargs(args) -> dict:
    """从 CLI 参数提取 mock 生成后端配置。"""
    from .llm_discover import DEFAULT_MODEL
    return {
        "backend": getattr(args, "mock_backend", None) or None,
        "model": getattr(args, "mock_model", None) or DEFAULT_MODEL,
        "replay_file": getattr(args, "mock_replay_file", None),
        "record_dir": getattr(args, "mock_record_dir", None),
    }


def _judge_kwargs(args) -> dict:
    """从 CLI 参数提取模式 B 判定后端配置。"""
    from .llm_discover import DEFAULT_MODEL
    return {
        "backend": getattr(args, "judge_backend", None) or None,
        "model": getattr(args, "judge_model", None) or DEFAULT_MODEL,
        "replay_file": getattr(args, "judge_replay_file", None),
        "record_dir": getattr(args, "judge_record_dir", None),
    }


def _make_judge(args):
    """按判定模式构造模式 B 后端;模式 A 返回 None(纯确定性,无 LLM)。"""
    from .llm_discover import make_backend
    mode = getattr(args, "verdict_mode", "A") or "A"
    if mode != "B":
        return None
    kw = _judge_kwargs(args)
    return make_backend(kw["backend"] or "dry", model=kw["model"],
                        replay_file=kw["replay_file"],
                        record_dir=kw["record_dir"])


def _static_understanding() -> dict:
    return {
        "status": "llm_pending",
        "note": "逐告警静态理解未接入;候选发现已由 llm_discover 覆盖",
    }


def prepare_alert(alert: dict, project_dir: Path, run_dir: Path,
                  mock_kwargs: dict | None = None) -> dict:
    """阶段 1:提取 + mock + 组装;落盘各阶段产物。"""
    run_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "alert_id": alert["alert_id"],
        "cwe": alert.get("cwe"),
        "source_alert": {k: alert.get(k) for k in
                         ("check_id", "path", "line", "end_line", "message")},
        "static_understanding": _static_understanding(),
        "extract": None, "harness": None, "run": None,
        "verdict": None, "retries": [], "pending_attempt": None,
        "overhead": {"llm_calls": 0, "sandbox_runs": 1, "wall_time_s": None},
        "evidence": None,
    }
    src_file = _alert_relpath(alert, project_dir)
    extract_meta = extract.extract(src_file, alert["line"], run_dir)
    state["extract"] = extract_meta
    if not extract_meta.get("ok"):
        return state

    mock_meta = mock_gen.generate(alert, extract_meta, run_dir,
                                  **(mock_kwargs or {}))
    state["overhead"]["llm_calls"] += mock_meta.get("llm_calls", 0)
    state["mock"] = {k: mock_meta.get(k) for k in
                     ("generated_by", "template", "rationale", "error",
                      "fallback_reason") if mock_meta.get(k)}
    harness_meta = harness.assemble(alert, extract_meta, mock_meta, run_dir)
    state["harness"] = harness_meta
    return state


def collect_alert(alert: dict, state: dict, run_dir: Path,
                  judge_be=None, verdict_mode: str = "A",
                  judge_key: str = "") -> dict:
    """阶段 3:回收沙箱产物 → 判定(模式 A/B)→ 证据材料。"""
    if state["harness"] is None or not state["harness"].get("assemble_ok"):
        reason = (state["extract"].get("error")
                  if state["extract"] and not state["extract"].get("ok")
                  else (state["harness"] or {}).get("assemble_error"))
        state["verdict"] = {"verdict": "Unconfirmed",
                            "reason": f"流水线前段失败:{reason}",
                            "mode": verdict_mode, "fix_suggestion": None,
                            "confirmed_by": "execution"}
        return state

    run = sandbox.load_captured(run_dir)
    state["run"] = {k: run.get(k) for k in
                    ("env_ok", "exit_code", "elapsed_s", "replay_command")}
    state["run"]["env_snapshot"] = run["env"]
    state["run"]["stdout_tail"] = (run.get("stdout") or "")[-500:]
    state["run"]["stderr_tail"] = (run.get("stderr") or "")[-500:]

    payload_path = run_dir / "payload.txt"
    payload = (payload_path.read_text(encoding="utf-8")
               if payload_path.exists() else "")

    if verdict_mode == "B" and judge_be is not None:
        evidence = {}
        for name, fname in (("snippet", "snippet.py"),
                            ("mock", "mock_patch.py")):
            f = run_dir / fname
            evidence[name] = (f.read_text(encoding="utf-8")
                              if f.exists() else None)
        state["verdict"] = verdict.judge_mode_b(
            alert, payload, run, evidence, judge_be, key=judge_key)
        state["overhead"]["llm_calls"] += \
            state["verdict"].get("judge_llm_calls", 0)
    else:
        state["verdict"] = verdict.judge_mode_a(alert, payload, run)

    state["evidence"] = {
        "run_dir": run_dir.resolve().as_posix(),
        "harness_path": state["harness"].get("harness_path"),
        "payload": payload or None,
        "env_snapshot": run["env"],
        "replay_command": run.get("replay_command"),
        "stdout_tail": state["run"]["stdout_tail"],
    }
    return state


def _finalize(out_dir: Path, run_base: Path, run_id: str,
              states: list[dict]) -> None:
    (out_dir / "alerts_result.jsonl").write_text(
        "\n".join(json.dumps(s, ensure_ascii=False) for s in states) + "\n",
        encoding="utf-8")
    counts = {"TP": 0, "FP": 0, "Unconfirmed": 0}
    for s in states:
        label = (s.get("verdict") or {}).get("verdict", "Unconfirmed")
        counts[label] = counts.get(label, 0) + 1
    llm_calls = sum(s.get("overhead", {}).get("llm_calls", 0) for s in states)
    summary = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(states),
        "counts": counts,
        "unconfirmed_rate": (counts["Unconfirmed"] / len(states))
        if states else None,
        "llm_calls": llm_calls,
        "note": "mock 生成后端见各 finding 的 mock.generated_by;"
                "判定均为模式 A(确定性)",
    }
    (out_dir / "audit_report.json").write_text(
        json.dumps({"summary": summary, "findings": states},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# 审计报告(中期演示)", "",
             f"- 运行编号:{run_id}",
             f"- 告警总数:{summary['total']}",
             f"- 判定分布:TP={counts['TP']}, FP={counts['FP']}, "
             f"未确认={counts['Unconfirmed']}", ""]
    for s in states:
        v = s.get("verdict") or {}
        lines += [f"## {s['alert_id']}({s.get('cwe')})",
                  f"- 判定:**{v.get('verdict')}** —— {v.get('reason')}",
                  f"- 复现命令:{(s.get('evidence') or {}).get('replay_command')}",
                  ""]
    (out_dir / "audit_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[orchestrator] summary: {counts} -> "
          f"{(out_dir / 'audit_report.json').resolve().as_posix()}")


def _load_alerts(paths) -> list[dict]:
    """读取一个或多个候选来源的 alerts,按 alert_id 去重后合并。

    支持多来源:SAST 的 `A-*`(sast_alerts.json)与 LLM 发现的 `L-*`
    (llm_candidates.json)前缀不同,合并后全局唯一;下游流程无需区分来源。
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    out: list[dict] = []
    seen: set = set()
    for p in paths:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        for a in doc.get("alerts", []):
            aid = a.get("alert_id")
            if aid in seen:
                continue
            seen.add(aid)
            out.append(a)
    return out


def cmd_prepare(args) -> int:
    alerts = _load_alerts(args.alerts)
    out_dir = Path(args.out)
    run_base = out_dir / f"run_{args.run_id}"
    run_base.mkdir(parents=True, exist_ok=True)
    project_dir = Path(args.project).resolve()
    mk = _mock_kwargs(args)

    cmds = ["#!/usr/bin/env bash",
            "# 由 auditor.orchestrator prepare 生成;执行容器内 harness。",
            "set -u",
            "# Git Bash 会把 /work 改写为 Windows 路径,此变量在 Linux 上无副作用",
            "export MSYS_NO_PATHCONV=1"]
    states = []
    for alert in alerts:
        run_dir = run_base / alert["alert_id"]
        st = prepare_alert(alert, project_dir, run_dir, mk)
        states.append(st)
        label = st["harness"]["assemble_ok"] if st["harness"] else False
        gen_by = (st.get("mock") or {}).get("generated_by", "-")
        print(f"[prepare] {alert['alert_id']}: "
              f"extract={'ok' if st['extract'].get('ok') else 'fail'} "
              f"harness={'ok' if label else 'fail'} mock={gen_by}")
        if st["harness"] and st["harness"].get("assemble_ok"):
            cmds.append(sandbox.emit_command_file(run_dir))
    cmds.append('echo "sandbox step done"')
    (run_base / "sandbox_cmds.sh").write_text("\n".join(cmds) + "\n",
                                              encoding="utf-8")
    # 暂存阶段 1 状态,collect 阶段续用
    (run_base / "_prepare_states.json").write_text(
        json.dumps(states, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[prepare] sandbox_cmds.sh -> {run_base.as_posix()}")
    return 0


def cmd_collect(args) -> int:
    round_no = getattr(args, "round", 1) or 1
    run_base = Path(args.out) / f"run_{args.run_id}"
    states = json.loads((run_base / "_prepare_states.json")
                        .read_text(encoding="utf-8"))
    out_dir = Path(args.out)
    mode = getattr(args, "verdict_mode", "A") or "A"
    judge_be = _make_judge(args)
    retry_rows = []
    for st in states:
        if round_no == 1:
            attempt_dir = run_base / st["alert_id"]
        else:
            pend = st.get("pending_attempt") or {}
            if pend.get("round") != round_no:
                continue  # 本轮无需重试的告警直接跳过
            attempt_dir = Path(pend["dir"])
        collect_alert({}, st, attempt_dir, judge_be=judge_be,
                      verdict_mode=mode,
                      judge_key=f"{st['alert_id']}::judge_r{round_no}")
        st["overhead"]["sandbox_runs"] = round_no
        print(f"[collect r{round_no}] {st['alert_id']}: "
              f"verdict={st['verdict']['verdict']}"
              f"(mode {st['verdict']['mode']})")
        if round_no > 1:
            pend = st.get("pending_attempt") or {}
            retry_rows.append({
                "alert_id": st["alert_id"], "round": round_no,
                "branch": pend.get("branch"),
                "attempt_dir": str(attempt_dir.as_posix()),
                "verdict": st["verdict"]["verdict"],
                "reason": st["verdict"]["reason"][:200],
            })
        st["pending_attempt"] = None
    # 状态写回,供下一轮 regen 续用
    (run_base / "_prepare_states.json").write_text(
        json.dumps(states, ensure_ascii=False, indent=2), encoding="utf-8")
    if retry_rows:
        with (out_dir / "retry_trace.jsonl").open("a", encoding="utf-8") as f:
            for row in retry_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    _finalize(out_dir, run_base, args.run_id, states)
    return 0


def cmd_regen(args) -> int:
    """重试闭环(方案 4.3.5):按上一轮判定与 fix_suggestion 再生成 mock。

    verdict=TP            → 不动;
    FP 且建议改 payload   → 仅换 payload,复用现有 harness(省一次生成);
    Unconfirmed/FP 且建议改 mock → 带 feedback 重新生成 mock 并重新组装;
    达到 MAX_RETRIES 或 LLM 预算上限 → 不再重试,维持上一轮判定。
    """
    round_no = args.round
    run_base = Path(args.out) / f"run_{args.run_id}"
    states = json.loads((run_base / "_prepare_states.json")
                        .read_text(encoding="utf-8"))
    project_dir = Path(args.project).resolve()
    mk = _mock_kwargs(args)

    cmds = ["#!/usr/bin/env bash",
            f"# 重试第 {round_no} 轮(由 auditor.orchestrator regen 生成)",
            "set -u", "export MSYS_NO_PATHCONV=1"]
    n_regenerated = 0
    for st in states:
        v = st.get("verdict") or {}
        if v.get("verdict") == "TP":
            continue
        if len(st.get("retries", [])) >= MAX_RETRIES:
            print(f"[regen] {st['alert_id']}: 达到重试上限,维持 "
                  f"{v.get('verdict')}")
            continue
        if st["overhead"].get("llm_calls", 0) >= MAX_LLM_CALLS:
            print(f"[regen] {st['alert_id']}: LLM 预算上限,不再重试")
            continue
        base_dir = run_base / st["alert_id"]
        attempt_dir = base_dir / f"attempt_{round_no}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        # 提取结果不变,复制 snippet 供 generate/assemble 使用
        if (base_dir / "snippet.py").exists():
            (attempt_dir / "snippet.py").write_text(
                (base_dir / "snippet.py").read_text(encoding="utf-8"),
                encoding="utf-8")

        fix = v.get("fix_suggestion") or "改 mock"
        feedback = f"verdict={v.get('verdict')};reason={v.get('reason')}"
        stderr_tail = ((st.get("run") or {}).get("stderr_tail") or "").strip()
        if stderr_tail:
            feedback += f";stderr={stderr_tail[-300:]}"

        if fix == "改 payload":
            # 仅更新 payload,复用现有 harness(省一次 mock 生成)
            import shutil
            for name in ("harness.py", "mock_patch.py"):
                src = base_dir / name
                if src.exists():
                    shutil.copy(src, attempt_dir / name)
            for name in ("mock_meta.json", "harness_meta.json"):
                src = base_dir / name
                if src.exists():
                    shutil.copy(src, attempt_dir / name)
            old_payload = (base_dir / "payload.txt").read_text(encoding="utf-8")
            new_payload = f"{old_payload.rstrip(chr(10))}; {mock_gen.MARKER}-r{round_no}"
            (attempt_dir / "payload.txt").write_text(new_payload, encoding="utf-8")
            st["overhead"]["llm_calls"] += 0
            change = f"payload 更新为 {new_payload[:60]}"
            print(f"[regen] {st['alert_id']}: 改 payload(复用 harness)")
        else:
            alert = {"alert_id": st["alert_id"], "cwe": st.get("cwe"),
                     **{k: (st.get("source_alert") or {}).get(k)
                        for k in ("check_id", "path", "line", "end_line",
                                  "message")}}
            mock_meta = mock_gen.generate(alert, st["extract"], attempt_dir,
                                          feedback=feedback, attempt=round_no,
                                          **mk)
            st["overhead"]["llm_calls"] += mock_meta.get("llm_calls", 0)
            if not mock_meta.get("ok"):
                print(f"[regen] {st['alert_id']}: mock 再生成失败,"
                      f"维持 {v.get('verdict')}({mock_meta.get('error')})")
                continue
            harness_meta = harness.assemble(alert, st["extract"], mock_meta,
                                            attempt_dir)
            if not harness_meta.get("assemble_ok"):
                print(f"[regen] {st['alert_id']}: 重新组装失败,维持上一轮")
                continue
            change = (f"mock 再生成({mock_meta.get('generated_by')});"
                      f"feedback={feedback[:120]}")
            print(f"[regen] {st['alert_id']}: mock 已再生成"
                  f"({mock_meta.get('generated_by')})")
        n_regenerated += 1
        st["retries"].append({"round": round_no, "branch": fix,
                              "change": change})
        st["pending_attempt"] = {"round": round_no,
                                 "dir": attempt_dir.as_posix(),
                                 "branch": fix}
        cmds.append(sandbox.emit_command_file(attempt_dir))

    (run_base / "_prepare_states.json").write_text(
        json.dumps(states, ensure_ascii=False, indent=2), encoding="utf-8")
    if n_regenerated:
        cmds.append('echo "retry sandbox step done"')
        sh = run_base / f"sandbox_cmds_round{round_no}.sh"
        sh.write_text("\n".join(cmds) + "\n", encoding="utf-8")
        print(f"[regen] {n_regenerated} 条告警进入第 {round_no} 轮;"
              f"执行 bash {sh.as_posix()} 后运行 collect --round {round_no}")
    else:
        print("[regen] 无需重试(全部 TP 或无可重试项)")
    return 0


def cmd_run(args) -> int:
    """一体化模式(标准环境):docker 由本进程直接驱动。"""
    alerts = _load_alerts(args.alerts)
    out_dir = Path(args.out)
    run_base = out_dir / f"run_{args.run_id}"
    project_dir = Path(args.project).resolve()
    mk = _mock_kwargs(args)
    judge_be = _make_judge(args)
    mode = getattr(args, "verdict_mode", "A") or "A"
    states = []
    for alert in alerts:
        run_dir = run_base / alert["alert_id"]
        st = prepare_alert(alert, project_dir, run_dir, mk)
        t0 = time.time()
        if st["harness"] and st["harness"].get("assemble_ok"):
            run = sandbox.run_harness(run_dir)
            payload = (run_dir / "payload.txt").read_text(encoding="utf-8")
            st["run"] = {k: run.get(k) for k in
                         ("env_ok", "exit_code", "elapsed_s", "replay_command")}
            st["run"]["env_snapshot"] = run["env"]
            st["run"]["stdout_tail"] = (run.get("stdout") or "")[-500:]
            st["run"]["stderr_tail"] = (run.get("stderr") or "")[-500:]
            if mode == "B" and judge_be is not None:
                evidence = {n: (run_dir / f).read_text(encoding="utf-8")
                            if (run_dir / f).exists() else None
                            for n, f in (("snippet", "snippet.py"),
                                         ("mock", "mock_patch.py"))}
                st["verdict"] = verdict.judge_mode_b(
                    alert, payload, run, evidence, judge_be,
                    key=f"{alert['alert_id']}::judge_r1")
                st["overhead"]["llm_calls"] += \
                    st["verdict"].get("judge_llm_calls", 0)
            else:
                st["verdict"] = verdict.judge_mode_a(alert, payload, run)
            st["evidence"] = {
                "run_dir": run_dir.resolve().as_posix(),
                "harness_path": st["harness"].get("harness_path"),
                "payload": payload,
                "env_snapshot": run["env"],
                "replay_command": run.get("replay_command"),
                "stdout_tail": st["run"]["stdout_tail"],
            }
        st["overhead"]["wall_time_s"] = round(time.time() - t0, 2)
        states.append(st)
        print(f"[run] {alert['alert_id']}: verdict="
              f"{(st['verdict'] or {}).get('verdict')}")
    _finalize(out_dir, run_base, args.run_id, states)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="audit_alert 编排器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _common(p, need_round=False):
        p.add_argument("--alerts", required=True, nargs="+",
                       help="候选来源 JSON,可给多个"
                            "(如 sast_alerts.json llm_candidates.json)")
        p.add_argument("--project", required=True, help="被扫描项目目录")
        p.add_argument("--run-id", required=True, help="运行编号")
        p.add_argument("--out", default="records", help="records 目录")
        p.add_argument("--mock-backend", default=None,
                       choices=["template", "deepseek", "replay", "dry"],
                       help="mock 生成后端(默认 template)")
        p.add_argument("--mock-model", default=None, help="LLM 模型名")
        p.add_argument("--mock-replay-file", help="replay 后端的响应 JSON")
        p.add_argument("--mock-record-dir",
                       help="deepseek 后端录制 mock 生成响应的目录")
        if need_round:
            p.add_argument("--round", type=int, required=True,
                           help="重试轮次(≥2)")
        p.add_argument("--verdict-mode", default="A", choices=["A", "B"],
                       help="判定模式:A=硬编码检测器(确定性);B=LLM 日志推理(带护栏)")
        p.add_argument("--judge-backend", default=None,
                       choices=["deepseek", "replay", "dry"],
                       help="模式 B 判定后端(仅 --verdict-mode B 时使用)")
        p.add_argument("--judge-model", default=None, help="模式 B 模型名")
        p.add_argument("--judge-replay-file", help="模式 B replay 后端响应 JSON")
        p.add_argument("--judge-record-dir", help="模式 B deepseek 后端录制目录")

    _common(sub.add_parser("prepare"))
    p_collect = sub.add_parser("collect")
    _common(p_collect)
    p_collect.add_argument("--round", type=int, default=1,
                           help="回收轮次(默认 1;重试轮传对应轮次)")
    _common(sub.add_parser("run"))
    _common(sub.add_parser("regen"), need_round=True)

    args = ap.parse_args(argv)
    fn = {"prepare": cmd_prepare, "collect": cmd_collect,
          "run": cmd_run, "regen": cmd_regen}[args.cmd]
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
