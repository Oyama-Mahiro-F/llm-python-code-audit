# -*- coding: utf-8 -*-
"""判定描述生成(落实老师 2026-11-22 反馈第 1 条)。

问题:原 reason 是通用话术("payload 已到达 sink……漏洞成立"),看不出每个
样本的特点。本模块改为**用该条 finding 自己的证据填空**,输出:

  位置    文件:行 + 所属函数
  污点源  外部输入以哪个形参进入被测函数(取自函数签名 + 告警来源)
  传播    引用原始代码中的实际拼接行(带行号)
  危险操作点 实际被拦截的危险 API + 调用行(sink,污点汇聚处)
  截获值  沙箱内 mock 记录到的真实实参(这是"跑出来了"的硬证据)
  payload 本次注入的标记串
  依据    为什么判 TP/FP/Unconfirmed(与三分类口径一致)
  CVE     经 NVD 核验的真实同类漏洞(按 CWE+语言匹配,匹配不到就不写)

纯确定性生成,不调用大模型;模板只负责措辞,事实全部来自落盘记录。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_HERE = Path(__file__).parent
CVE_LIB_PATH = _HERE / "cve_refs.json"

CWE_NAMES = {
    "CWE-89": "SQL 注入",
    "CWE-78": "OS 命令注入",
    "CWE-22": "路径穿越",
    "CWE-79": "跨站脚本(XSS)",
    "CWE-94": "代码注入",
}

_PHP_SIG = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(\s*(\$[A-Za-z_]\w*)")
_PY_SIG = re.compile(r"def\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)")


def load_cve_refs(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else CVE_LIB_PATH
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8")).get("entries", [])


def match_cve(cwe: str | None, language: str | None,
              refs: list[dict] | None = None) -> dict | None:
    """按 CWE+语言精确匹配;退化为仅按 CWE;仍无则 None(不臆造)。"""
    refs = refs if refs is not None else load_cve_refs()
    if not cwe:
        return None
    same_cwe = [r for r in refs if r.get("cwe") == cwe]
    for r in same_cwe:
        if (r.get("language") or "").lower() == (language or "").lower():
            return r
    return same_cwe[0] if same_cwe else None


def _read_lines(path: str | None) -> list[str]:
    if not path:
        return []
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _signature_param(fn_code: str, language: str) -> str | None:
    pat = _PHP_SIG if language == "php" else _PY_SIG
    m = pat.search(fn_code or "")
    return m.group(2) if m else None


_SIG_MARKS = ("function ", "def ")


def _find_body_param_line(lines: list[str], param: str, start: int,
                          end: int) -> int | None:
    """在函数体内找首个包含 param 的行;跳过函数签名行与定义行。"""
    for i in range(max(start - 1, 0), min(end, len(lines))):
        line = lines[i]
        if param not in line:
            continue
        stripped = line.strip()
        if stripped.startswith(_SIG_MARKS) or any(
                m in stripped[: stripped.find("(") + 1] for m in _SIG_MARKS):
            continue
        return i + 1
    return None


def _find_line(lines: list[str], needle: str, start: int, end: int) -> int | None:
    """在 [start,end](1-based,含)范围内找首个包含 needle 的行号。"""
    for i in range(max(start - 1, 0), min(end, len(lines))):
        if needle in lines[i]:
            return i + 1
    return None


def build(state: dict, snippet: str, mock_code: str,
          cve_refs: list[dict] | None = None) -> dict:
    """生成结构化描述 + 可直接展示的中文长句。"""
    extract_meta = state.get("extract") or {}
    src_alert = state.get("source_alert") or {}
    verdict = state.get("verdict") or {}
    run = state.get("run") or {}
    mock_meta = state.get("mock") or {}

    language = extract_meta.get("language") or "python"
    cwe = state.get("cwe")
    cwe_name = CWE_NAMES.get(cwe or "", cwe or "未知类型")
    sink_fn = extract_meta.get("sink_function")
    fns = extract_meta.get("functions") or []
    sink_fn_meta = next((f for f in fns if f.get("is_sink")), None)
    start = (sink_fn_meta or {}).get("start_line") or 1
    end = (sink_fn_meta or {}).get("end_line") or start

    # ---- 截获证据:从沙箱 stdout 的 @@RESULT@@ 取 ----
    captured = {}
    stdout = run.get("stdout_tail") or ""
    idx = stdout.find("@@RESULT@@")
    if idx >= 0:
        try:
            captured = json.loads(stdout[idx + len("@@RESULT@@"):].strip())
        except json.JSONDecodeError:
            captured = {}
    cap = captured.get("captured") or {}
    calls = cap.get("calls") or []
    first_call = calls[0] if calls else {}
    sink_api = (cap.get("sink_api") or mock_meta.get("sink_api")
                or "被拦截的危险调用")
    captured_arg = str(first_call.get("args") or "")[:400]

    # ---- 代码事实:参数名 / 拼接行 / sink 调用行 ----
    param = _signature_param(snippet, language)
    lines = _read_lines(extract_meta.get("file"))
    # 跳过函数签名行本身:传播行必须在函数体内
    taint_line = _find_body_param_line(lines, param, start, end) if param else None
    sink_call_line = _find_line(lines, str(sink_api).split(".")[-1], start, end)

    def line_text(n: int | None) -> str:
        if not n or n - 1 >= len(lines):
            return ""
        return lines[n - 1].strip()

    # ---- 判定依据 ----
    label = verdict.get("verdict")
    sanitized = any(c.get("sanitized") is True for c in calls)
    if label == "TP":
        basis = (f"payload 原样出现在 {sink_api} 的实参中且未见净化处理"
                 f"({('存在净化标记' if sanitized else '无 sanitized 标记、无参数绑定')}),"
                 "污点路径被执行证实 → 已确认(TP)")
    elif label == "FP":
        basis = f"payload 到达 {sink_api},但实参表明已净化/参数化,不构成漏洞 → 已排除(FP)"
    else:
        basis = f"动态验证未得出确定结论({verdict.get('reason', '')[:80]})→ 未确认,不计入误报"

    cve = match_cve(cwe, language, cve_refs)
    source_desc = ((src_alert.get("metavars") or {}).get("source")
                   or (f"{param} 形参" if param else "外部输入"))
    is_llm = (str(src_alert.get("alert_id", "")).startswith("L-")
              or str(src_alert.get("check_id", "")).startswith("llm."))
    origin = "LLM 候选发现通道" if is_llm else "SAST 规则扫描"

    loc = (f"{Path(str(src_alert.get('path') or extract_meta.get('file'))).name}:"
           f"{sink_call_line or src_alert.get('line')}")
    lang_label = {"php": "PHP", "python": "Python"}.get(language, language)
    parts = [
        f"{lang_label} {cwe_name}({cwe}):{loc},所属函数 {sink_fn}()。",
        f"污点源:{source_desc}(候选来自{origin})。",
    ]
    if taint_line:
        parts.append(f"传播:第 {taint_line} 行 `{line_text(taint_line)}`,"
                     "外部输入未经净化即拼接进危险调用的参数。")
    if sink_call_line:
        parts.append(f"危险操作点:第 {sink_call_line} 行 `{line_text(sink_call_line)}`,"
                     f"执行危险调用 {sink_api}。")
    if captured_arg:
        parts.append(f"沙箱截获的实际实参:`{captured_arg}`,payload "
                     f"`{captured.get('payload', '')}` 已到达危险操作点。")
    parts.append(basis + "。")
    if cve:
        parts.append(f"CVE 参照:{cve['cve_id']}({cve.get('summary_zh', '')};"
                     f"{cve.get('nvd_cwe', cwe)}"
                     + (f",CVSS {cve['cvss']}" if cve.get("cvss") else "")
                     + ";NVD 链接见下方)")

    return {
        "title": f"{lang_label} {cwe_name} / {cwe}",
        "language": language,
        "cwe": cwe,
        "cwe_name": cwe_name,
        "location": {"file": src_alert.get("path") or extract_meta.get("file"),
                     "line": src_alert.get("line"),
                     "sink_call_line": sink_call_line,
                     "function": sink_fn},
        "source": {"desc": source_desc, "param": param, "origin": origin},
        "propagation": {"line": taint_line, "code": line_text(taint_line)},
        "sink": {"api": sink_api, "line": sink_call_line,
                 "code": line_text(sink_call_line)},
        "captured_arg": captured_arg,
        "payload": captured.get("payload") or state.get("payload"),
        "basis": basis,
        "cve_ref": cve,
        "text": "".join(parts),
    }
