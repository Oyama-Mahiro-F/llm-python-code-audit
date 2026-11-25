# -*- coding: utf-8 -*-
"""harness 组装器(对应《项目方案》4.3.2)。

将业务源码片段(extract 产出)与 mock 桩拼装为**独立可执行**的单元测试脚本,
分语言两种模板:

  python  monkey-patch 拦截:mock 直接改写 sys.modules 里的函数(如
          sqlite3.connect / builtins.open),片段原样保留;
  php     接缝重定向:PHP 内建函数不可重定义,故把片段中 NAME( 改写为
          __mock_NAME( ,由桩函数记录入参(改写表来自 mock_meta.redirect,
          全部写入 harness_meta 的 redirects_applied,可审计)。

参数注入约定(两种语言一致):**被测函数把外部输入作为第一个形参**,
harness 以 payload 作为第一个实参调用它。该约定写入 demos 的样本设计说明。

输出:harness.<ext> + harness_meta.json(含 sha、redirects_applied)
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

_PY_TEMPLATE = '''\
# -*- coding: utf-8 -*-
# 由 auditor.harness 自动生成(alert_id={alert_id});勿手工编辑。
import json
import sys

{imports}

# === 1. 业务源码片段(extract.py 产出)====================================
{snippet}

# === 2. mock 桩(mock_gen.py 产出)=======================================
{mock_code}
_install_mock()

# === 3. 送入 payload,触发 sink ==========================================
PAYLOAD = {payload!r}
_result = {{"captured": None, "payload": PAYLOAD, "error": None}}
try:
    _fn = globals()[{sink_function!r}]
    _fn(PAYLOAD)
except Exception as _e:  # 业务代码自身异常也完整记录,由判定器归因
    _result["error"] = type(_e).__name__ + ": " + str(_e)
_result["captured"] = CAPTURED

sys.stdout.write("@@RESULT@@" + json.dumps(_result, ensure_ascii=False))
sys.stdout.write("\\n")
'''

_PHP_TEMPLATE = '''\
<?php
// 由 auditor.harness 自动生成(alert_id={alert_id});勿手工编辑。
// === 1. mock 桩(mock_gen.py 产出;接缝重定向的接收方)==================
{mock_code}

// === 2. 业务源码片段(extract.py 产出;sink 调用已重定向)===============
{snippet}

// === 3. 送入 payload,触发 sink =========================================
$payload = {payload_literal};
$result = ['captured' => null, 'payload' => $payload, 'error' => null];
try {{
    $fn = {sink_function_literal};
    $fn($payload);
}} catch (\\Throwable $e) {{
    $result['error'] = get_class($e) . ': ' . $e->getMessage();
}}
$result['captured'] = isset($GLOBALS['CAPTURED']) ? $GLOBALS['CAPTURED'] : null;
echo "@@RESULT@@" . json_encode(
    $result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
) . PHP_EOL;
'''


def _php_str(s: str) -> str:
    """PHP 单引号字符串字面量(仅需转义 \\ 与 ' )。"""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def apply_redirects(snippet: str, redirect: list[str]) -> tuple[str, list[dict]]:
    """把片段中的 sink 调用 NAME( 改写为 __mock_NAME( 。

    只改写**名字直接调用**,不触碰成员方法($x->NAME( / x.NAME( / ::NAME(),
    也不触碰已被 __mock_ 前缀的调用。字符串字面量内的同名文本无法区分,
    属已知局限(样本设计时避免)。
    """
    applied = []
    out = snippet
    for name in redirect or []:
        if not name:
            continue
        pattern = re.compile(rf"(?<![>\w:$'\"]){re.escape(name)}\s*\(")
        out, n = pattern.subn(f"__mock_{name}(", out)
        applied.append({"name": name, "count": n})
    return out, applied


def assemble(alert: dict, extract_meta: dict, mock_meta: dict,
             run_dir: str | Path) -> dict:
    """拼装 harness 并落盘;返回组装元数据(assemble_ok 等)。"""
    run_dir = Path(run_dir)
    language = extract_meta.get("language") or "python"
    snippet_file = extract_meta.get("snippet_file") or "snippet.py"
    snippet_path = run_dir / snippet_file

    if not extract_meta.get("ok"):
        return _fail(run_dir, "extract_failed:" + str(extract_meta.get("error")))
    if not mock_meta.get("ok"):
        return _fail(run_dir, "mock_failed:" + str(mock_meta.get("error")))

    snippet = snippet_path.read_text(encoding="utf-8")
    mock_code = Path(mock_meta["mock_path"]).read_text(encoding="utf-8")
    payload = mock_meta["payload"]
    sink_fn = mock_meta.get("sink_function")

    if language == "php":
        snippet, applied = apply_redirects(snippet, mock_meta.get("redirect") or [])
        harness_name = "harness.php"
        code = _PHP_TEMPLATE.format(
            alert_id=alert["alert_id"],
            mock_code=mock_code,
            snippet=snippet,
            payload_literal=_php_str(payload),
            sink_function_literal=_php_str(str(sink_fn)),
        )
    else:
        applied = []
        harness_name = "harness.py"
        imports = "\n".join(mock_meta.get("imports", []))
        code = _PY_TEMPLATE.format(
            alert_id=alert["alert_id"],
            imports=imports,
            snippet=snippet,
            mock_code=mock_code,
            payload=payload,
            sink_function=str(sink_fn),
        )

    harness_path = run_dir / harness_name
    harness_path.write_text(code, encoding="utf-8")

    info = {
        "assemble_ok": True,
        "assemble_error": None,
        "language": language,
        "harness_file": harness_name,
        "harness_path": harness_path.resolve().as_posix(),
        "harness_sha": hashlib.sha256(code.encode("utf-8")).hexdigest()[:16],
        "payload_sha": hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16],
        "redirects_applied": applied,
        "param_convention": "被测函数第一个形参接收外部输入;harness 以 payload 作为第一个实参调用",
    }
    (run_dir / "harness_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def _fail(run_dir: Path, reason: str) -> dict:
    info = {"assemble_ok": False, "assemble_error": reason}
    (run_dir / "harness_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info
