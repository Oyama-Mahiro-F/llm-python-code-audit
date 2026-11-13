# -*- coding: utf-8 -*-
"""harness 组装器(对应《项目方案》4.3.2)。

将业务源码片段(extract 产出)与 mock 桩拼装为**独立可执行**的单元
测试脚本:harness 内先定义业务函数,再安装 mock(拦截危险 sink),
最后送入 payload 调用 sink 所属函数,并以 JSON 打印 mock 捕获的
sink 入参(供模式 A 硬编码检测器判定)。
"""
from __future__ import annotations

import json
from pathlib import Path

_HARNESS_TEMPLATE = '''\
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


def assemble(alert: dict, extract_meta: dict, mock_meta: dict,
             run_dir: str | Path) -> dict:
    """拼装 harness 并落盘;返回组装元数据(assemble_ok 等)。"""
    run_dir = Path(run_dir)
    snippet_path = run_dir / "snippet.py"
    if not extract_meta.get("ok"):
        info = {"assemble_ok": False,
                "assemble_error": "extract_failed:" + str(extract_meta.get("error"))}
        (run_dir / "harness_meta.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
        return info
    if not mock_meta.get("ok"):
        info = {"assemble_ok": False,
                "assemble_error": "mock_failed:" + str(mock_meta.get("error"))}
        (run_dir / "harness_meta.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
        return info

    snippet = snippet_path.read_text(encoding="utf-8")
    mock_code = Path(mock_meta["mock_path"]).read_text(encoding="utf-8")
    imports = "\n".join(mock_meta.get("imports", []))

    code = _HARNESS_TEMPLATE.format(
        alert_id=alert["alert_id"],
        imports=imports,
        snippet=snippet,
        mock_code=mock_code,
        payload=mock_meta["payload"],
        sink_function=mock_meta["sink_function"],
    )
    harness_path = run_dir / "harness.py"
    harness_path.write_text(code, encoding="utf-8")

    info = {
        "assemble_ok": True,
        "assemble_error": None,
        "harness_path": harness_path.resolve().as_posix(),
        "harness_sha": __import__("hashlib").sha256(
            code.encode("utf-8")).hexdigest()[:16],
        "payload_sha": __import__("hashlib").sha256(
            mock_meta["payload"].encode("utf-8")).hexdigest()[:16],
    }
    (run_dir / "harness_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info
