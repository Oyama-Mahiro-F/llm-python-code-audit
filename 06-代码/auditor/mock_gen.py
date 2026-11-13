# -*- coding: utf-8 -*-
"""Mock 桩生成(对应《项目方案》4.3.2)。

两条生成路径:
  template   内置模板(当前覆盖 CWE-89/sqlite),确定性、零幻觉,作为
             LLM 失败时的**保底回退**;
  llm        调用大模型生成 mock 桩与 payload(默认 deepseek),配合
             few-shot 与**输出校验**,用于覆盖模板未及的 CWE 类型。

LLM 输出契约(校验不过即回退模板或判失败):
  {"imports": ["import os", ...],
   "mock_code": "<完整 mock 源码,必须含 CAPTURED 与 _install_mock()>",
   "payload": "<必须含标记串 MARKER 的触发输入>",
   "rationale": "<一句话拦截策略>"}

mock 桩契约(harness 与模式 A 判定器都依赖):
  CAPTURED = {"sink_api": "<危险API名>", "calls": []}
  每次拦截到的危险调用向 calls 追加 dict,必须含 "args"(危险参数字符串);
  若调用方式本身安全(如参数化绑定),附加 "sanitized": True;
  必须定义 _install_mock() 完成掉包;桩内不得真实调用任何危险 API。

安全校验:生成代码先 compile() 语法检查,再做**调用形态黑名单**扫描
(os.system(、subprocess.、eval( 等调用形态禁止;`os.system = 桩` 这类
赋值形态允许——那是拦截本身)。校验在沙箱外完成,不合格代码不进沙箱。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .llm_discover import DEFAULT_MODEL, make_backend, parse_llm_json

MARKER = "zxq-demo-marker"
MOCK_PROMPT_VERSION = "v1-2026-11-06"

# 调用形态黑名单:匹配"调用"而非"赋值拦截"(赋值形如 os.system = _fake,无左括号)
_BLOCKLIST_CALLS = [
    r"os\.system\s*\(", r"os\.popen\s*\(", r"subprocess\.\w+\s*\(",
    r"\beval\s*\(", r"\bexec\s*\(", r"__import__\s*\(",
    r"socket\.\w+\s*\(", r"shutil\.\w+\s*\(", r"requests\.\w+\s*\(",
    r"urlopen\s*\(", r"\bpopen\s*\(",
]

# ---------------------------------------------------------------- 模板(CWE-89 保底)
_SQLITE_MOCK = '''\
# --- mock 桩(模板生成,拦截 sqlite3 危险 sink)---
import json as _json

CAPTURED = {"sink_api": "sqlite3.Cursor.execute", "calls": []}


class _FakeCursor:
    def execute(self, sql=None, params=None):
        CAPTURED["calls"].append({
            "sql": sql if isinstance(sql, str) else repr(sql),
            "params": None if params is None else repr(params),
            "sanitized": params is not None,
        })
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []


class _FakeConnection:
    def cursor(self):
        return _FakeCursor()


def _install_mock():
    import sqlite3
    sqlite3.connect = lambda *a, **k: _FakeConnection()
'''


def _payload_cwe89(alert: dict) -> str:
    return f"{MARKER}' OR '1'='1"


TEMPLATES = {
    "sqlite3.Cursor.execute": {
        "imports": ["import sqlite3"],
        "mock_code": _SQLITE_MOCK,
        "payload_fn": _payload_cwe89,
        "cwe_scope": ["CWE-89"],
    },
}

# ---------------------------------------------------------------- few-shot
_EXAMPLE_SQLITE = '''{"imports": ["import sqlite3"],
 "mock_code": "CAPTURED = {'sink_api': 'sqlite3.Cursor.execute', 'calls': []}\\n\\nclass _FakeCursor:\\n    def execute(self, sql=None, params=None):\\n        CAPTURED['calls'].append({'args': str(sql), 'sanitized': params is not None})\\n        return self\\n\\ndef _install_mock():\\n    import sqlite3\\n    sqlite3.connect = lambda *a, **k: _FakeCursor()",
 "payload": "MARKER' OR '1'='1",
 "rationale": "掉包 sqlite3.connect,记录 SQL 与是否参数化"}'''

_EXAMPLE_CMD = '''{"imports": ["import os"],
 "mock_code": "CAPTURED = {'sink_api': 'os.system', 'calls': []}\\n\\ndef _fake_system(cmd):\\n    CAPTURED['calls'].append({'args': str(cmd)})\\n    return 0\\n\\ndef _install_mock():\\n    import os\\n    os.system = _fake_system",
 "payload": "MARKER; echo pwned",
 "rationale": "掉包 os.system,只记录命令不执行"}'''

PROMPT_TEMPLATE = """你是安全测试工程师。任务:为一段被提取的 Python 业务代码编写 mock 桩与触发 payload,
用于在隔离沙箱中验证一条疑似漏洞告警。这只是一次"带记录的排练":危险操作绝不真实发生。

硬性要求:
1. mock 桩必须拦截告警指向的危险 sink 调用(函数/方法整体掉包),绝不真实执行危险操作;
2. 严格遵守 CAPTURED 契约:
   CAPTURED = {{"sink_api": "<危险API名>", "calls": []}}
   每次拦截到的危险调用向 CAPTURED["calls"] 追加一个 dict,**必须含 "args" 键**
   (危险参数的字符串形式,如 SQL 语句 / 命令行 / 文件路径);
   若该调用方式本身安全(如参数化绑定、白名单校验),额外附加 "sanitized": True;
   必须定义 _install_mock() 完成掉包;桩内不得真实调用任何危险 API、不得有副作用;
3. payload 必须包含标记串 "{marker}",并设计成能流到 sink;
   即便你认为告警可能是误报,也请正常构造,由动态验证裁决;
4. "imports" 列出业务片段引用但未定义、harness 运行所需的 import 语句;
5. mock_code 中不允许出现对危险 API 的调用形态(允许对它们赋值/掉包)。

输出严格 JSON(不要输出任何解释文字):
{{"imports": ["import os", ...],
 "mock_code": "<完整 mock 源码,含 CAPTURED 与 _install_mock()>",
 "payload": "<含 {marker} 的触发输入>",
 "rationale": "<一句话拦截策略>"}}

CWE 类型:{cwe}
原始告警:{alert_message}

few-shot 示例(参考格式与风格,不要照抄内容):
--- 示例 1:拦截 sqlite3 ---
{example_sqlite}
--- 示例 2:拦截 os.system ---
{example_cmd}

被提取的业务代码(注意其中引用的外部模块需列入 imports):
```python
{snippet}
```
{feedback}
只输出 JSON。"""


def _build_prompt(alert: dict, snippet: str, feedback: str | None) -> str:
    fb = ""
    if feedback:
        fb = ("上一轮尝试失败,判定如下,请修正 mock(注意保持 CAPTURED 契约):\n"
              + feedback + "\n")
    return PROMPT_TEMPLATE.format(
        marker=MARKER, cwe=alert.get("cwe") or "未知",
        alert_message=(alert.get("message") or "")[:300],
        example_sqlite=_EXAMPLE_SQLITE, example_cmd=_EXAMPLE_CMD,
        snippet=snippet, feedback=fb,
    )


def _validate(mock_code: str, payload: str, imports: list[str]) -> str | None:
    """返回 None 表示通过;否则返回失败原因。"""
    if not isinstance(mock_code, str) or "CAPTURED" not in mock_code:
        return "mock_code 缺少 CAPTURED"
    if "_install_mock" not in mock_code:
        return "mock_code 缺少 _install_mock()"
    if not isinstance(payload, str) or MARKER not in payload:
        return f"payload 未包含标记串 {MARKER}"
    for pat in _BLOCKLIST_CALLS:
        if re.search(pat, mock_code):
            return f"mock_code 含危险调用形态:{pat}"
    try:
        compile("\n".join(list(imports) + [mock_code]), "<mock>", "exec")
    except SyntaxError as exc:
        return f"mock_code 语法错误:{exc}"
    return None


def _write(run_dir: Path, info: dict) -> dict:
    (run_dir / "mock_patch.py").write_text(info["mock_code"], encoding="utf-8")
    (run_dir / "payload.txt").write_text(info["payload"], encoding="utf-8")
    info["mock_path"] = str((run_dir / "mock_patch.py").as_posix())
    info["payload_path"] = str((run_dir / "payload.txt").as_posix())
    (run_dir / "mock_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def _fail(run_dir: Path, error: str, **extra) -> dict:
    info = {"ok": False, "error": error, **extra}
    (run_dir / "mock_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def _template_info(alert: dict, extract_meta: dict, run_dir: Path) -> dict:
    tpl_name = "sqlite3.Cursor.execute"  # 当前唯一模板
    tpl = TEMPLATES[tpl_name]
    payload = tpl["payload_fn"](alert)
    info = {
        "ok": True, "template": tpl_name,
        "generated_by": "template",
        "llm_backend": None, "llm_calls": 0,
        "payload": payload, "imports": list(tpl["imports"]),
        "sink_function": extract_meta.get("sink_function"),
        "mock_code": tpl["mock_code"],
    }
    return _write(run_dir, info)


def generate(alert: dict, extract_meta: dict, run_dir: str | Path, *,
             backend: str | None = None, model: str = DEFAULT_MODEL,
             replay_file: str | None = None, record_dir: str | None = None,
             feedback: str | None = None, attempt: int = 1) -> dict:
    """生成 mock 桩与 payload。

    backend=None/"template":仅模板(CWE-89);
    backend="deepseek"/"replay"/"dry":先走 LLM,失败回退模板(如有),
    无模板可回退时返回 ok=False(由编排器按三分类处理)。
    """
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    snippet_path = run_dir / "snippet.py"
    snippet = (snippet_path.read_text(encoding="utf-8")
               if snippet_path.exists() else "")

    if not backend or backend == "template":
        if (alert.get("cwe") or "") not in \
                TEMPLATES["sqlite3.Cursor.execute"]["cwe_scope"]:
            return _fail(run_dir, f"no_template_for_cwe:{alert.get('cwe')}",
                         llm_backend=None, llm_calls=0)
        return _template_info(alert, extract_meta, run_dir)

    be = make_backend(backend, model=model, replay_file=replay_file,
                      record_dir=record_dir)
    prompt = _build_prompt(alert, snippet, feedback)
    key = f"{alert.get('alert_id', 'alert')}::attempt{attempt}"
    llm_error = None
    try:
        raw = be.complete_for(key, prompt) if hasattr(be, "complete_for") \
            else be.complete(prompt)
    except Exception as exc:  # 网络/限额/缺 key
        llm_error = f"{type(exc).__name__}: {exc}"
        raw = None

    info = {"llm_backend": backend, "llm_model": getattr(be, "model", model),
            # replay 为离线回放、零 API 成本,不计入 LLM 调用预算
            "llm_calls": (0 if backend == "replay"
                          else getattr(be, "calls", 0)),
            "prompt_version": MOCK_PROMPT_VERSION,
            "attempt": attempt, "sink_function": extract_meta.get("sink_function")}
    if raw is None:
        info["llm_error"] = llm_error
    else:
        info["llm_raw_chars"] = len(raw)
        item = parse_llm_json(raw)
        item = item[0] if item else None
        if not isinstance(item, dict):
            info["llm_error"] = "输出不可解析为 JSON 对象"
        else:
            imports = item.get("imports") or []
            if not isinstance(imports, list):
                imports = []
            reason = _validate(str(item.get("mock_code") or ""),
                               str(item.get("payload") or ""), imports)
            if reason:
                info["llm_error"] = f"校验失败:{reason}"
            else:
                info.update({
                    "ok": True, "generated_by": f"llm({backend})",
                    "mock_code": str(item["mock_code"]),
                    "payload": str(item["payload"]),
                    "imports": [str(x) for x in imports],
                    "rationale": str(item.get("rationale") or "")[:300],
                })
                return _write(run_dir, info)

    # ---- 回退:模板保底 ----
    if (alert.get("cwe") or "") in TEMPLATES["sqlite3.Cursor.execute"]["cwe_scope"]:
        info_fb = _template_info(alert, extract_meta, run_dir)
        info_fb["generated_by"] = "llm->fallback-template"
        info_fb["fallback_reason"] = info.get("llm_error")
        info_fb["llm_calls"] = info.get("llm_calls", 0)
        info_fb["llm_backend"] = backend
        return _write(run_dir, info_fb)
    return _fail(run_dir, f"llm_failed_and_no_template:{info.get('llm_error')}",
                 **{k: v for k, v in info.items()
                    if k in ("llm_backend", "llm_calls", "attempt")})
