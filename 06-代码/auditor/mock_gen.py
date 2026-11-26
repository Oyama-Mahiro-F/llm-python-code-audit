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

# PHP 危险调用黑名单(PHP 函数名大小写不敏感,匹配用 IGNORECASE)。
# (?<![\w]) 负向前瞻:排除 __mock_shell_exec( 这类桩定义(拦截本身),
# 只拦 shell_exec( 这种真实调用形态。覆盖命令执行 / 代码执行 / SQL 执行三类。
_BLOCKLIST_CALLS_PHP = [
    r"(?<![\w])shell_exec\s*\(", r"(?<![\w])passthru\s*\(",
    r"(?<![\w])system\s*\(", r"(?<![\w])exec\s*\(",
    r"(?<![\w])proc_open\s*\(", r"(?<![\w])popen\s*\(",
    r"(?<![\w])pcntl_exec\s*\(",
    r"(?<![\w])eval\s*\(", r"(?<![\w])assert\s*\(",
    r"(?<![\w])create_function\s*\(",
    r"(?<![\w])mysqli_query\s*\(", r"(?<![\w])mysql_query\s*\(",
    r"(?<![\w])pg_query\s*\(",
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


# ---------------------------------------------------------------- Python 路径穿越模板
_PY_OPEN_MOCK = '''\
# --- mock 桩(模板生成,拦截内置 open 文件读取)---
import json as _json

CAPTURED = {"sink_api": "builtins.open", "calls": []}


class _FakeFile:
    def __init__(self, path):
        self._path = path

    def read(self):
        return "MOCK_CONTENT:" + str(self._path)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        pass


def _fake_open(file=None, *args, **kwargs):
    CAPTURED["calls"].append({"args": str(file)})
    return _FakeFile(file)


def _install_mock():
    import builtins
    builtins.open = _fake_open
'''

# ---------------------------------------------------------------- PHP 模板
# PHP 内建函数无法 monkey-patch,改用组装期"接缝重定向":
# harness 把业务片段中的 NAME(...) 改写为 __mock_NAME(...)(见 redirect 字段),
# 由桩函数记录入参并返回无害值。
_PHP_SQLI_MOCK = r'''// --- mock 桩(模板生成,记录 mysqli_query 的 SQL 参数,不执行任何 SQL)---
$GLOBALS['CAPTURED'] = ['sink_api' => 'mysqli_query', 'calls' => []];

class __MockResult
{
    public $num_rows = 0;
    public function fetch_assoc() { return null; }
    public function fetch_row() { return null; }
    public function fetch_array() { return null; }
}

function __mock_mysqli_query($link, $query)
{
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($query) ? $query : var_export($query, true),
    ];
    return new __MockResult();
}
'''

_PHP_CMD_MOCK = r'''// --- mock 桩(模板生成,记录 shell 命令串,不执行任何命令)---
$GLOBALS['CAPTURED'] = ['sink_api' => 'shell_exec', 'calls' => []];

function __mock_shell_exec($cmd)
{
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_exec($cmd, &$output = null, &$code = null)
{
    $output = [];
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_system($cmd, &$code = null)
{
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}

function __mock_passthru($cmd, &$code = null)
{
    $code = 0;
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($cmd) ? $cmd : var_export($cmd, true),
    ];
    return '';
}
'''

_PHP_PATH_MOCK = r'''// --- mock 桩(模板生成,记录文件读取路径,不读取真实文件)---
$GLOBALS['CAPTURED'] = ['sink_api' => 'file_get_contents', 'calls' => []];

function __mock_file_get_contents($path)
{
    $GLOBALS['CAPTURED']['calls'][] = [
        'args' => is_string($path) ? $path : var_export($path, true),
    ];
    return 'MOCK_CONTENT:' . strval($path);
}
'''

PHP_SQLI_PAYLOAD = MARKER + "' OR '1'='1"
PHP_CMD_PAYLOAD = "127.0.0.1; echo " + MARKER
PHP_PATH_PAYLOAD = "../../etc/" + MARKER


def _payload_const(v: str):
    return lambda alert: v


TEMPLATES = {
    # ---------------- python ----------------
    "py:sqlite3.Cursor.execute": {
        "language": "python",
        "imports": ["import sqlite3"],
        "mock_code": _SQLITE_MOCK,
        "payload_fn": _payload_cwe89,
        "redirect": [],
        "sink_api": "sqlite3.Cursor.execute",
        "cwe_scope": ["CWE-89"],
    },
    "py:builtins.open": {
        "language": "python",
        "imports": [],
        "mock_code": _PY_OPEN_MOCK,
        "payload_fn": _payload_const("../../etc/passwd"),
        "redirect": [],
        "sink_api": "builtins.open",
        "cwe_scope": ["CWE-22"],
    },
    # ---------------- php ----------------
    "php:mysqli_query": {
        "language": "php",
        "imports": [],
        "mock_code": _PHP_SQLI_MOCK,
        "payload_fn": _payload_const(PHP_SQLI_PAYLOAD),
        "redirect": ["mysqli_query"],
        "sink_api": "mysqli_query",
        "cwe_scope": ["CWE-89"],
    },
    "php:shell_exec": {
        "language": "php",
        "imports": [],
        "mock_code": _PHP_CMD_MOCK,
        "payload_fn": _payload_const(PHP_CMD_PAYLOAD),
        "redirect": ["shell_exec", "exec", "system", "passthru"],
        "sink_api": "shell_exec",
        "cwe_scope": ["CWE-78"],
    },
    "php:file_get_contents": {
        "language": "php",
        "imports": [],
        "mock_code": _PHP_PATH_MOCK,
        "payload_fn": _payload_const(PHP_PATH_PAYLOAD),
        "redirect": ["file_get_contents"],
        "sink_api": "file_get_contents",
        "cwe_scope": ["CWE-22"],
    },
}

# (language, cwe) → 模板键
TEMPLATE_SELECTION = {
    ("python", "CWE-89"): "py:sqlite3.Cursor.execute",
    ("python", "CWE-22"): "py:builtins.open",
    ("php", "CWE-89"): "php:mysqli_query",
    ("php", "CWE-78"): "php:shell_exec",
    ("php", "CWE-22"): "php:file_get_contents",
}


def pick_template(alert: dict, language: str = "python") -> str | None:
    """按 (语言, CWE) 选模板;无匹配返回 None(交 LLM 路径或按失败处理)。"""
    return TEMPLATE_SELECTION.get((language, (alert.get("cwe") or "")))

# ---------------------------------------------------------------- few-shot
_EXAMPLE_SQLITE = '''{"imports": ["import sqlite3"],
 "mock_code": "CAPTURED = {'sink_api': 'sqlite3.Cursor.execute', 'calls': []}\\n\\nclass _FakeCursor:\\n    def execute(self, sql=None, params=None):\\n        CAPTURED['calls'].append({'args': str(sql), 'sanitized': params is not None})\\n        return self\\n\\ndef _install_mock():\\n    import sqlite3\\n    sqlite3.connect = lambda *a, **k: _FakeCursor()",
 "payload": "MARKER' OR '1'='1",
 "rationale": "掉包 sqlite3.connect,记录 SQL 与是否参数化"}'''

_EXAMPLE_CMD = '''{"imports": ["import os"],
 "mock_code": "CAPTURED = {'sink_api': 'os.system', 'calls': []}\\n\\ndef _fake_system(cmd):\\n    CAPTURED['calls'].append({'args': str(cmd)})\\n    return 0\\n\\ndef _install_mock():\\n    import os\\n    os.system = _fake_system",
 "payload": "MARKER; echo pwned",
 "rationale": "掉包 os.system,只记录命令不执行"}'''

_EXAMPLE_PHP_SQLI = '''{"redirect": ["mysqli_query"],
 "mock_code": "$GLOBALS['CAPTURED'] = ['sink_api' => 'mysqli_query', 'calls' => []];\\nfunction __mock_mysqli_query($link, $query) {\\n    $GLOBALS['CAPTURED']['calls'][] = ['args' => is_string($query) ? $query : var_export($query, true)];\\n    return null;\\n}",
 "payload": "MARKER' OR '1'='1",
 "sink_api": "mysqli_query",
 "rationale": "定义 __mock_mysqli_query 记录 SQL,harness 将 mysqli_query( 重定向到它"}'''

_EXAMPLE_PHP_CMD = '''{"redirect": ["shell_exec"],
 "mock_code": "$GLOBALS['CAPTURED'] = ['sink_api' => 'shell_exec', 'calls' => []];\\nfunction __mock_shell_exec($cmd) {\\n    $GLOBALS['CAPTURED']['calls'][] = ['args' => is_string($cmd) ? $cmd : var_export($cmd, true)];\\n    return '';\\n}",
 "payload": "127.0.0.1; echo MARKER",
 "sink_api": "shell_exec",
 "rationale": "定义 __mock_shell_exec 记录命令串,harness 将 shell_exec( 重定向到它"}'''

PROMPT_TEMPLATE = """你是安全测试工程师。任务:为一段被提取的 {lang_name} 业务代码编写 mock 桩与触发 payload,
用于在隔离沙箱中验证一条疑似漏洞告警。这只是一次"带记录的排练":危险操作绝不真实发生。

硬性要求:
1. mock 桩必须拦截告警指向的危险 sink 调用,绝不真实执行危险操作;
2. 严格遵守 CAPTURED 契约:
   CAPTURED = {{"sink_api": "<危险API名>", "calls": []}}
   每次拦截到的危险调用向 CAPTURED["calls"] 追加一个 dict,**必须含 "args" 键**
   (危险参数的字符串形式,如 SQL 语句 / 命令行 / 文件路径);
   若该调用方式本身安全(如参数化绑定、白名单校验),额外附加 "sanitized": True;
3. payload 必须包含标记串 "{marker}",并设计成能流到 sink;
   即便你认为告警可能是误报,也请正常构造,由动态验证裁决;
4. mock_code 中不允许出现对危险 API 的调用形态(允许对它们赋值/掉包)。

{lang_rules}

输出严格 JSON(不要输出任何解释文字):
{output_schema}

CWE 类型:{cwe}
原始告警:{alert_message}

few-shot 示例(参考格式与风格,不要照抄内容):
{examples}

被提取的业务代码:
```{fence}
{snippet}
```
{feedback}
只输出 JSON。"""

_LANG_RULES = {
    "python": """5. 语言为 Python:用"掉包"方式拦截(如 sqlite3.connect = 桩),并定义 _install_mock() 完成安装;
6. "imports" 列出业务片段引用但未定义、harness 运行所需的 import 语句。""",
    "php": """5. 语言为 PHP:PHP 内建函数无法被重新定义,故采用"接缝重定向":
   定义名为 __mock_<原函数名> 的桩函数,并在 "redirect" 数组列出需要重定向的原函数名
   (harness 会把业务片段中的 <原函数名>( 改写为 __mock_<原函数名>( );
   桩函数返回无害值(字符串返回 ''、结果集返回 null 或最小桩对象);
6. mock_code 不要包含 <?php 标签(harness 统一加),不要定义 _install_mock(对 PHP 无意义);
7. "imports" 对 PHP 固定输出空数组。""",
}

_SCHEMA = {
    "python": """{{"imports": ["import os", ...],
 "mock_code": "<完整 mock 源码,含 CAPTURED 与 _install_mock()>",
 "payload": "<含 {marker} 的触发输入>",
 "rationale": "<一句话拦截策略>"}}""",
    "php": """{{"redirect": ["mysqli_query", ...],
 "mock_code": "<PHP 桩代码,含 $GLOBALS['CAPTURED'] 与 __mock_<函数名>() 定义,不含 <?php>",
 "payload": "<含 {marker} 的触发输入>",
 "sink_api": "<被拦截的危险函数名>",
 "rationale": "<一句话拦截策略>"}}""",
}


def _build_prompt(alert: dict, snippet: str, feedback: str | None,
                  language: str = "python") -> str:
    fb = ""
    if feedback:
        fb = ("上一轮尝试失败,判定如下,请修正 mock(注意保持 CAPTURED 契约):\n"
              + feedback + "\n")
    if language == "php":
        examples = ("--- 示例 1:拦截 mysqli_query(PHP)---\n" + _EXAMPLE_PHP_SQLI
                    + "\n--- 示例 2:拦截 shell_exec(PHP)---\n" + _EXAMPLE_PHP_CMD)
        lang_name, fence = "PHP", "php"
    else:
        examples = ("--- 示例 1:拦截 sqlite3 ---\n" + _EXAMPLE_SQLITE
                    + "\n--- 示例 2:拦截 os.system ---\n" + _EXAMPLE_CMD)
        lang_name, fence = "Python", "python"
    return PROMPT_TEMPLATE.format(
        marker=MARKER, cwe=alert.get("cwe") or "未知",
        alert_message=(alert.get("message") or "")[:300],
        lang_name=lang_name, fence=fence,
        lang_rules=_LANG_RULES.get(language, _LANG_RULES["python"]),
        output_schema=_SCHEMA.get(language, _SCHEMA["python"]).format(
            marker=MARKER),
        examples=examples, snippet=snippet, feedback=fb,
    )


def _validate(mock_code: str, payload: str, imports: list[str],
              language: str = "python") -> str | None:
    """返回 None 表示通过;否则返回失败原因。"""
    if not isinstance(mock_code, str) or "CAPTURED" not in mock_code:
        return "mock_code 缺少 CAPTURED"
    if not isinstance(payload, str) or MARKER not in payload:
        return f"payload 未包含标记串 {MARKER}"
    if language == "php":
        blocklist, flags = _BLOCKLIST_CALLS_PHP, re.IGNORECASE
    else:
        blocklist, flags = _BLOCKLIST_CALLS, 0
    for pat in blocklist:
        if re.search(pat, mock_code, flags):
            return f"mock_code 含危险调用形态:{pat}"
    if language == "php":
        # PHP:不能本地 compile,做结构性校验(花括号配平 + 桩定义存在)
        if "<?php" in mock_code:
            return "mock_code 不应包含 <?php 标签"
        if mock_code.count("{") != mock_code.count("}"):
            return "mock_code 花括号不配平"
        if "__mock_" not in mock_code:
            return "mock_code 缺少 __mock_<函数名> 桩定义"
        return None
    if "_install_mock" not in mock_code:
        return "mock_code 缺少 _install_mock()"
    try:
        compile("\n".join(list(imports) + [mock_code]), "<mock>", "exec")
    except SyntaxError as exc:
        return f"mock_code 语法错误:{exc}"
    return None


def _write(run_dir: Path, info: dict, language: str = "python") -> dict:
    name = "mock_patch.py" if language == "python" else "mock_patch.php"
    (run_dir / name).write_text(info["mock_code"], encoding="utf-8")
    (run_dir / "payload.txt").write_text(info["payload"], encoding="utf-8")
    info["mock_path"] = str((run_dir / name).as_posix())
    info["mock_file"] = name
    info["payload_path"] = str((run_dir / "payload.txt").as_posix())
    (run_dir / "mock_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def _fail(run_dir: Path, error: str, **extra) -> dict:
    info = {"ok": False, "error": error, **extra}
    (run_dir / "mock_meta.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    return info


def _template_info(alert: dict, extract_meta: dict, run_dir: Path,
                   tpl_name: str) -> dict:
    tpl = TEMPLATES[tpl_name]
    payload = tpl["payload_fn"](alert)
    info = {
        "ok": True, "template": tpl_name,
        "generated_by": "template",
        "language": tpl["language"],
        "llm_backend": None, "llm_calls": 0,
        "payload": payload, "imports": list(tpl["imports"]),
        "sink_function": extract_meta.get("sink_function"),
        "sink_api": tpl.get("sink_api"),
        # 接缝重定向表:harness 据此把业务片段中的 sink 调用改到 __mock_* 
        "redirect": list(tpl.get("redirect") or []),
        "mock_code": tpl["mock_code"].lstrip(),
    }
    return _write(run_dir, info, tpl["language"])


def generate(alert: dict, extract_meta: dict, run_dir: str | Path, *,
             backend: str | None = None, model: str = DEFAULT_MODEL,
             replay_file: str | None = None, record_dir: str | None = None,
             feedback: str | None = None, attempt: int = 1) -> dict:
    """生成 mock 桩与 payload。

    backend=None/"template":仅模板(按 语言×CWE 选择);
    backend="deepseek"/"replay"/"dry":先走 LLM,失败回退模板(如有),
    无模板可回退时返回 ok=False(由编排器按三分类处理)。
    """
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    language = extract_meta.get("language") or "python"
    snippet_file = extract_meta.get("snippet_file") or "snippet.py"
    snippet_path = run_dir / snippet_file
    snippet = (snippet_path.read_text(encoding="utf-8")
               if snippet_path.exists() else "")

    tpl_name = pick_template(alert, language)

    if not backend or backend == "template":
        if tpl_name is None:
            return _fail(run_dir, f"no_template_for:{language}/{alert.get('cwe')}",
                         llm_backend=None, llm_calls=0)
        return _template_info(alert, extract_meta, run_dir, tpl_name)

    be = make_backend(backend, model=model, replay_file=replay_file,
                      record_dir=record_dir)
    prompt = _build_prompt(alert, snippet, feedback, language)
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
            "prompt_version": MOCK_PROMPT_VERSION, "language": language,
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
                               str(item.get("payload") or ""), imports,
                               language)
            if reason:
                info["llm_error"] = f"校验失败:{reason}"
            else:
                info.update({
                    "ok": True, "generated_by": f"llm({backend})",
                    "mock_code": str(item["mock_code"]),
                    "payload": str(item["payload"]),
                    "imports": [str(x) for x in imports],
                    "redirect": [str(x) for x in (item.get("redirect") or [])],
                    "sink_api": item.get("sink_api"),
                    "rationale": str(item.get("rationale") or "")[:300],
                })
                return _write(run_dir, info, language)

    # ---- 回退:模板保底 ----
    if tpl_name is not None:
        info_fb = _template_info(alert, extract_meta, run_dir, tpl_name)
        info_fb["generated_by"] = "llm->fallback-template"
        info_fb["fallback_reason"] = info.get("llm_error")
        info_fb["llm_calls"] = info.get("llm_calls", 0)
        info_fb["llm_backend"] = backend
        return _write(run_dir, info_fb, language)
    return _fail(run_dir, f"llm_failed_and_no_template:{info.get('llm_error')}",
                 **{k: v for k, v in info.items()
                    if k in ("llm_backend", "llm_calls", "attempt")})
