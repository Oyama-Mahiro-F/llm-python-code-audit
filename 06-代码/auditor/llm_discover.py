# -*- coding: utf-8 -*-
"""LLM 候选发现通道 —— SAST 之外的第二个候选来源。

## 为什么需要它(写进报告用)

SAST 规则覆盖不到的漏洞永远不会进入本流水线,系统召回上界被 SAST 封住。
本模块不依赖任何 SAST 告警,直接把函数源码交给大模型判断是否存在污点流,
从而把"发现能力"与"该规则集是否覆盖"解耦。

## 与"用 LLM 直接判定漏洞"的本质区别

本模块产出的候选**一律不被采纳**,必须经下游 Extract-Mock-Test 动态验证。
即:LLM 在这里只当"候选生成器",其幻觉由确定性验证层兜住——
这是本项目"确定性夹住不确定性"的结构在发现层的延伸。

## 接口(与 sast_alerts.json 完全同 schema,下游零改动)

    python -m auditor.llm_discover --project <项目目录> \\
        --out records/llm_candidates.json --backend dry

    {
      "tool": "llm_discover", "backend": "...", "model": "...",
      "prompt_version": "...", "generated_at": "...", "ok": true,
      "stats": {"files", "functions", "llm_calls", "candidates", "errors"},
      "alerts": [{"alert_id": "L-001", "check_id": "llm.discover.<cwe>",
                  "path", "line", "col", "end_line", "cwe", "message",
                  "metavars": {"source","sink","function","confidence"}}]
    }

alert_id 用 `L-` 前缀,与 SAST 的 `A-` 不冲突,合并后全局唯一。

## 后端(可插拔)

  deepseek  真实 DeepSeek API(OpenAI 兼容 /chat/completions,需 DEEPSEEK_API_KEY)
  replay    回放已录制的响应 JSON(离线回归/演示用;无 key 时验证链路)
  dry       不调用 LLM,只做切片与提示词构造,输出 token 估算(干跑校验)

## 边界(如实记录)

- 本模块产出的候选**未经任何验证**,置信度字段仅为 LLM 自述,不参与判定;
- `dry`/`replay` 不产生真实 LLM 输出,不得用于报告"LLM 发现能力"的数据;
- 真实 API 调用会产生费用,`--max-functions` 与 `--max-chars` 用于控制预算。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_MODEL = "deepseek-chat"
PROMPT_VERSION = "v1-2026-10-30"
DEFAULT_CWE_SCOPE = ["CWE-89", "CWE-78", "CWE-22", "CWE-79"]
ALERT_ID_PREFIX = "L-"

PROMPT_TEMPLATE = """你是代码安全审计助手。请只做一件事:找出给定函数里**可能存在的污点流漏洞**。

本次只关注这些漏洞类型:{cwe_scope}

函数所在文件:{filename}
函数名:{func_name}
行号范围:{start_line}-{end_line}

函数源码:
```python
{code}
```

判定要求:
1. 只有当你能够明确指出"外部可控输入(source)→ 未经净化 → 到达危险操作(sink)"的路径时才报告;
2. 不报告风格问题、密码学误用、配置问题、依赖问题;
3. sink 行号必须是给定源码中真实存在的行(按上面的行号范围换算);
4. 输出严格的 JSON 数组,每项字段如下,不要输出任何解释文字:
   {{"cwe": "CWE-xxx", "line": <sink 行号>, "source": "<source 描述>",
     "sink": "<sink 函数名>", "reason": "<一句话理由>", "confidence": <0~1 浮点数>}}
5. 没有发现就输出 []

只输出 JSON。
"""


# ---------------------------------------------------------------- AST 切片
def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def iter_top_functions(root):
    """产出最外层函数/方法定义(跳过嵌套函数,避免重复切片)。"""
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        parent = node.parent
        nested = False
        while parent is not None:
            if parent.type == "function_definition":
                nested = True
                break
            parent = parent.parent
        if not nested:
            yield node


def slice_functions(path: str | Path, max_chars: int) -> list[dict]:
    """把一个源文件切成若干函数单元;超过 max_chars 的函数跳过并记录。"""
    src = Path(path).read_bytes()
    tree = Parser(PY_LANGUAGE).parse(src)
    out = []
    for node in iter_top_functions(tree.root_node):
        name_node = node.child_by_field_name("name")
        code = node.text.decode("utf-8", errors="replace")
        if len(code) > max_chars:
            out.append({
                "name": (name_node.text.decode() if name_node is not None else "?"),
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "code": None,
                "skipped": f"too_large:{len(code)}>{max_chars}",
            })
            continue
        out.append({
            "name": (name_node.text.decode() if name_node is not None else "?"),
            "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "code": code,
        })
    return out


def build_prompt(unit: dict, filename: str, cwe_scope: list[str]) -> str:
    return PROMPT_TEMPLATE.format(
        cwe_scope="、".join(cwe_scope),
        filename=filename,
        func_name=unit["name"],
        start_line=unit["start_line"],
        end_line=unit["end_line"],
        code=unit["code"],
    )


# ---------------------------------------------------------------- LLM 输出解析
def parse_llm_json(text: str) -> list[dict]:
    """容错解析 LLM 返回:支持 ```json 代码块、裸数组、单对象、前后夹杂文字。"""
    if not text:
        return []
    t = text.strip()
    # 去掉 markdown 代码围栏
    m = re.search(r"```(?:json)?\s*(.+?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    # 先尝试整体解析(可能是单个对象或纯数组)
    try:
        data = json.loads(t)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
    except json.JSONDecodeError:
        pass
    # 再截取第一个 '[' 到最后一个 ']'(处理前后夹杂说明文字)
    i, j = t.find("["), t.rfind("]")
    if i == -1 or j == -1 or j <= i:
        return []
    try:
        data = json.loads(t[i:j + 1])
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return [d for d in data if isinstance(d, dict)]


# ---------------------------------------------------------------- 后端
class DryBackend:
    """不调用 LLM:只验证切片与提示词构造,产出 0 条候选。"""

    name = "dry"

    def __init__(self, model: str = "-", **_):
        self.model = model
        self.calls = 0
        self.chars = 0

    def complete(self, prompt: str) -> str:
        self.calls += 1
        self.chars += len(prompt)
        return "[]"


class ReplayBackend:
    """回放预先录制的响应。key = "<相对路径>::<函数名>"。"""

    name = "replay"

    def __init__(self, replay_file: str, model: str = "-", **_):
        self.model = model
        self.calls = 0
        self.chars = 0
        self._data = json.loads(Path(replay_file).read_text(encoding="utf-8"))

    def complete_for(self, key: str, prompt: str) -> str:
        self.calls += 1
        self.chars += len(prompt)
        return self._data.get(key, "") or "[]"

    def complete(self, prompt: str, key: str = "") -> str:  # pragma: no cover
        return self.complete_for(key, prompt)


class DeepSeekBackend:
    """真实 DeepSeek API(OpenAI 兼容)。需要环境变量 DEEPSEEK_API_KEY。"""

    name = "deepseek"

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None,
                 base_url: str = DEEPSEEK_URL, timeout: int = 90,
                 temperature: float = 0.0, record_dir: str | None = None, **_):
        self.model = model
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        if not self.api_key:
            raise RuntimeError(
                "缺少 DEEPSEEK_API_KEY;无密钥时请改用 --backend dry 或 replay")
        self.base_url = base_url
        self.timeout = timeout
        self.temperature = temperature
        self.calls = 0
        self.chars = 0
        self._record = {}
        self.record_dir = Path(record_dir) if record_dir else None

    def complete_for(self, key: str, prompt: str) -> str:
        import requests  # 延迟导入:dry/replay 后端不依赖 requests
        self.calls += 1
        self.chars += len(prompt)
        resp = requests.post(
            self.base_url,
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"},
            json={"model": self.model, "temperature": self.temperature,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=self.timeout,
        )
        if resp.status_code >= 400:
            # 带上响应体,便于定位 422/429 等瞬时问题(DeepSeek 会给出明细)
            raise RuntimeError(
                f"HTTP {resp.status_code} from LLM API: {resp.text[:300]}")
        content = resp.json()["choices"][0]["message"]["content"]
        self._record[key] = content
        if self.record_dir is not None:
            # 合并写入:后端实例逐告警创建,若直接整文件覆写会丢失
            # 其他告警的录制(实测 bug:多告警运行只剩最后一条)
            self.record_dir.mkdir(parents=True, exist_ok=True)
            rf = self.record_dir / "llm_replay.json"
            merged = {}
            if rf.exists():
                try:
                    merged = json.loads(rf.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    merged = {}
            merged.update(self._record)
            rf.write_text(json.dumps(merged, ensure_ascii=False, indent=2),
                          encoding="utf-8")
        return content

    def complete(self, prompt: str, key: str = "") -> str:  # pragma: no cover
        return self.complete_for(key, prompt)


def make_backend(name: str, **kw):
    # 防御:model=None 会让请求体出现 "model": null 而 422,统一回落默认模型
    if not kw.get("model"):
        kw["model"] = DEFAULT_MODEL
    if name == "dry":
        return DryBackend(**kw)
    if name == "replay":
        return ReplayBackend(**kw)
    if name == "deepseek":
        return DeepSeekBackend(**kw)
    raise ValueError(f"unknown backend: {name}")


# ---------------------------------------------------------------- 主流程
def discover(project_dir: str | Path, out_path: str | Path, *,
             backend: str = "dry", model: str = DEFAULT_MODEL,
             cwe_scope: list[str] | None = None,
             patterns: list[str] | None = None,
             max_functions: int = 50, max_chars: int = 8000,
             replay_file: str | None = None,
             record_dir: str | None = None) -> dict:
    project_dir = Path(project_dir).resolve()
    out_path = Path(out_path)
    cwe_scope = cwe_scope or list(DEFAULT_CWE_SCOPE)
    patterns = patterns or ["*.py"]

    be = make_backend(backend, model=model, replay_file=replay_file,
                      record_dir=record_dir)

    files = []
    for pat in patterns:
        files.extend(sorted(project_dir.rglob(pat)))
    files = [f for f in files if ".venv" not in f.parts]

    stats = {"files": len(files), "functions": 0, "skipped": 0,
             "llm_calls": 0, "candidates": 0, "errors": 0}
    errors: list[str] = []
    alerts: list[dict] = []
    seen = set()
    budget = max_functions

    for f in files:
        if budget <= 0:
            break
        rel = f.relative_to(project_dir).as_posix()
        try:
            units = slice_functions(f, max_chars)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{rel}: slice_failed:{exc}")
            stats["errors"] += 1
            continue
        for unit in units:
            if budget <= 0:
                break
            stats["functions"] += 1
            if unit["code"] is None:
                stats["skipped"] += 1
                continue
            budget -= 1
            prompt = build_prompt(unit, rel, cwe_scope)
            key = f"{rel}::{unit['name']}"
            try:
                if hasattr(be, "complete_for"):
                    raw = be.complete_for(key, prompt)
                else:
                    raw = be.complete(prompt)
            except Exception as exc:  # 网络/限额等
                errors.append(f"{key}: llm_failed:{type(exc).__name__}:{exc}")
                stats["errors"] += 1
                continue
            stats["llm_calls"] = be.calls
            for item in parse_llm_json(raw):
                cwe = str(item.get("cwe") or "").strip().upper()
                if not re.fullmatch(r"CWE-\d+", cwe):
                    continue
                if cwe not in cwe_scope:
                    continue
                line = item.get("line")
                if not isinstance(line, int):
                    line = unit["start_line"]
                line = max(unit["start_line"], min(line, unit["end_line"]))
                dedup = (rel, line, cwe)
                if dedup in seen:
                    continue
                seen.add(dedup)
                alert_id = f"{ALERT_ID_PREFIX}{len(alerts) + 1:03d}"
                alerts.append({
                    "alert_id": alert_id,
                    "check_id": f"llm.discover.{cwe.lower().replace('-', '')}",
                    "path": rel,
                    "line": line,
                    "col": None,
                    "end_line": line,
                    "cwe": cwe,
                    "message": ("LLM 候选(未经动态验证):"
                                + str(item.get("reason") or ""))[:500],
                    "metavars": {
                        "source": item.get("source"),
                        "sink": item.get("sink"),
                        "function": unit["name"],
                        "confidence_llm_self_report": item.get("confidence"),
                        "note": "置信度为 LLM 自述,不参与判定",
                    },
                })
                stats["candidates"] += 1

    result = {
        "tool": "llm_discover",
        "backend": backend,
        "model": getattr(be, "model", model),
        "prompt_version": PROMPT_VERSION,
        "cwe_scope": cwe_scope,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ok": stats["errors"] == 0,
        "stats": stats,
        "prompt_chars_total": getattr(be, "chars", 0),
        "errors_from_tool": errors,
        "alerts": alerts,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="LLM 候选发现通道(SAST 之外的第二个候选来源)")
    ap.add_argument("--project", required=True, help="被扫描项目目录")
    ap.add_argument("--out", required=True, help="输出 JSON 路径")
    ap.add_argument("--backend", default="dry",
                    choices=["dry", "replay", "deepseek"])
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--cwe", default=",".join(DEFAULT_CWE_SCOPE),
                    help="逗号分隔的 CWE 范围")
    ap.add_argument("--pattern", default="*.py", help="文件匹配模式")
    ap.add_argument("--max-functions", type=int, default=50,
                    help="最多送 LLM 的函数数(预算控制)")
    ap.add_argument("--max-chars", type=int, default=8000,
                    help="单个函数源码字符上限")
    ap.add_argument("--replay-file", help="replay 后端的响应 JSON")
    ap.add_argument("--record-dir", help="deepseek 后端把响应录制到该目录")
    args = ap.parse_args(argv)

    cwe_scope = [c.strip().upper() for c in args.cwe.split(",") if c.strip()]
    try:
        result = discover(
            args.project, args.out,
            backend=args.backend, model=args.model, cwe_scope=cwe_scope,
            patterns=[args.pattern], max_functions=args.max_functions,
            max_chars=args.max_chars, replay_file=args.replay_file,
            record_dir=args.record_dir,
        )
    except RuntimeError as exc:
        print(f"[llm_discover] {exc}", file=sys.stderr)
        return 2

    s = result["stats"]
    print(f"[llm_discover] backend={result['backend']} "
          f"files={s['files']} funcs={s['functions']} "
          f"llm_calls={s['llm_calls']} candidates={s['candidates']} "
          f"errors={s['errors']} -> {Path(args.out).as_posix()}")
    if result["backend"] == "dry":
        print(f"[llm_discover] dry 模式:未调用 LLM,候选数必为 0;"
              f"prompt 字符总量={result['prompt_chars_total']}"
              f"(约 {result['prompt_chars_total'] // 3.5:.0f} tokens 量级)")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
