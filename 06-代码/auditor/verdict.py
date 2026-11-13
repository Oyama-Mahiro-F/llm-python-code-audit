# -*- coding: utf-8 -*-
"""漏洞判定(对应《项目方案》4.3.4)。

两种判定模式(E2 实验比选):
  模式 A(硬编码检测器)——纯确定性,按 CAPTURED 契约匹配,无幻觉;
  模式 B(LLM 日志推理)——判定规则由本项目设计并写入固定提示词,
      LLM 仅负责对证据做推理分类;输出经结构化校验与确定性护栏约束。

结果三分类(方案 4.4 / 任务书 3.3):
  TP           payload 到达 sink 且构成漏洞
  FP           证据表明不构成漏洞(如参数化查询已拦截)
  Unconfirmed  环境问题 / harness 失败 / payload 未触发(不计入误报)

模式 B 的确定性护栏(代码强制,LLM 不可越过):
  1. env_ok=False 或 exit_code≠0 → 一律 Unconfirmed(LLM 无权把坏运行说成 TP);
  2. 输出不可解析 / verdict 不在白名单 → Unconfirmed(fail-safe);
  3. payload 到达证据由 CAPTURED 客观记录提供,LLM 只做归因分类。
"""
from __future__ import annotations

import json
import re

RESULT_MARK = "@@RESULT@@"

MODE_B_PROMPT_VERSION = "v1-2026-11-09"


def _extract_result(stdout: str) -> dict | None:
    for line in stdout.splitlines():
        if line.startswith(RESULT_MARK):
            try:
                return json.loads(line[len(RESULT_MARK):])
            except json.JSONDecodeError:
                return None
    return None


_ENV_ERROR_PATTERNS = (
    "ModuleNotFoundError", "ImportError", "SyntaxError",
    "NameError", "AttributeError: '_Fake",
    "No module named", "image_unavailable", "timeout",
)


def judge_mode_a(alert: dict, payload: str, run: dict) -> dict:
    """模式 A:依据 mock 捕获的 sink 入参做确定性判定。"""
    env_ok = run.get("env_ok")
    exit_code = run.get("exit_code")

    if not env_ok:
        return {"verdict": "Unconfirmed",
                "reason": "沙箱环境不可用(镜像缺失),属环境问题,不计入误报",
                "mode": "A", "fix_suggestion": "改环境", "confirmed_by": "execution"}

    if exit_code not in (0,):
        err_tail = (run.get("stderr") or "")[-800:]
        return {"verdict": "Unconfirmed",
                "reason": f"harness 运行失败(exit={exit_code}),疑似环境/组装问题:...{err_tail[-200:]}",
                "mode": "A", "fix_suggestion": "改 mock", "confirmed_by": "execution"}

    result = _extract_result(run.get("stdout", ""))
    if result is None:
        return {"verdict": "Unconfirmed",
                "reason": "harness 未输出结构化结果,判定器无法解析",
                "mode": "A", "fix_suggestion": "改 mock", "confirmed_by": "execution"}

    if result.get("error"):
        # 业务代码抛错:可能 payload 构造不当或环境差异 → 不武断判 FP
        return {"verdict": "Unconfirmed",
                "reason": f"payload 执行抛错({result['error']}),未能到达 sink;不等同于漏洞不存在",
                "mode": "A", "fix_suggestion": "改 payload", "confirmed_by": "execution"}

    captured = result.get("captured") or {}
    calls = captured.get("calls", [])
    # 泛化:payload 可出现在任一记录字段(SQL/命令/路径……),不限于 "sql";
    # 净化判定:调用记录显式标 sanitized,或模板兼容的 params 非空(参数化绑定)。
    reached = [c for c in calls
               if payload and payload in json.dumps(c, ensure_ascii=False)]
    sanitized = [c for c in reached
                 if c.get("sanitized") is True
                 or c.get("params") not in (None, "None")]

    if reached and not sanitized:
        return {
            "verdict": "TP",
            "reason": (f"payload 已到达 sink(共 {len(calls)} 次调用被拦截),"
                       "且未净化——污点数据未处理即进入危险操作,漏洞成立"),
            "mode": "A", "fix_suggestion": None,
            "confirmed_by": "execution",
            "sink_calls": len(calls),
        }
    if reached and sanitized:
        return {"verdict": "FP",
                "reason": "payload 到达 sink,但调用方式已净化(参数化/绑定),不构成漏洞",
                "mode": "A", "fix_suggestion": None, "confirmed_by": "execution",
                "sink_calls": len(calls)}
    return {"verdict": "Unconfirmed",
            "reason": "payload 未能触发 sink 调用;可能构造不当,不等同于漏洞不存在",
            "mode": "A", "fix_suggestion": "改 payload", "confirmed_by": "execution",
            "sink_calls": len(calls)}


# ---------------------------------------------------------------- 模式 B

MODE_B_PROMPT = """你是代码安全审计的质量控制员。一次沙箱动态验证已经运行完毕,
你的任务是对这次运行做**归因分类**,不是重新找漏洞。

判定口径(由项目方定义,必须严格遵守):
- TP:payload 确实到达了被拦截的危险 sink,且运行证据表明构成漏洞;
- FP:payload 到达了 sink,但运行证据表明不构成漏洞(如参数化绑定、校验生效);
- Unconfirmed:验证未得出确定结论。失败只分两类:
  ① mock/harness 环境错误(桩写错、依赖缺失、语法错误);
  ② payload 未能触发(payload 构造不当)。
  **②不等同于漏洞不存在**——只是没验证出来,必须归入 Unconfirmed,不得判 FP。

输入证据:
- 原始告警:{cwe} {alert_message}
- 触发 payload:{payload}
- harness 运行日志(stdout,完整):
{stdout}
- 运行报错(stderr,末段):
{stderr}
- 提取的业务源码:
```python
{snippet}
```
- mock 桩定义:
```python
{mock}
```

输出严格 JSON,不要任何解释文字:
{{"verdict": "TP|FP|Unconfirmed",
 "reason": "<依据运行日志的一句话归因>",
 "fix_suggestion": "改 mock|改 payload|null"}}

只输出 JSON。"""


def _extract_json_obj(text: str) -> dict | None:
    """容错提取 LLM 返回中的单个 JSON 对象(```json 围栏 / 裸对象 / 夹杂文字)。"""
    if not text:
        return None
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(.+?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    try:
        data = json.loads(t)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass
    i, j = t.find("{"), t.rfind("}")
    if i == -1 or j <= i:
        return None
    try:
        data = json.loads(t[i:j + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def judge_mode_b(alert: dict, payload: str, run: dict,
                 evidence: dict, backend, key: str = "") -> dict:
    """模式 B:LLM 日志推理判定(规则我方设计,LLM 仅推理;护栏代码强制)。"""
    # ---- 确定性护栏 1:坏运行不进 LLM,一律 Unconfirmed ----
    if not run.get("env_ok"):
        return {"verdict": "Unconfirmed",
                "reason": "沙箱环境不可用,属环境问题,不计入误报",
                "mode": "B", "fix_suggestion": "改环境",
                "confirmed_by": "deterministic_guard", "judge_llm_calls": 0}
    if run.get("exit_code") != 0:
        return {"verdict": "Unconfirmed",
                "reason": f"harness 运行失败(exit={run.get('exit_code')}),"
                          "疑似环境/组装问题,代码护栏强制 Unconfirmed",
                "mode": "B", "fix_suggestion": "改 mock",
                "confirmed_by": "deterministic_guard", "judge_llm_calls": 0}

    # ---- 组证据 → LLM 推理 ----
    prompt = MODE_B_PROMPT.format(
        cwe=alert.get("cwe") or "未知",
        alert_message=(alert.get("message") or "")[:300],
        payload=payload,
        stdout=(run.get("stdout") or "")[-3000:] or "(空)",
        stderr=(run.get("stderr") or "")[-800:] or "(空)",
        snippet=(evidence.get("snippet") or "(未提供)")[:4000],
        mock=(evidence.get("mock") or "(未提供)")[:4000],
    )
    calls_before = getattr(backend, "calls", 0)
    llm_error = None
    raw = None
    try:
        raw = (backend.complete_for(key, prompt)
               if hasattr(backend, "complete_for")
               else backend.complete(prompt))
    except Exception as exc:
        llm_error = f"{type(exc).__name__}: {exc}"
    judge_calls = getattr(backend, "calls", calls_before) - calls_before

    def _guard(reason):
        return {"verdict": "Unconfirmed", "reason": reason, "mode": "B",
                "fix_suggestion": None, "confirmed_by": "deterministic_guard",
                "judge_llm_calls": judge_calls}

    if raw is None:
        return _guard(f"模式 B 调用失败,代码护栏强制 Unconfirmed:{llm_error}")
    item = _extract_json_obj(raw)
    if not item or item.get("verdict") not in ("TP", "FP", "Unconfirmed"):
        return _guard(f"模式 B 输出不可解析或 verdict 不在白名单,强制 Unconfirmed")

    label = item["verdict"]
    fix = item.get("fix_suggestion")
    if fix not in ("改 mock", "改 payload"):
        fix = None

    # ---- 确定性护栏 2:分类必须与执行证据一致 ----
    result = _extract_result(run.get("stdout", ""))
    calls = ((result or {}).get("captured") or {}).get("calls", [])
    reached = any(payload and payload in json.dumps(c, ensure_ascii=False)
                  for c in calls)
    if label == "TP" and not reached:
        return _guard("模式 B 判 TP,但 CAPTURED 无 payload 到达记录,"
                      "与执行证据矛盾,护栏强制 Unconfirmed")
    if label == "FP" and not reached:
        return _guard("模式 B 判 FP,但 CAPTURED 无到达记录,无法凭日志排除,"
                      "护栏强制 Unconfirmed")

    return {"verdict": label,
            "reason": str(item.get("reason") or "")[:400],
            "mode": "B", "fix_suggestion": fix,
            "confirmed_by": "llm_reasoning(deterministic-guarded)",
            "judge_llm_calls": judge_calls,
            "reached": reached}
