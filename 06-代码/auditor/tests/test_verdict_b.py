# -*- coding: utf-8 -*-
"""模式 B(LLM 日志推理判定)单元测试——离线假后端,不烧 API。

重点验证三道确定性护栏:坏运行不进 LLM、输出白名单、分类与执行证据一致性。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from auditor import verdict  # noqa: E402

PAYLOAD = "zxq-demo-marker; echo pwned"
ALERT = {"alert_id": "A-078", "cwe": "CWE-78", "message": "命令注入告警"}
EVIDENCE = {"snippet": "def run_command(u):\n    os.system('ls ' + u)\n",
            "mock": "def _install_mock():\n    os.system = _fake\n"}


def _run(calls=None, exit_code=0, env_ok=True, omit_result=False):
    if omit_result:
        stdout = "some noise without result marker"
    else:
        stdout = ("@@RESULT@@" + json.dumps(
            {"captured": {"calls": calls or []}, "error": None},
            ensure_ascii=False))
    return {"env_ok": env_ok, "exit_code": exit_code,
            "stdout": stdout, "stderr": ""}


class _FakeBackend:
    name = "fake"

    def __init__(self, reply):
        self.reply = reply
        self.calls = 0

    def complete_for(self, key, prompt):
        self.calls += 1
        return self.reply


def _reply(label, reason="测试归因", fix="改 mock"):
    return json.dumps({"verdict": label, "reason": reason,
                       "fix_suggestion": fix}, ensure_ascii=False)


class TestModeB(unittest.TestCase):
    def test_bad_env_guarded_before_llm(self):
        be = _FakeBackend(_reply("TP"))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(env_ok=False),
                                 EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")
        self.assertEqual(v["confirmed_by"], "deterministic_guard")
        self.assertEqual(v["judge_llm_calls"], 0)
        self.assertEqual(be.calls, 0)

    def test_failed_run_guarded_before_llm(self):
        be = _FakeBackend(_reply("TP"))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(exit_code=1),
                                 EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")
        self.assertEqual(be.calls, 0)

    def test_tp_with_reached_payload_accepted(self):
        be = _FakeBackend(_reply("TP"))
        run = _run(calls=[{"args": f"ls {PAYLOAD}"}])
        v = verdict.judge_mode_b(ALERT, PAYLOAD, run, EVIDENCE, be)
        self.assertEqual(v["verdict"], "TP")
        self.assertEqual(v["confirmed_by"], "llm_reasoning(deterministic-guarded)")
        self.assertEqual(v["judge_llm_calls"], 1)

    def test_tp_without_reach_downgraded(self):
        be = _FakeBackend(_reply("TP"))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(calls=[]), EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")
        self.assertEqual(v["confirmed_by"], "deterministic_guard")
        self.assertIn("护栏", v["reason"])

    def test_fp_without_reach_downgraded(self):
        be = _FakeBackend(_reply("FP"))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(calls=[]), EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")

    def test_fp_with_sanitized_reach_accepted(self):
        be = _FakeBackend(_reply("FP"))
        run = _run(calls=[{"args": f"ls {PAYLOAD}", "sanitized": True}])
        v = verdict.judge_mode_b(ALERT, PAYLOAD, run, EVIDENCE, be)
        self.assertEqual(v["verdict"], "FP")

    def test_payload_failed_to_trigger_is_unconfirmed(self):
        # ②payload 未能触发 → 必须归 Unconfirmed,不得判 FP(方案口径)
        be = _FakeBackend(_reply("Unconfirmed", fix="改 payload"))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(calls=[]), EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")
        self.assertEqual(v["confirmed_by"], "llm_reasoning(deterministic-guarded)")

    def test_unparseable_output_guarded(self):
        be = _FakeBackend("我觉得这条告警像是真的漏洞。")
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(calls=[]), EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")
        self.assertIn("不可解析", v["reason"])

    def test_verdict_whitelist_enforced(self):
        be = _FakeBackend(json.dumps({"verdict": "可能有问题", "reason": "x"}))
        v = verdict.judge_mode_b(ALERT, PAYLOAD, _run(calls=[]), EVIDENCE, be)
        self.assertEqual(v["verdict"], "Unconfirmed")

    def test_invalid_fix_suggestion_normalized(self):
        be = _FakeBackend(_reply("TP", fix="删库跑路"))
        run = _run(calls=[{"args": PAYLOAD}])
        v = verdict.judge_mode_b(ALERT, PAYLOAD, run, EVIDENCE, be)
        self.assertIsNone(v["fix_suggestion"])

    def test_marked_output_in_code_fence_parsed(self):
        reply = "```json\n" + _reply("TP") + "\n```"
        be = _FakeBackend(reply)
        run = _run(calls=[{"args": PAYLOAD}])
        v = verdict.judge_mode_b(ALERT, PAYLOAD, run, EVIDENCE, be)
        self.assertEqual(v["verdict"], "TP")


if __name__ == "__main__":
    unittest.main()
