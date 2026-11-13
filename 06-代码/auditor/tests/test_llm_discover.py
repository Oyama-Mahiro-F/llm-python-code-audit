# -*- coding: utf-8 -*-
"""LLM 候选发现通道单元测试。

运行:cd 06-代码 && .venv/Scripts/python.exe -m unittest discover -s auditor/tests -v

说明:测试全部走 `dry` / `replay` 后端,**不发起真实 LLM 调用**,
因此可离线、可重复、零费用;真实 DeepSeek 后端需 DEEPSEEK_API_KEY。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from auditor import llm_discover  # noqa: E402

SAMPLES = ROOT / "samples"
VULN = SAMPLES / "vuln_cwe89_user_dao.py"


class TestSliceFunctions(unittest.TestCase):
    def test_finds_expected_functions(self):
        units = llm_discover.slice_functions(VULN, max_chars=8000)
        names = [u["name"] for u in units]
        self.assertIn("open_db", names)
        self.assertIn("get_user", names)
        for u in units:
            self.assertIsNotNone(u["code"])
            self.assertLess(u["start_line"], u["end_line"] + 1)

    def test_oversize_function_skipped(self):
        units = llm_discover.slice_functions(VULN, max_chars=10)
        self.assertTrue(all(u["code"] is None for u in units))
        self.assertTrue(all("too_large" in (u.get("skipped") or "")
                            for u in units))


class TestParseLlmJson(unittest.TestCase):
    def test_variants(self):
        cases = [
            ('```json\n[{"cwe":"CWE-89","line":20}]\n```', 1),
            ('[{"cwe":"CWE-89","line":20}]', 1),
            ('没有发现任何漏洞', 0),
            ('{"cwe":"CWE-89","line":20}', 1),          # 单对象
            ('结果如下：\n[{"cwe":"CWE-78","line":10}]\n以上。', 1),
            ('', 0),
            ('[1, 2, 3]', 0),                            # 非对象元素被过滤
        ]
        for text, expect in cases:
            got = llm_discover.parse_llm_json(text)
            self.assertEqual(len(got), expect, msg=repr(text))


class TestDiscoverBackends(unittest.TestCase):
    def _run(self, backend, **kw):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            res = llm_discover.discover(SAMPLES, out, backend=backend,
                                        max_functions=20, **kw)
            self.assertTrue(out.exists())
            return res

    def test_dry_backend_produces_no_candidates(self):
        res = self._run("dry")
        self.assertEqual(res["tool"], "llm_discover")
        self.assertEqual(res["backend"], "dry")
        self.assertEqual(res["alerts"], [])
        self.assertGreater(res["stats"]["files"], 0)
        self.assertGreater(res["stats"]["functions"], 0)
        self.assertGreater(res["prompt_chars_total"], 0)

    def test_replay_backend_produces_L_alert(self):
        replay = {
            "vuln_cwe89_user_dao.py::get_user": json.dumps([{
                "cwe": "CWE-89", "line": 20,
                "source": "参数 user_id", "sink": "cursor.execute",
                "reason": "f-string 拼接", "confidence": 0.9,
            }], ensure_ascii=False),
        }
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "replay.json"
            rf.write_text(json.dumps(replay, ensure_ascii=False), encoding="utf-8")
            res = self._run("replay", replay_file=str(rf))

        self.assertEqual(len(res["alerts"]), 1)
        a = res["alerts"][0]
        self.assertTrue(a["alert_id"].startswith("L-"))
        self.assertEqual(a["cwe"], "CWE-89")
        self.assertEqual(a["path"], "vuln_cwe89_user_dao.py")
        self.assertEqual(a["line"], 20)
        self.assertIn("llm.discover", a["check_id"])
        # 置信度仅作记录,不参与判定
        self.assertEqual(a["metavars"]["function"], "get_user")
        self.assertIn("不参与判定", a["metavars"]["note"])
        self.assertIn("未经动态验证", a["message"])

    def test_cwe_out_of_scope_filtered(self):
        replay = {
            "vuln_cwe89_user_dao.py::get_user": json.dumps([
                {"cwe": "CWE-999", "line": 20, "reason": "范围外"},
            ], ensure_ascii=False),
        }
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "replay.json"
            rf.write_text(json.dumps(replay, ensure_ascii=False), encoding="utf-8")
            res = self._run("replay", replay_file=str(rf),
                            cwe_scope=["CWE-89"])
        self.assertEqual(res["alerts"], [])

    def test_out_of_range_line_clamped(self):
        replay = {
            "vuln_cwe89_user_dao.py::get_user": json.dumps([
                {"cwe": "CWE-89", "line": 99999, "reason": "越界行号"},
            ], ensure_ascii=False),
        }
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "replay.json"
            rf.write_text(json.dumps(replay, ensure_ascii=False), encoding="utf-8")
            res = self._run("replay", replay_file=str(rf))
        self.assertEqual(len(res["alerts"]), 1)
        line = res["alerts"][0]["line"]
        self.assertGreaterEqual(line, 1)
        self.assertLess(line, 1000)

    def test_same_line_duplicate_deduped(self):
        replay = {
            "vuln_cwe89_user_dao.py::get_user": json.dumps([
                {"cwe": "CWE-89", "line": 20, "reason": "a"},
                {"cwe": "CWE-89", "line": 20, "reason": "b"},
            ], ensure_ascii=False),
        }
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "replay.json"
            rf.write_text(json.dumps(replay, ensure_ascii=False), encoding="utf-8")
            res = self._run("replay", replay_file=str(rf))
        self.assertEqual(len(res["alerts"]), 1)


class TestDeepSeekBackendGuard(unittest.TestCase):
    def test_missing_api_key_raises(self):
        with self.assertRaises(RuntimeError):
            llm_discover.DeepSeekBackend(api_key="")  # 无密钥应明确报错


if __name__ == "__main__":
    unittest.main()
