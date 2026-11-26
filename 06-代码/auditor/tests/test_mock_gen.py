# -*- coding: utf-8 -*-
"""mock_gen(LLM 路径)与泛化判定器的单元测试。全部离线:replay/dry 后端,不烧 API。

运行:cd 06-代码 && .venv/Scripts/python.exe -m unittest discover -s auditor/tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from auditor import mock_gen, verdict  # noqa: E402

ALERT_89 = {"alert_id": "A-001", "cwe": "CWE-89",
            "message": "SQL 注入告警", "line": 20}
ALERT_78 = {"alert_id": "A-078", "cwe": "CWE-78",
            "message": "os.system 命令注入告警", "line": 8}
EXTRACT = {"ok": True, "sink_function": "run_command",
           "snippet_path": "unused"}

GOOD_MOCK_78 = {
    "imports": ["import os"],
    "mock_code": ("CAPTURED = {'sink_api': 'os.system', 'calls': []}\n"
                  "\n"
                  "def _fake_system(cmd):\n"
                  "    CAPTURED['calls'].append({'args': str(cmd)})\n"
                  "    return 0\n"
                  "\n"
                  "def _install_mock():\n"
                  "    import os\n"
                  "    os.system = _fake_system\n"),
    "payload": mock_gen.MARKER + "; echo pwned",
    "rationale": "掉包 os.system,只记录命令不执行",
}
BAD_MOCK_CALL = {
    "imports": ["import os"],
    "mock_code": ("CAPTURED = {'sink_api': 'os.system', 'calls': []}\n"
                  "def _install_mock():\n"
                  "    import os\n"
                  "    os.system('ls')  # 危险:桩里真调用了\n"),
    "payload": mock_gen.MARKER,
}
BROKEN_PY = {
    "imports": ["import sqlite3"],
    "mock_code": "CAPTURED = {oops!!!\n\ndef _install_mock():\n    pass\n",
    "payload": mock_gen.MARKER,
}


def _replay_file(tmp: Path, key: str, item: dict) -> str:
    p = tmp / "mock_replay.json"
    p.write_text(json.dumps({key: json.dumps(item, ensure_ascii=False)}),
                 encoding="utf-8")
    return str(p)


class TestMockGenTemplate(unittest.TestCase):
    def test_template_default_still_works(self):
        with tempfile.TemporaryDirectory() as td:
            info = mock_gen.generate(ALERT_89, EXTRACT, td)
            self.assertTrue(info["ok"])
            self.assertEqual(info["generated_by"], "template")
            self.assertIn("sanitized", info["mock_code"])
            self.assertEqual(mock_gen.MARKER in info["payload"], True)

    def test_template_unsupported_cwe_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            info = mock_gen.generate(ALERT_78, EXTRACT, td)
            self.assertFalse(info["ok"])
            self.assertIn("no_template_for", info["error"])


class TestMockGenLLM(unittest.TestCase):
    def test_llm_good_response_cwe78(self):
        with tempfile.TemporaryDirectory() as td:
            rf = _replay_file(Path(td), "A-078::attempt1", GOOD_MOCK_78)
            info = mock_gen.generate(ALERT_78, EXTRACT, td, backend="replay",
                                     replay_file=rf)
            self.assertTrue(info["ok"], info.get("llm_error"))
            self.assertEqual(info["generated_by"], "llm(replay)")
            # replay 为离线回放、零 API 成本,不计入 LLM 调用预算
            self.assertEqual(info["llm_calls"], 0)
            self.assertIn("import os", info["imports"])
            self.assertEqual(
                (Path(td) / "mock_patch.py").exists(), True)
            compile(info["mock_code"], "<mock>", "exec")

    def test_llm_bad_python_falls_back_to_template_for_cwe89(self):
        with tempfile.TemporaryDirectory() as td:
            rf = _replay_file(Path(td), "A-001::attempt1", BROKEN_PY)
            info = mock_gen.generate(ALERT_89, EXTRACT, td, backend="replay",
                                     replay_file=rf)
            self.assertTrue(info["ok"])
            self.assertEqual(info["generated_by"], "llm->fallback-template")
            self.assertIn("语法错误", info["fallback_reason"])

    def test_llm_bad_python_no_fallback_for_unsupported_cwe(self):
        with tempfile.TemporaryDirectory() as td:
            rf = _replay_file(Path(td), "A-078::attempt1", BROKEN_PY)
            info = mock_gen.generate(ALERT_78, EXTRACT, td, backend="replay",
                                     replay_file=rf)
            self.assertFalse(info["ok"])
            self.assertIn("no_template", info["error"])

    def test_blocklist_rejects_mock_that_calls_dangerous_api(self):
        with tempfile.TemporaryDirectory() as td:
            rf = _replay_file(Path(td), "A-078::attempt1", BAD_MOCK_CALL)
            info = mock_gen.generate(ALERT_78, EXTRACT, td, backend="replay",
                                     replay_file=rf)
            self.assertFalse(info["ok"])
            self.assertIn("危险调用形态", info["error"])

    def test_validation_allows_patch_assignment_form(self):
        # `os.system = _fake` 是拦截本身,不得被黑名单误杀
        self.assertIsNone(mock_gen._validate(
            GOOD_MOCK_78["mock_code"], GOOD_MOCK_78["payload"],
            GOOD_MOCK_78["imports"]))

    def test_unbalanced_or_missing_marker_rejected(self):
        bad = dict(GOOD_MOCK_78)
        bad["payload"] = "no marker here"
        reason = mock_gen._validate(bad["mock_code"], bad["payload"],
                                    bad["imports"])
        self.assertIn("标记串", reason)

    def test_llm_php_shell_exec_generates(self):
        # PHP LLM 路径:接缝重定向 + 桩定义,经校验通过并落盘 mock_patch.php
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "run"
            run_dir.mkdir()
            (run_dir / "snippet.php").write_text(
                "function ping_host($host) {\n"
                "    return shell_exec('ping -c 1 ' . $host);\n"
                "}\n", encoding="utf-8")
            php_good = {
                "redirect": ["shell_exec"],
                "mock_code": (
                    "$GLOBALS['CAPTURED'] = ['sink_api' => 'shell_exec', 'calls' => []];\n"
                    "function __mock_shell_exec($cmd) {\n"
                    "    $GLOBALS['CAPTURED']['calls'][] = ['args' => "
                    "is_string($cmd) ? $cmd : var_export($cmd, true)];\n"
                    "    return '';\n"
                    "}"),
                "payload": "127.0.0.1; echo zxq-demo-marker",
                "sink_api": "shell_exec",
                "rationale": "拦截 shell_exec",
            }
            rf = _replay_file(Path(td), "A-078::attempt1", php_good)
            info = mock_gen.generate(
                {"alert_id": "A-078", "cwe": "CWE-78",
                 "message": "shell_exec 命令注入告警", "line": 14},
                {"ok": True, "language": "php", "snippet_file": "snippet.php",
                 "sink_function": "ping_host"},
                run_dir, backend="replay", replay_file=rf)
            self.assertTrue(info["ok"], info.get("llm_error"))
            self.assertEqual(info["generated_by"], "llm(replay)")
            self.assertEqual(info["language"], "php")
            self.assertIn("__mock_shell_exec", info["mock_code"])
            self.assertTrue((run_dir / "mock_patch.php").exists())


class TestVerdictGeneric(unittest.TestCase):
    RUN_OK = {"env_ok": True, "exit_code": 0,
              "stdout": '@@RESULT@@{"captured": {"calls": []}, "error": null}'}

    def _run_with_calls(self, calls):
        stdout = ('@@RESULT@@'
                  + json.dumps({"captured": {"calls": calls},
                                "error": None}, ensure_ascii=False))
        return {"env_ok": True, "exit_code": 0, "stdout": stdout,
                "stderr": ""}

    def test_payload_in_cmd_field_is_tp(self):
        run = self._run_with_calls([
            {"args": f"ls {mock_gen.MARKER}; echo pwned"}])
        v = verdict.judge_mode_a(ALERT_78, mock_gen.MARKER + "; echo pwned",
                                 run)
        self.assertEqual(v["verdict"], "TP")

    def test_sanitized_flag_is_fp(self):
        run = self._run_with_calls([
            {"args": f"ls {mock_gen.MARKER}", "sanitized": True}])
        v = verdict.judge_mode_a(ALERT_78, mock_gen.MARKER, run)
        self.assertEqual(v["verdict"], "FP")

    def test_no_reach_is_unconfirmed(self):
        run = self._run_with_calls([{"args": "ls harmless"}])
        v = verdict.judge_mode_a(ALERT_78, mock_gen.MARKER, run)
        self.assertEqual(v["verdict"], "Unconfirmed")

    def test_sqlite_template_params_still_recognized(self):
        # 模板兼容:参数化绑定(params 非空)视为净化 → FP
        run = self._run_with_calls([
            {"sql": f"SELECT * WHERE name = '{mock_gen.MARKER}'",
             "params": "(username,)"}])
        v = verdict.judge_mode_a(ALERT_89, mock_gen.MARKER, run)
        self.assertEqual(v["verdict"], "FP")


if __name__ == "__main__":
    unittest.main()
