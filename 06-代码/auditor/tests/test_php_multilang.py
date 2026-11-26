# -*- coding: utf-8 -*-
"""多语言(PHP)与描述生成、CVE 参照库的单元测试(全部离线,不需要 Docker/API)。"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from auditor import extract, harness, lang, mock_gen, narrative  # noqa: E402

CASE1 = ROOT / "demos" / "case1_php_sqli" / "user_login.php"
CASE2 = ROOT / "demos" / "case2_php_cmd" / "ping.php"
CASE3 = ROOT / "demos" / "case3_python_path" / "report_reader.py"


def _sink_line(path: Path, needle: str) -> int:
    for i, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in ln:
            return i
    raise AssertionError(f"{needle} not found")


class TestLangDetect(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(lang.detect("a.py"), "python")
        self.assertEqual(lang.detect("a.php"), "php")
        self.assertEqual(lang.detect("A.PHP"), "php")
        with self.assertRaises(ValueError):
            lang.detect("a.rb")

    def test_runtime(self):
        self.assertEqual(lang.runtime_of("x.php")["image"], "php:8.2-cli")
        self.assertEqual(lang.runtime_of("x.py")["image"], "python:3.12-slim")


class TestExtractPhp(unittest.TestCase):
    def test_php_function_and_calls(self):
        with tempfile.TemporaryDirectory() as td:
            meta = extract.extract(CASE1, _sink_line(CASE1, "mysqli_query"), td)
            self.assertTrue(meta["ok"], meta.get("error"))
            self.assertEqual(meta["language"], "php")
            self.assertEqual(meta["sink_function"], "login_check")
            self.assertEqual(meta["snippet_file"], "snippet.php")
            self.assertIn("mysqli_query", meta["direct_calls"])
            self.assertFalse(meta["cross_file_missing"])
            snippet = (Path(td) / "snippet.php").read_text(encoding="utf-8")
            self.assertIn("function login_check", snippet)
            self.assertNotIn("<?php", snippet)   # 片段不含文件头

    def test_php_shell_exec(self):
        with tempfile.TemporaryDirectory() as td:
            meta = extract.extract(CASE2, _sink_line(CASE2, "shell_exec"), td)
            self.assertTrue(meta["ok"])
            self.assertEqual(meta["sink_function"], "ping_host")
            self.assertIn("shell_exec", meta["direct_calls"])

    def test_python_module_constant_still_extracted(self):
        with tempfile.TemporaryDirectory() as td:
            meta = extract.extract(CASE3, _sink_line(CASE3, "with open("), td)
            self.assertTrue(meta["ok"])
            self.assertEqual(meta["language"], "python")
            snippet = (Path(td) / "snippet.py").read_text(encoding="utf-8")
            self.assertIn('REPORT_DIR = "/var/app/reports"', snippet)


class TestRedirect(unittest.TestCase):
    def test_rewrites_plain_call_only(self):
        src = ('function f($u) {\n'
               '    $sql = "SELECT " . $u;\n'
               '    return mysqli_query($c, $sql);\n'
               '}\n')
        out, applied = harness.apply_redirects(src, ["mysqli_query"])
        self.assertIn("__mock_mysqli_query($c, $sql)", out)
        self.assertEqual(applied[0]["count"], 1)

    def test_does_not_rewrite_member_or_prefixed(self):
        src = ("$db->mysqli_query($x);\n"
               "__mock_mysqli_query($y);\n")
        out, applied = harness.apply_redirects(src, ["mysqli_query"])
        self.assertIn("$db->mysqli_query($x)", out)
        self.assertEqual(out.count("__mock_mysqli_query"), 1)

    def test_no_redirect_keeps_source(self):
        src = "print(1)\n"
        out, applied = harness.apply_redirects(src, [])
        self.assertEqual(out, src)
        self.assertEqual(applied, [])


class TestPhpTemplates(unittest.TestCase):
    def test_template_selection_by_language_and_cwe(self):
        self.assertEqual(mock_gen.pick_template({"cwe": "CWE-89"}, "php"),
                         "php:mysqli_query")
        self.assertEqual(mock_gen.pick_template({"cwe": "CWE-78"}, "php"),
                         "php:shell_exec")
        self.assertEqual(mock_gen.pick_template({"cwe": "CWE-22"}, "python"),
                         "py:builtins.open")
        self.assertIsNone(mock_gen.pick_template({"cwe": "CWE-79"}, "php"))

    def test_php_templates_have_redirect_and_no_tag(self):
        for key in ("php:mysqli_query", "php:shell_exec", "php:file_get_contents"):
            tpl = mock_gen.TEMPLATES[key]
            self.assertTrue(tpl["redirect"], key)
            self.assertNotIn("<?php", tpl["mock_code"], key)
            self.assertIn("CAPTURED", tpl["mock_code"], key)
            self.assertIn(f"MARKER" if False else mock_gen.MARKER,
                          tpl["payload_fn"]({}), key)

    def test_php_validate_rejects_tag_and_unbalanced(self):
        self.assertIn("<?php", mock_gen._validate(
            "<?php CAPTURED=1; function __mock_x(){}", "zxq-demo-marker", [], "php"))
        self.assertIn("花括号", mock_gen._validate(
            "CAPTURED=1; function __mock_x(){", "zxq-demo-marker", [], "php"))

    def test_php_validate_rejects_dangerous_call(self):
        # mock 桩里真实调用了 shell_exec → 拒(此前 PHP 套用 Python 黑名单,拦不住)
        reason = mock_gen._validate(
            "$GLOBALS['CAPTURED'] = ['sink_api' => 'shell_exec', 'calls' => []];\n"
            "function __mock_bad($cmd) { shell_exec('rm -rf /'); return ''; }",
            "zxq-demo-marker", [], "php")
        self.assertIn("危险调用形态", reason)

    def test_php_validate_allows_mock_prefixed_template(self):
        # 模板里 __mock_shell_exec / __mock_exec / __mock_system 是拦截本身,不误伤
        self.assertIsNone(mock_gen._validate(
            mock_gen._PHP_CMD_MOCK, "127.0.0.1; echo zxq-demo-marker", [], "php"))


class TestNarrative(unittest.TestCase):
    def _state(self, cwe, alert_id, path, line, verdict="TP"):
        return {
            "alert_id": alert_id, "cwe": cwe,
            "source_alert": {"alert_id": alert_id, "path": path, "line": line,
                             "metavars": {"source": "函数参数 $user(外部可控输入)"}},
            "extract": {"ok": True, "language": "php", "file": str(CASE1),
                        "sink_function": "login_check",
                        "functions": [{"name": "login_check", "is_sink": True,
                                       "start_line": 11, "end_line": 17}]},
            "mock": {"sink_api": "mysqli_query"},
            "run": {"stdout_tail": '@@RESULT@@{"captured": {"sink_api": '
                                   '"mysqli_query", "calls": [{"args": '
                                   '"SELECT ... \'zxq-demo-marker\' OR \'1\'=\'1\'"}]},'
                                   ' "payload": "zxq-demo-marker\' OR \'1\'=\'1\'"}'},
            "verdict": {"verdict": verdict, "reason": "x"},
            "payload": "zxq-demo-marker' OR '1'='1",
        }

    def test_tp_narrative_is_specific(self):
        st = self._state("CWE-89", "L-001", "/src/user_login.php", 15)
        nar = narrative.build(st, CASE1.read_text(encoding="utf-8"), "")
        self.assertEqual(nar["location"]["function"], "login_check")
        self.assertEqual(nar["sink"]["api"], "mysqli_query")
        self.assertIn("zxq-demo-marker", nar["captured_arg"])
        # 传播行必须是函数体内的实际拼接行,且不是签名行
        self.assertEqual(nar["propagation"]["line"], 14)
        self.assertIn("$user", nar["propagation"]["code"])
        self.assertIn("LLM 候选发现通道", nar["text"])
        self.assertEqual(nar["cve_ref"]["cve_id"], "CVE-2019-15573")

    def test_sast_origin_detected(self):
        st = self._state("CWE-78", "A-001", "/src/ping.php", 14)
        st["extract"]["file"] = str(CASE2)
        st["extract"]["sink_function"] = "ping_host"
        st["extract"]["functions"][0].update({"name": "ping_host",
                                              "start_line": 10, "end_line": 15})
        st["run"]["stdout_tail"] = '@@RESULT@@{"captured": {"sink_api": "shell_exec",' \
                                   ' "calls": [{"args": "ping -c 1 127.0.0.1; echo ' \
                                   'zxq-demo-marker"}]}, "payload": "127.0.0.1; echo ' \
                                   'zxq-demo-marker"}'
        nar = narrative.build(st, CASE2.read_text(encoding="utf-8"), "")
        self.assertIn("SAST 规则扫描", nar["text"])
        self.assertIn("传播:第 13 行", nar["text"])

    def test_unconfirmed_basis(self):
        st = self._state("CWE-89", "L-001", "/src/user_login.php", 15,
                         verdict="Unconfirmed")
        nar = narrative.build(st, CASE1.read_text(encoding="utf-8"), "")
        self.assertIn("未确认", nar["basis"])
        self.assertIn("不计入误报", nar["basis"])

    def test_cve_absent_when_unmatched(self):
        st = self._state("CWE-79", "A-009", "/src/x.php", 5)
        nar = narrative.build(st, CASE1.read_text(encoding="utf-8"), "")
        self.assertIsNone(nar["cve_ref"])


class TestCveLibrary(unittest.TestCase):
    def test_entries_have_required_fields(self):
        refs = narrative.load_cve_refs()
        self.assertGreaterEqual(len(refs), 8)
        for r in refs:
            for k in ("cwe", "cve_id", "nvd_url", "summary_zh"):
                self.assertTrue(r.get(k), f"{r.get('cve_id')} missing {k}")
            self.assertRegex(r["cve_id"], r"^CVE-\d{4}-\d+$")
            self.assertIn("nvd.nist.gov/vuln/detail/", r["nvd_url"])

    def test_match_prefers_language(self):
        refs = narrative.load_cve_refs()
        php = narrative.match_cve("CWE-22", "php", refs)
        py = narrative.match_cve("CWE-22", "python", refs)
        self.assertEqual(php["language"], "php")
        self.assertEqual(py["language"], "python")
        self.assertIsNone(narrative.match_cve("CWE-1333", "python", refs))


if __name__ == "__main__":
    unittest.main()
