# -*- coding: utf-8 -*-
"""Extract 工具单元测试。

运行:cd 06-代码 && .venv/Scripts/python.exe -m unittest discover -s auditor/tests -v
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from auditor import extract  # noqa: E402

SAMPLE = ROOT / "samples" / "vuln_cwe89_user_dao.py"

# 样本中 cursor.execute(query) 所在行(以文件实际内容为准,动态求出)
_LINES = SAMPLE.read_text(encoding="utf-8").splitlines()
SINK_LINE = next(i + 1 for i, ln in enumerate(_LINES)
                 if ln.strip().startswith("cursor.execute"))


class TestExtract(unittest.TestCase):
    def test_enclosing_function_is_sink_function(self):
        tree, _, _lang = extract.parse_file(SAMPLE)
        fn = extract.find_enclosing_function(tree.root_node, SINK_LINE)
        self.assertIsNotNone(fn)
        name = fn.child_by_field_name("name").text.decode()
        self.assertEqual(name, "get_user")

    def test_helpers_and_meta(self):
        with tempfile.TemporaryDirectory() as td:
            meta = extract.extract(SAMPLE, SINK_LINE, td)
            self.assertTrue(meta["ok"])
            self.assertEqual(meta["sink_function"], "get_user")
            names = [f["name"] for f in meta["functions"]]
            # 同文件辅助函数 open_db 被包含,sink 函数也在列
            self.assertIn("open_db", names)
            self.assertIn("get_user", names)
            # 属性调用(conn.cursor / cursor.execute)不算跨文件缺失
            self.assertFalse(meta["cross_file_missing"])
            self.assertEqual(meta["unresolved_calls"], [])
            snippet = (Path(td) / "snippet.py").read_text(encoding="utf-8")
            self.assertIn("def open_db", snippet)
            self.assertIn("def get_user", snippet)
            # 辅助函数在 sink 函数之前(open_db 定义行号更小)
            self.assertLess(snippet.index("def open_db"),
                            snippet.index("def get_user"))
            # 被引用的模块级常量一并提取(v1.1:修复 DB_PATH 缺失导致的 NameError)
            self.assertIn('DB_PATH = "app.db"', snippet)
            self.assertEqual(meta["module_constants"], ['DB_PATH = "app.db"'])

    def test_cross_file_call_marked_unresolved(self):
        src = "def caller():\n    helper_from_other_file()\n"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.py"
            p.write_text(src, encoding="utf-8")
            meta = extract.extract(p, 2, td)
            self.assertTrue(meta["ok"])
            self.assertTrue(meta["cross_file_missing"])
            self.assertIn("helper_from_other_file", meta["unresolved_calls"])

    def test_sink_outside_function_fails_cleanly(self):
        src = "X = 1\nY = X + 1\n"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.py"
            p.write_text(src, encoding="utf-8")
            meta = extract.extract(p, 2, td)
            self.assertFalse(meta["ok"])
            self.assertEqual(meta["error"], "sink_line_not_in_any_function")


if __name__ == "__main__":
    unittest.main()
