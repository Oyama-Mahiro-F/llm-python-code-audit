# -*- coding: utf-8 -*-
"""Extract 代码提取工具(自研,对应《项目方案》4.3.1)。

基于 tree-sitter 做 AST 解析,封装为独立可执行入口:
    python -m auditor.extract --file <目标文件> --line <sink 行号> --out <输出目录>

输入:目标文件路径、sink 函数位置(行号);
输出:sink 函数及同文件内被直接调用的辅助函数源码片段(snippet.py),
      及提取元数据(extract_meta.json,含提取范围、包含函数清单、
      跨文件未解析调用、提取失败原因)。

已知局限(方案 4.5):仅提取同文件函数,丢失跨文件全局状态与净化逻辑;
无法在文件内解析的调用名记入 unresolved_calls,供"未确认"归因使用。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())

# 仅用于过滤常见内建名,避免把内建调用当作跨文件缺失
_BUILTINS = {
    "print", "len", "str", "int", "float", "bool", "dict", "list", "set",
    "tuple", "range", "enumerate", "open", "super", "isinstance", "getattr",
    "setattr", "hasattr", "type", "repr", "sorted", "min", "max", "sum",
    "abs", "map", "filter", "zip", "format", "bytes", "bytearray", "id",
    "hash", "iter", "next", "callable", "vars", "dir", "ord", "chr",
}


def _make_parser() -> Parser:
    return Parser(PY_LANGUAGE)


def parse_file(path: str | Path):
    """解析源文件,返回 (tree, source_bytes)。语法错误不中断(树上标记 ERROR)。"""
    src = Path(path).read_bytes()
    tree = _make_parser().parse(src)
    return tree, src


def _text(node, src: bytes) -> str:
    return node.text.decode("utf-8", errors="replace")


def find_enclosing_function(root, line: int):
    """返回包含该行(1-based)的最小 function_definition 节点;找不到返回 None。"""
    best = None
    for node in _walk(root):
        if node.type == "function_definition":
            start = node.start_point[0] + 1
            end = node.end_point[0] + 1
            if start <= line <= end:
                if best is None or (end - start) < (best.end_point[0] - best.start_point[0]):
                    best = node
    return best


def _walk(node):
    """先序遍历 AST。"""
    yield node
    for child in node.children:
        yield from _walk(child)


def collect_direct_calls(fn_node):
    """收集函数体内以标识符直接调用的函数名(保序去重)。

    仅统计 `name(...)` 形式;`obj.method(...)` 属属性调用,不在此列
    (方案口径:sink 函数 + 同文件内被直接调用的辅助函数)。
    """
    names: list[str] = []
    seen = set()
    for node in _walk(fn_node):
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None and fn.type == "identifier":
                name = fn.text.decode()
                if name not in seen:
                    seen.add(name)
                    names.append(name)
    return names


def find_function_defs(root) -> dict[str, object]:
    """文件内全部函数定义,按名字索引(同名取先出现者)。"""
    defs: dict[str, object] = {}
    for node in _walk(root):
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                name = name_node.text.decode()
                defs.setdefault(name, node)
    return defs


def _referenced_names(nodes) -> set[str]:
    """收集若干 AST 节点中引用的全部标识符名。"""
    names: set[str] = set()
    for node in nodes:
        for n in _walk(node):
            if n.type == "identifier":
                names.add(n.text.decode())
    return names


def collect_module_constants(root, fn_nodes) -> list[object]:
    """收集被提取函数引用的模块级常量赋值(NAME = 字面量/表达式)。

    背景:仅提取函数时,函数引用的模块级常量(如 DB_PATH = "app.db")
    会缺失,导致 harness 运行 NameError——实测发现后补充此规则。
    """
    refs = _referenced_names(fn_nodes)
    consts = []
    for node in root.children:
        if node.type != "expression_statement":
            continue
        for stmt in node.children:
            if stmt.type != "assignment":
                continue
            # tree-sitter-python 0.25+ 将左值字段命名为 left(旧版为 targets)
            left = stmt.child_by_field_name("left") or stmt.child_by_field_name("targets")
            if left is None:
                continue
            if left.type == "identifier":
                names = [left.text.decode()]
            else:
                names = [t.text.decode() for t in left.children
                         if t.type == "identifier"]
            if names and names[0] in refs:
                consts.append(node)
                break
    return consts


def extract(path: str | Path, sink_line: int, out_dir: str | Path) -> dict:
    """执行提取,落盘 snippet.py 与 extract_meta.json,返回元数据 dict。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        tree, src = parse_file(path)
    except (OSError, UnicodeDecodeError) as exc:
        meta = {"ok": False, "error": f"parse_failed: {exc}",
                "file": str(path), "sink_line": sink_line}
        (out / "extract_meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta

    root = tree.root_node
    sink_fn = find_enclosing_function(root, sink_line)
    if sink_fn is None:
        meta = {"ok": False, "error": "sink_line_not_in_any_function",
                "file": str(path), "sink_line": sink_line}
        (out / "extract_meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta

    defs = find_function_defs(root)
    sink_name = _text(sink_fn.child_by_field_name("name"), src)
    called = collect_direct_calls(sink_fn)

    helpers, unresolved = [], []
    for name in called:
        if name == sink_name:
            continue
        node = defs.get(name)
        if node is not None and node.id != sink_fn.id:
            helpers.append(node)
        elif name not in _BUILTINS:
            unresolved.append(name)

    included = sorted(helpers + [sink_fn], key=lambda n: n.start_point[0])
    constants = collect_module_constants(root, included)

    parts = ([_text(n, src) for n in constants]
             + [_text(n, src) for n in included])
    snippet = "\n\n".join(parts) + "\n"
    (out / "snippet.py").write_text(snippet, encoding="utf-8")

    meta = {
        "ok": True,
        "file": str(path),
        "sink_line": sink_line,
        "sink_function": sink_name,
        "module_constants": [
            _text(c, src).strip().splitlines()[0] for c in constants
        ],
        "functions": [
            {
                "name": _text(n.child_by_field_name("name"), src),
                "start_line": n.start_point[0] + 1,
                "end_line": n.end_point[0] + 1,
                "is_sink": n.id == sink_fn.id,
            }
            for n in included
        ],
        "direct_calls": called,
        "unresolved_calls": unresolved,
        "cross_file_missing": bool(unresolved),
        "snippet_path": str((out / "snippet.py").as_posix()),
    }
    (out / "extract_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Extract:sink 函数与同文件辅助函数提取")
    ap.add_argument("--file", required=True, help="目标源文件路径")
    ap.add_argument("--line", required=True, type=int, help="sink 所在行号(1-based)")
    ap.add_argument("--out", required=True, help="输出目录")
    args = ap.parse_args(argv)
    meta = extract(args.file, args.line, args.out)
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0 if meta.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
