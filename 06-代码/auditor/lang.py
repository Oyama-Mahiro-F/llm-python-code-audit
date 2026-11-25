# -*- coding: utf-8 -*-
"""多语言支持层:按文件后缀选择 tree-sitter 语法与语言相关口径。

当前支持:
  .py  → tree-sitter-python(0.25+)
  .php → tree-sitter-php(0.25+)

语言差异只在三处:函数节点/调用节点/内建名集合(见 extract.py),
其余流水线(沙箱、判定、报告)与语言无关。
"""
from __future__ import annotations

from pathlib import Path

PY_EXT = {".py"}
PHP_EXT = {".php", ".phtml"}

# 各语言的运行时镜像与执行器(沙箱层使用)
RUNTIME = {
    "python": {"image": "python:3.12-slim", "run": ["python", "harness.py"],
               "filename": "harness.py"},
    "php": {"image": "php:8.2-cli", "run": ["php", "harness.php"],
            "filename": "harness.php"},
}

_CACHE: dict[str, object] = {}


def detect(path: str | Path) -> str:
    """按后缀判定语言;未知后缀抛 ValueError(由调用方按失败处理)。"""
    suffix = Path(path).suffix.lower()
    if suffix in PY_EXT:
        return "python"
    if suffix in PHP_EXT:
        return "php"
    raise ValueError(f"unsupported_language_suffix:{suffix}")


def language_of(path: str | Path):
    """返回 tree-sitter Language 对象(带缓存)。"""
    lang = detect(path)
    if lang in _CACHE:
        return _CACHE[lang]
    if lang == "python":
        import tree_sitter_python as ts
        from tree_sitter import Language
        obj = Language(ts.language())
    elif lang == "php":
        import tree_sitter_php as ts
        from tree_sitter import Language
        obj = Language(ts.language_php())
    else:  # pragma: no cover
        raise ValueError(lang)
    _CACHE[lang] = obj
    return obj


def runtime_of(path: str | Path) -> dict:
    return RUNTIME[detect(path)]
