# -*- coding: utf-8 -*-
"""数据集清单构建(任务书 S2:dataset_manifest.json)。

对任意候选目录生成符合任务书 3.2 S2 口径的清单:项目名、语言、代码规模、
CWE 类型、来源、许可证、真值标注方式、过滤规则与过滤前后样本数。

    python -m auditor.dataset build-manifest --dir samples \\
        --name demo-samples --language python \\
        --source "self-built" --license "MIT(自建)" \\
        --gt "作者即标注者(样本级)" --out records/dataset_manifest.json

SARD Python 子集 / Vul4Py 的下载器待数据集决策(见
05-实验步骤/数据集选型决策)落地后补充;本模块先统一清单口径。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import tree_sitter_python as tspython
from tree_sitter import Language, Parser

PY_LANGUAGE = Language(tspython.language())


def _functions_count(src: bytes) -> int:
    tree = Parser(PY_LANGUAGE).parse(src)
    return sum(1 for n in _walk(tree.root_node) if n.type == "function_definition")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def build_manifest(directory: str | Path, *, name: str, language: str,
                   source: str, license_name: str, gt_mode: str,
                   cwe: str | None = None, out_path: str | Path,
                   patterns: list[str] | None = None) -> dict:
    directory = Path(directory)
    patterns = patterns or ["*.py"]
    files = []
    for pat in patterns:
        files.extend(sorted(directory.rglob(pat)))
    files = [f for f in files if ".venv" not in f.parts]

    entries = []
    for f in files:
        try:
            src = f.read_bytes()
            loc = src.decode("utf-8", errors="replace").count("\n") + 1
            n_funcs = _functions_count(src)
        except OSError as exc:
            entries.append({"file": f.name, "error": str(exc)})
            continue
        entries.append({
            "file": f.name,
            "language": language,
            "lines": loc,
            "functions": n_funcs,
            "cwe_label": cwe if cwe else "见文件名(vuln_cweXX 命名约定)",
        })

    manifest = {
        "dataset": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "license": license_name,
        "ground_truth_mode": gt_mode,
        "sampling": "固定随机种子(接入真实数据集后启用;演示样本为全集)",
        "filter_rules": "无(自建样本全量;真实数据集接入时记录过滤规则与前后样本数)",
        "n_files": len(entries),
        "files": entries,
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="数据集清单构建(S2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build-manifest")
    p.add_argument("--dir", required=True, help="数据集目录")
    p.add_argument("--name", required=True)
    p.add_argument("--language", default="python")
    p.add_argument("--source", required=True, help="数据来源")
    p.add_argument("--license", required=True, help="许可证")
    p.add_argument("--gt", required=True, help="真值标注方式")
    p.add_argument("--cwe", help="统一 CWE 标注(可选)")
    p.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    m = build_manifest(args.dir, name=args.name, language=args.language,
                       source=args.source, license_name=args.license,
                       gt_mode=args.gt, cwe=args.cwe, out_path=args.out)
    print(f"[dataset] {m['dataset']}: {m['n_files']} files -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
