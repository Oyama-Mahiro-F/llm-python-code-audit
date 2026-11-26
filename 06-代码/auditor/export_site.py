# -*- coding: utf-8 -*-
"""导出静态站点数据(GitHub Pages 用)。

GitHub Pages 只能托管静态文件,无法运行 Python/Docker/tree-sitter/Semgrep。
因此静态版定位为两件事:
  ① **证据浏览**——把已落盘的运行结果(判定、五段证据链、源码、mock、日志、CVE)
     导出为 JSON,任何人可在线查看并复制复现命令;
  ② **自带 key 的候选发现**——浏览器直接调用 DeepSeek(已实测 CORS 允许),
     复刻 llm_discover 的提示词。**浏览器无法执行容器**,所以明确标注:
     这里只产生候选,判定必须由本地流水线的沙箱执行。

    python -m auditor.export_site --out ../docs/data

产出:docs/data/index.json(全部案例与证据)、docs/data/sources/<id>.json(源码)
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # 06-代码

CASES = [
    {
        "id": "case1_php_sqli",
        "title": "案例 1:PHP SQL 注入",
        "project": "demos/case1_php_sqli",
        "alerts": "records/demos/case1_php_sqli/llm_candidates.json",
        "run_id": "demo_case1_php_sqli",
        "channel": "LLM 候选发现通道",
        "note": "官方规则集 p/default、p/php、p/security-audit、p/owasp-top-ten 对本案均零命中,候选由 LLM 通道产出——只靠 SAST 会漏。",
        "cwe_scope": ["CWE-89", "CWE-78", "CWE-22", "CWE-79"],
    },
    {
        "id": "case2_php_cmd",
        "title": "案例 2:PHP 命令注入",
        "project": "demos/case2_php_cmd",
        "alerts": "records/demos/case2_php_cmd/sast_alerts.json",
        "run_id": "demo_case2_php_cmd",
        "channel": "SAST 规则扫描(p/default)",
        "note": "Semgrep 该规则 metadata 记为 CWE-94(代码注入),本项目按显式规则归一为 CWE-78(OS 命令注入),原始值保留在 cwe_reported。",
        "cwe_scope": ["CWE-89", "CWE-78", "CWE-22", "CWE-79"],
    },
    {
        "id": "case3_python_path",
        "title": "案例 3:Python 路径穿越",
        "project": "demos/case3_python_path",
        "alerts": "records/demos/case3_python_path/llm_candidates.json",
        "run_id": "demo_case3_python_path",
        "channel": "LLM 候选发现通道",
        "note": "官方规则集零命中;同时演示模块级常量 REPORT_DIR 被 Extract 一并提取(否则 harness 会 NameError)。",
        "cwe_scope": ["CWE-89", "CWE-78", "CWE-22", "CWE-79"],
    },
]


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _source_files(project_dir: Path) -> list[dict]:
    out = []
    for pat in ("*.php", "*.py"):
        for f in sorted(project_dir.glob(pat)):
            out.append({"path": f.name, "language": f.suffix.lstrip("."),
                        "code": _read(f) or ""})
    return out


def build_case(case: dict, root: Path) -> dict | None:
    report_path = (root / "records" / "demos" / case["id"] / "audit_report.json")
    if not report_path.exists():
        return None
    report = json.loads(report_path.read_text(encoding="utf-8"))
    run_base = root / "records" / "demos" / case["id"] / f"run_{case['run_id']}"

    findings = []
    for f in report.get("findings", []):
        nar = f.get("narrative") or {}
        ev = f.get("evidence") or {}
        run_dir = Path(ev.get("run_dir") or "")
        snippet_file = (f.get("extract") or {}).get("snippet_file") or "snippet.py"
        mock_file = (f.get("mock") or {}).get("mock_file") or "mock_patch.py"
        harness_file = (f.get("harness") or {}).get("harness_file") or "harness.py"
        findings.append({
            "alert_id": f.get("alert_id"),
            "cwe": f.get("cwe"),
            "title": nar.get("title"),
            "verdict": (f.get("verdict") or {}).get("verdict"),
            "verdict_mode": (f.get("verdict") or {}).get("mode"),
            "reason": (f.get("verdict") or {}).get("reason"),
            "narrative": nar,
            "source_alert": f.get("source_alert"),
            "extract": {k: (f.get("extract") or {}).get(k) for k in
                        ("language", "sink_function", "functions",
                         "module_constants", "unresolved_calls")},
            "mock": f.get("mock"),
            "harness": {k: (f.get("harness") or {}).get(k) for k in
                        ("harness_file", "redirects_applied", "harness_sha")},
            "run": f.get("run"),
            "files": {
                "snippet": _read(run_dir / snippet_file),
                "mock": _read(run_dir / mock_file),
                "harness": _read(run_dir / harness_file),
                "stdout": _read(run_dir / "stdout.txt"),
                "stderr": _read(run_dir / "stderr.txt"),
            },
            "replay_command": ev.get("replay_command"),
        })

    return {
        "id": case["id"],
        "title": case["title"],
        "channel": case["channel"],
        "note": case["note"],
        "cwe_scope": case["cwe_scope"],
        "summary": report.get("summary"),
        "sources": _source_files(root / case["project"]),
        "findings": findings,
    }


def export(out_dir: str | Path, root: str | Path | None = None) -> dict:
    root = Path(root) if root else ROOT
    out = Path(out_dir)
    (out / "sources").mkdir(parents=True, exist_ok=True)

    cve_lib = json.loads((root / "auditor" / "cve_refs.json")
                         .read_text(encoding="utf-8"))
    cases = [c for c in (build_case(case, root) for case in CASES) if c]

    doc = {
        "site": "可验证的大模型代码审计系统 · 证据浏览器",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "基于大语言模型的 Python 代码审计系统",
        "repo": "https://github.com/Oyama-Mahiro-F/llm-python-code-audit",
        "boundary": ("本静态站点用于浏览已落盘的运行证据(判定 + 五段证据链 + 源码 + mock + "
                     "运行日志 + CVE 参照)。真正的判定依赖 Docker 沙箱执行,无法在浏览器中完成;"
                     "「自带 Key 分析」只做候选发现,结果不等于判定结论。"),
        "cve_verified_at": cve_lib.get("verified_at"),
        "cve_refs": cve_lib.get("entries", []),
        "cases": cases,
    }
    (out / "index.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    for c in cases:
        (out / "sources" / f"{c['id']}.json").write_text(
            json.dumps({"id": c["id"], "sources": c["sources"]},
                       ensure_ascii=False, indent=1), encoding="utf-8")
    return {"cases": len(cases),
            "findings": sum(len(c["findings"]) for c in cases),
            "out": out.as_posix()}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="导出 GitHub Pages 静态数据")
    ap.add_argument("--out", default="../docs/data", help="输出目录")
    ap.add_argument("--root", default=None, help="06-代码 根目录")
    args = ap.parse_args(argv)
    info = export(args.out, args.root)
    print(f"[export_site] {info['cases']} 案例 / {info['findings']} 条 finding "
          f"-> {info['out']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
