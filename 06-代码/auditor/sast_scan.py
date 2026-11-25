# -*- coding: utf-8 -*-
"""SAST 扫描封装(对应《项目方案》4.1)。

Semgrep 以官方规则集默认配置扫描(不针对评测基准手工调优)。
Windows 宿主机不走 native 后端(semgrep 官方不支持 Windows 原生运行),
默认经由 semgrep/semgrep 官方容器执行——纯进程调用,不接触源码。

输出:records/sast_alerts.json
{
  "tool": "semgrep", "version": ..., "config": ...,
  "backend": "docker|native",
  "generated_at": ...,
  "alerts": [{"alert_id", "check_id", "path", "line", "col", "end_line",
              "cwe", "message", "metavars"}]
}
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SEMGREP_IMAGE = "semgrep/semgrep:latest"
SEMGREP_TIMEOUT_S = 900

# CWE 归一化(显式、可审计):Semgrep 部分规则把"OS 命令注入"标为 CWE-94
# (代码注入,父类),但 shell 命令拼接的准确分类是 CWE-78。
# 仅当 消息含 "command injection" 且 上报 CWE 为 CWE-94 时归一,
# 原始值保留在 cwe_reported 字段,并在 cwe_normalization 中记录依据。
CWE_NORMALIZE_RULES = [
    {"from": "CWE-94", "to": "CWE-78", "when_message_contains": "command injection",
     "reason": "Semgrep 规则 metadata 记为 CWE-94(代码注入),shell 命令拼接的准确分类为 CWE-78(OS 命令注入)"},
]


def _normalize_cwe(cwe: str | None, message: str | None) -> tuple[str | None, dict | None]:
    msg = (message or "").lower()
    for rule in CWE_NORMALIZE_RULES:
        if cwe == rule["from"] and rule["when_message_contains"] in msg:
            return rule["to"], rule
    return cwe, None


def _cwe_of(extra: dict) -> str | None:
    meta = extra.get("metadata") or {}
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if not cwe:
        return None
    m = re.search(r"CWE-\d+", str(cwe))
    return m.group(0) if m else None


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def scan(project_dir: str | Path, out_path: str | Path,
         config: str = "p/python", backend: str = "docker") -> dict:
    project_dir = Path(project_dir).resolve()
    out_path = Path(out_path)
    if backend == "docker":
        cmd = ["docker", "run", "--rm",
               "-v", f"{project_dir}:/src",
               "-e", "SEMGREP_SEND_METRICS=off",
               SEMGREP_IMAGE,
               "semgrep", "scan", "--json", "--config", config, "/src"]
    elif backend == "native":
        cmd = [sys.executable, "-m", "semgrep", "scan", "--json",
               "--config", config, str(project_dir)]
    else:
        raise ValueError(f"unknown backend: {backend}")

    proc = _run(cmd, SEMGREP_TIMEOUT_S)
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raw = None

    if raw is None:
        result = {
            "tool": "semgrep", "config": config, "backend": backend,
            "ok": False,
            "error": (proc.stderr or proc.stdout or "")[-2000:],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alerts": [],
        }
    else:
        alerts = []
        for i, r in enumerate(raw.get("results", []), start=1):
            start, end = r.get("start", {}), r.get("end", {})
            alerts.append({
                "alert_id": f"A-{i:03d}",
                "check_id": r.get("check_id"),
                "path": r.get("path"),
                "line": start.get("line"),
                "col": start.get("col"),
                "end_line": end.get("line"),
                "cwe": _cwe_of(r.get("extra", {})),
                "message": (r.get("extra", {}) or {}).get("message"),
                "metavars": (r.get("extra", {}) or {}).get("metavars"),
            })
        result = {
            "tool": "semgrep",
            "version": raw.get("version"),
            "config": config,
            "backend": backend,
            "ok": True,
            "errors_from_tool": raw.get("errors", []),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alerts": alerts,
        }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return result


def normalize(raw_path: str | Path, out_path: str | Path,
              config: str = "p/python") -> dict:
    """两阶段模式:解析 shell 侧已捕获的 semgrep 原始 JSON 并归一化落盘。"""
    raw = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    alerts = []
    for i, r in enumerate(raw.get("results", []), start=1):
        start, end = r.get("start", {}), r.get("end", {})
        cwe_reported = _cwe_of(r.get("extra", {}))
        message = (r.get("extra", {}) or {}).get("message")
        cwe, rule_hit = _normalize_cwe(cwe_reported, message)
        entry = {
            "alert_id": f"A-{i:03d}",
            "check_id": r.get("check_id"),
            "path": r.get("path"),
            "line": start.get("line"),
            "col": start.get("col"),
            "end_line": end.get("line"),
            "cwe": cwe,
            "message": message,
            "metavars": (r.get("extra", {}) or {}).get("metavars"),
        }
        if rule_hit is not None:
            entry["cwe_reported"] = cwe_reported
            entry["cwe_normalization"] = rule_hit
        alerts.append(entry)
    result = {
        "tool": "semgrep",
        "version": raw.get("version"),
        "config": config,
        "backend": "docker(external)",
        "ok": True,
        "errors_from_tool": raw.get("errors", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alerts": alerts,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SAST 扫描封装(Semgrep)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="直接扫描(标准环境)")
    p_scan.add_argument("--project", required=True)
    p_scan.add_argument("--out", required=True)
    p_scan.add_argument("--config", default="p/python")
    p_scan.add_argument("--backend", default="docker",
                        choices=["docker", "native"])

    p_norm = sub.add_parser("normalize", help="两阶段模式:归一化 shell 捕获的原始 JSON")
    p_norm.add_argument("--raw", required=True, help="semgrep --json 原始输出文件")
    p_norm.add_argument("--out", required=True)
    p_norm.add_argument("--config", default="p/python")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        result = scan(args.project, args.out, args.config, args.backend)
    else:
        result = normalize(args.raw, args.out, args.config)
    ok = "ok" if result.get("ok") else "FAILED"
    print(f"[sast_scan] {ok}: {len(result['alerts'])} alerts -> "
          f"{args.out}")
    if not result.get("ok"):
        print(result.get("error", ""))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
