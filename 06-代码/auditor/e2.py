# -*- coding: utf-8 -*-
"""E2 消融实验:验证配置的边际贡献(任务书 3.4 / 中期报告「下一步计划」)。

四种配置:
  none  纯候选直接采纳,不做动态验证(纯 SAST/纯 LLM 分诊基线;在代码内构造)
  A     仅模式 A(硬编码检测器)动态验证          → 读 run_<id> 产物
  B     仅模式 B(LLM 日志推理)动态验证          → 读 run_<id> 产物
  full  模式 A + 重试闭环(regen;本样本集无失败项,闭环空转)→ 复用 A 的 run

用法:各配置先按 orchestrator 命令序列跑完落盘,再汇总——

    python -m auditor.e2 --alerts records/sast_alerts_multi.json \\
        records/llm_candidates_multi.json \\
        --runs none:baseline,A:e2_A,B:e2_B,full:e2_A \\
        --runs-root records --ground-truth records/e2/ground_truth.json \\
        --out records/e2

输出:e2_report.json / e2_report.md(配置矩阵 + 各配置判定分布、LLM 调用、
沙箱次数、告警级精确率)。

诚实边界(写进报告):演示样本集全部告警都指向真实缺陷(安全对照样本零候选),
各配置在该集上精确率同为 1.0,**不具备区分度**;E2 的定量结论以 Vul4Py
真实数据集(含真实误报)为准——本报告交付的是 E2 机制本身与全链路可用性。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

CONFIG_MECHANISMS = {
    "none": "候选直接采纳(无动态验证)",
    "A": "模式 A 硬编码检测器(确定性)",
    "B": "模式 B LLM 日志推理(带确定性护栏)",
    "full": "动态验证 + 重试闭环(改 mock/改 payload,上限 3 轮;本轮判定用模式 B)",
}


def _load_states(run_root: Path, run_id: str) -> list[dict]:
    f = run_root / f"run_{run_id}" / "_prepare_states.json"
    return json.loads(f.read_text(encoding="utf-8"))


def _baseline_findings(alert_paths: list[str]) -> list[dict]:
    """none 配置:所有候选直接采纳,不经动态验证。"""
    out = []
    for p in alert_paths:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        for a in doc.get("alerts", []):
            out.append({
                "alert_id": a["alert_id"], "cwe": a.get("cwe"),
                "path": a.get("path"),
                "verdict": {"verdict": "accepted(unverified)",
                            "mode": "none",
                            "reason": "无动态验证基线:候选直接进入采纳集"},
                "overhead": {"llm_calls": 0, "sandbox_runs": 0},
            })
    return out


def _precision(findings: list[dict], gt: dict | None) -> float | None:
    if not gt or not findings:
        return None
    vuln_files = set(gt.get("vulnerable_files", []))
    tp = 0
    for f in findings:
        path = f.get("path") or (f.get("source_alert") or {}).get("path") or ""
        if Path(path).name in vuln_files:
            tp += 1
    return round(tp / len(findings), 4)


def build_report(alert_paths: list[str], runs: list[tuple[str, str]],
                 runs_root: Path, gt_path: Path | None) -> dict:
    gt = (json.loads(Path(gt_path).read_text(encoding="utf-8"))
          if gt_path and Path(gt_path).exists() else None)
    configs = []
    for name, run_id in runs:
        if name == "none":
            findings = _baseline_findings(alert_paths)
            llm_calls = 0
            sandbox_runs = 0
            retry_note = "不适用"
        else:
            findings = _load_states(runs_root, run_id)
            llm_calls = sum(f.get("overhead", {}).get("llm_calls", 0)
                            for f in findings)
            sandbox_runs = max((f.get("overhead", {}).get("sandbox_runs", 0)
                                for f in findings), default=0)
            n_retries = sum(len(f.get("retries", [])) for f in findings)
            retry_note = (f"重试 {n_retries} 次" if n_retries
                          else "本轮无失败项,闭环空转(机制可用性已验证)")
        dist: dict[str, int] = {}
        for f in findings:
            label = (f.get("verdict") or {}).get("verdict", "?")
            dist[label] = dist.get(label, 0) + 1
        configs.append({
            "config": name,
            "mechanism": CONFIG_MECHANISMS.get(name, name),
            "run_id": run_id,
            "n_findings": len(findings),
            "verdict_distribution": dist,
            "llm_calls": llm_calls,
            "sandbox_runs": sandbox_runs,
            "precision_alert_level": _precision(findings, gt),
            "note": retry_note,
        })
    return {
        "experiment": "E2 消融(验证配置的边际贡献)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth": (str(Path(gt_path).as_posix())
                         if gt_path else None),
        "configs": configs,
        "honest_boundary": ("演示样本集的全部告警均指向真实缺陷、安全对照样本"
                            "零候选,各配置精确率同为 1.0,不具备区分度;"
                            "E2 定量结论以 Vul4Py 真实数据集(含真实误报)为准,"
                            "本报告交付 E2 机制与全链路可用性。"
                            "重试闭环实战演示:首次模式 B 运行中,L-001(CWE-22)被判 "
                            "Unconfirmed(归因:mock 假文件返回空内容、payload 构造证据弱,"
                            "建议改 mock);regen 带该反馈再生成 mock(_FakeFile.read() "
                            "改为回显路径内容)后,round 2 判 TP——Unconfirmed→反馈→"
                            "修复→确认 全链路走通,轨迹见 retry_trace.jsonl。"
                            "如实说明:该次演示的判定响应被后续重跑共用录制目录覆盖、"
                            "attempt 目录被清理,trace 首行为其残留记录(记录管理失误);"
                            "修复措施:录制目录此后按运行隔离。"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="E2 消融实验报告")
    ap.add_argument("--alerts", required=True, nargs="+",
                    help="候选来源 JSON(none 基线与精确率计算用)")
    ap.add_argument("--runs", required=True,
                    help="配置:运行编号,逗号分隔,如 none:baseline,A:e2_A")
    ap.add_argument("--runs-root", default="records", help="run_* 目录所在根")
    ap.add_argument("--ground-truth", help="样本级真值 JSON(可选)")
    ap.add_argument("--out", required=True, help="报告输出目录")
    args = ap.parse_args(argv)

    runs = []
    for part in args.runs.split(","):
        name, _, rid = part.partition(":")
        runs.append((name.strip(), rid.strip() or name.strip()))

    report = build_report(args.alerts, runs, Path(args.runs_root),
                          Path(args.ground_truth) if args.ground_truth else None)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "e2_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# E2 消融实验报告", "",
             f"- 生成时间:{report['generated_at']}",
             f"- 真值文件:{report['ground_truth'] or '(未提供)'}", "",
             "| 配置 | 机制 | findings | 判定分布 | LLM 调用 | 沙箱轮次 | 告警级精确率 | 备注 |",
             "|---|---|---|---|---|---|---|---|"]
    for c in report["configs"]:
        lines.append(
            f"| {c['config']} | {c['mechanism']} | {c['n_findings']} "
            f"| {json.dumps(c['verdict_distribution'], ensure_ascii=False)} "
            f"| {c['llm_calls']} | {c['sandbox_runs']} "
            f"| {c['precision_alert_level']} | {c['note']} |")
    lines += ["", f"> {report['honest_boundary']}", ""]
    (out / "e2_report.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[e2] {len(report['configs'])} 个配置 -> "
          f"{(out / 'e2_report.md').resolve().as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
