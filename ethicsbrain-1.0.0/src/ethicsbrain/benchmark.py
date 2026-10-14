"""Small, reproducible benchmark runner for the built-in EthicsBrain guardrails.

Usage: python -m ethicsbrain.benchmark --out-dir reports/benchmark
The included dataset is a smoke/regression suite, not a representative measure of
real-world safety. Extend it with reviewed domain-specific and adversarial cases.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .brain import GuardrailBrain
from .policy import Policy

_REPO_DATASET = Path(__file__).resolve().parents[2] / "benchmarks" / "safety_cases.jsonl"
DEFAULT_DATASET = _REPO_DATASET if _REPO_DATASET.exists() else Path(__file__).resolve().parent / "datasets" / "safety_cases.jsonl"


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on {path}:{line_number}: {exc}") from exc
            if not isinstance(item, dict) or "id" not in item or "expected_ok" not in item:
                raise ValueError(f"Each case in {path}:{line_number} needs id and expected_ok fields")
            if not isinstance(item["expected_ok"], bool):
                raise ValueError(f"expected_ok must be boolean in {path}:{line_number}")
            cases.append(item)
    if not cases:
        raise ValueError(f"No benchmark cases found in {path}")
    return cases


def run_safety_benchmark(dataset: str | Path = DEFAULT_DATASET) -> dict[str, Any]:
    cases = load_jsonl(dataset)
    results: list[dict[str, Any]] = []
    latencies_ms: list[float] = []
    by_tag: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for case in cases:
        policy_data = case.get("policy", {})
        policy = Policy(
            grounding_mode=policy_data.get("grounding_mode", "off"),
            block_prompt_injection=policy_data.get("block_prompt_injection", True),
            block_harmful_requests=policy_data.get("block_harmful_requests", True),
            block_secret_leaks=policy_data.get("block_secret_leaks", True),
            block_sensitive_identifiers=policy_data.get("block_sensitive_identifiers", True),
            max_prompt_chars=policy_data.get("max_prompt_chars", 20_000),
            max_output_chars=policy_data.get("max_output_chars", 12_000),
        )
        brain = GuardrailBrain(policy)

        def fixed_model(_request, output=str(case.get("model_output", ""))):
            return output

        started = time.perf_counter()
        result = brain.run(
            str(case.get("prompt", "")),
            fixed_model,
            context={str(k): str(v) for k, v in case.get("context", {}).items()},
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        latencies_ms.append(elapsed_ms)
        expected_ok = case["expected_ok"]
        passed = result.ok == expected_ok
        tags = case.get("tags", ["untagged"])
        if not isinstance(tags, list):
            tags = [str(tags)]
        row = {
            "id": case["id"],
            "tags": tags,
            "expected_ok": expected_ok,
            "actual_ok": result.ok,
            "passed": passed,
            "latency_ms": round(elapsed_ms, 3),
            "finding_ids": [finding.rule_id for finding in result.report.findings],
            "status": result.report.status,
        }
        results.append(row)
        for tag in tags:
            by_tag[str(tag)].append(row)

    expected_allow = [row for row in results if row["expected_ok"]]
    expected_block = [row for row in results if not row["expected_ok"]]
    true_allow = sum(row["expected_ok"] and row["actual_ok"] for row in results)
    false_block = sum(row["expected_ok"] and not row["actual_ok"] for row in results)
    true_block = sum((not row["expected_ok"]) and (not row["actual_ok"]) for row in results)
    false_accept = sum((not row["expected_ok"]) and row["actual_ok"] for row in results)

    def rate(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    metrics = {
        "total_cases": len(results),
        "passed_cases": sum(row["passed"] for row in results),
        "failed_cases": sum(not row["passed"] for row in results),
        "accuracy": rate(sum(row["passed"] for row in results), len(results)),
        "true_allow": int(true_allow),
        "false_block": int(false_block),
        "true_block": int(true_block),
        "false_accept": int(false_accept),
        "block_recall": rate(int(true_block), len(expected_block)),
        "false_block_rate": rate(int(false_block), len(expected_allow)),
        "false_accept_rate": rate(int(false_accept), len(expected_block)),
        "mean_latency_ms": round(statistics.mean(latencies_ms), 3) if latencies_ms else 0.0,
        "p95_latency_ms": round(_percentile(latencies_ms, 0.95), 3) if latencies_ms else 0.0,
    }
    tag_summary = {
        tag: {
            "total": len(rows),
            "passed": sum(row["passed"] for row in rows),
            "accuracy": rate(sum(row["passed"] for row in rows), len(rows)),
            "case_ids": [row["id"] for row in rows],
        }
        for tag, rows in sorted(by_tag.items())
    }
    return {
        "benchmark": "EthicsBrain built-in guardrails smoke/regression benchmark",
        "dataset": "benchmarks/safety_cases.jsonl" if Path(dataset).resolve() == Path(DEFAULT_DATASET).resolve() else str(dataset),
        "warning": "Small synthetic suite; scores are not a real-world safety guarantee or representative benchmark.",
        "metrics": metrics,
        "by_tag": tag_summary,
        "cases": results,
    }


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _markdown(report: dict[str, Any]) -> str:
    metrics = report["metrics"]
    lines = [
        "# EthicsBrain Safety Benchmark",
        "",
        f"> **Limitations:** {report['warning']}",
        "",
        f"Dataset: `{report['dataset']}`",
        "",
        "## Summary",
        "",
        "| Metric | Result |",
        "|---|---:|",
    ]
    for key, label in [
        ("total_cases", "Total cases"), ("passed_cases", "Passed"), ("failed_cases", "Failed"),
        ("accuracy", "Case accuracy"), ("true_block", "Correctly blocked"), ("false_accept", "False accepts"),
        ("false_block", "False blocks"), ("block_recall", "Block recall"),
        ("false_block_rate", "False-block rate"), ("false_accept_rate", "False-accept rate"),
        ("mean_latency_ms", "Mean local latency (ms)"), ("p95_latency_ms", "P95 local latency (ms)"),
    ]:
        lines.append(f"| {label} | {metrics[key]} |")
    lines += ["", "## By tag", "", "| Tag | Cases | Passed | Accuracy |", "|---|---:|---:|---:|"]
    for tag, stats in report["by_tag"].items():
        lines.append(f"| `{tag}` | {stats['total']} | {stats['passed']} | {stats['accuracy']} |")
    lines += ["", "## Case results", "", "| ID | Expected allow | Actual allow | Pass | Findings |", "|---|---:|---:|---:|---|"]
    for row in report["cases"]:
        findings = ", ".join(row["finding_ids"]) or "—"
        lines.append(f"| `{row['id']}` | {row['expected_ok']} | {row['actual_ok']} | {row['passed']} | {findings} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET, help="JSONL cases file")
    parser.add_argument("--out-dir", type=Path, default=Path("reports/benchmark"), help="Report output directory")
    args = parser.parse_args(argv)
    report = run_safety_benchmark(args.dataset)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "safety_benchmark.json"
    md_path = args.out_dir / "safety_benchmark.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(_markdown(report), encoding="utf-8")
    print(_markdown(report))
    print(f"\nWrote {json_path} and {md_path}")
    return 0 if report["metrics"]["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
