"""Evaluate a semantic evidence verifier against a labeled JSONL dataset.

Usage (downloads/cache model weights on first run if not already present):
  python -m ethicsbrain.verification_benchmark --out-dir reports/verification
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .nli import TransformersNliEvaluator
from .verification import verify_response

_REPO_DATASET = Path(__file__).resolve().parents[2] / "benchmarks" / "verification_cases.jsonl"
DEFAULT_DATASET = _REPO_DATASET if _REPO_DATASET.exists() else Path(__file__).resolve().parent / "datasets" / "verification_cases.jsonl"


def _load_verification_jsonl(path: str | Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on {path}:{line_number}: {exc}") from exc
            required = {"id", "response", "evidence", "expected_status"}
            missing = required - set(case) if isinstance(case, dict) else required
            if missing:
                raise ValueError(f"Missing required verification fields on {path}:{line_number}: {sorted(missing)}")
            cases.append(case)
    if not cases:
        raise ValueError(f"No verification benchmark cases found in {path}")
    return cases


def run_verification_benchmark(dataset: str | Path, evaluator: Any) -> dict[str, Any]:
    cases = _load_verification_jsonl(dataset)
    rows: list[dict[str, Any]] = []
    by_expected: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        report = verify_response(
            str(case["response"]),
            {str(k): str(v) for k, v in case["evidence"].items()},
            evaluator,
            minimum_confidence=float(case.get("minimum_confidence", 0.75)),
        )
        expected = str(case["expected_status"])
        predicted = report.claims[0].status if len(report.claims) == 1 else report.status
        passed = predicted == expected
        row = {
            "id": case["id"],
            "expected_status": expected,
            "predicted_status": predicted,
            "confidence": report.claims[0].confidence if report.claims else None,
            "passed": passed,
            "explanation": report.claims[0].explanation if report.claims else "No claim verdict returned.",
        }
        rows.append(row)
        by_expected[expected].append(row)

    total = len(rows)
    correct = sum(row["passed"] for row in rows)
    labels = sorted({row["expected_status"] for row in rows} | {row["predicted_status"] for row in rows})
    matrix = {
        actual: {predicted: sum(row["expected_status"] == actual and row["predicted_status"] == predicted for row in rows) for predicted in labels}
        for actual in labels
    }
    return {
        "benchmark": "EthicsBrain semantic evidence-verification benchmark",
        "dataset": "benchmarks/verification_cases.jsonl" if Path(dataset).resolve() == Path(DEFAULT_DATASET).resolve() else str(dataset),
        "evaluator": evaluator.__class__.__name__,
        "warning": "Synthetic starter set. NLI scores are not calibrated probabilities; results do not prove general factual reliability.",
        "metrics": {"total_cases": total, "correct_cases": correct, "failed_cases": total - correct, "accuracy": round(correct / total, 4) if total else None},
        "confusion_matrix_rows_actual_columns_predicted": matrix,
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out-dir", type=Path, default=Path("reports/verification"))
    parser.add_argument("--nli-model", default="cross-encoder/nli-deberta-v3-small")
    parser.add_argument("--device", type=int, default=-1, help="-1 for CPU; 0 for first supported GPU")
    args = parser.parse_args(argv)
    evaluator = TransformersNliEvaluator(args.nli_model, device=args.device)
    report = run_verification_benchmark(args.dataset, evaluator)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "verification_benchmark.json"
    md_path = args.out_dir / "verification_benchmark.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    metrics = report["metrics"]
    lines = [
        "# EthicsBrain Semantic Verification Benchmark", "",
        f"> **Limitations:** {report['warning']}", "",
        f"Evaluator: `{report['evaluator']}`", "",
        f"- Total cases: {metrics['total_cases']}", f"- Correct: {metrics['correct_cases']}",
        f"- Failed: {metrics['failed_cases']}", f"- Accuracy: {metrics['accuracy']}", "",
        "## Confusion matrix (rows = actual, columns = predicted)", "",
        "| Actual \\ Predicted | " + " | ".join(report["confusion_matrix_rows_actual_columns_predicted"].keys()) + " |",
        "|---|" + "---:|" * len(report["confusion_matrix_rows_actual_columns_predicted"]),
    ]
    labels = list(report["confusion_matrix_rows_actual_columns_predicted"].keys())
    for actual, row in report["confusion_matrix_rows_actual_columns_predicted"].items():
        lines.append("| " + actual + " | " + " | ".join(str(row[label]) for label in labels) + " |")
    lines += ["", "## Individual cases", "", "| ID | Expected | Predicted | Confidence | Pass |", "|---|---|---|---:|---:|"]
    for row in report["cases"]:
        lines.append(f"| `{row['id']}` | {row['expected_status']} | {row['predicted_status']} | {row['confidence']} | {row['passed']} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {json_path} and {md_path}")
    return 0 if metrics["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
