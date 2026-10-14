"""Evaluate retrieval ranking on a labeled JSON corpus/query set.

Usage: python -m ethicsbrain.retrieval_benchmark --out-dir reports/retrieval
The included dataset is synthetic and only tests a small set of expected source rankings.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from .provenance import EvidenceStore

_REPO_DATASET = Path(__file__).resolve().parents[2] / "benchmarks" / "retrieval_cases.json"
DEFAULT_DATASET = _REPO_DATASET if _REPO_DATASET.exists() else Path(__file__).resolve().parent / "datasets" / "retrieval_cases.json"


def run_retrieval_benchmark(dataset: str | Path = DEFAULT_DATASET) -> dict[str, Any]:
    payload = json.loads(Path(dataset).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("documents"), list) or not isinstance(payload.get("queries"), list):
        raise ValueError("Retrieval dataset needs documents and queries arrays")
    if not payload["documents"] or not payload["queries"]:
        raise ValueError("Retrieval benchmark needs at least one document and one query")
    top_k = int(payload.get("top_k", 3))
    if top_k < 1:
        raise ValueError("top_k must be at least 1")
    with tempfile.TemporaryDirectory(prefix="ethicsbrain-retrieval-") as temp:
        store = EvidenceStore(Path(temp) / "evidence.json")
        for doc in payload["documents"]:
            store.add_document(
                source_id=str(doc["source_id"]), title=str(doc["title"]), text=str(doc["text"]),
                uri=str(doc.get("uri", "")), publisher=str(doc.get("publisher", "")),
                published_at=doc.get("published_at"), chunk_size=2000, overlap=0,
            )
        rows: list[dict[str, Any]] = []
        for query in payload["queries"]:
            expected = list(dict.fromkeys(str(item) for item in query["expected_source_ids"]))
            hits = store.search(str(query["query"]), top_k=top_k)
            ranked_sources: list[str] = []
            for hit in hits:
                if hit.chunk.source_id not in ranked_sources:
                    ranked_sources.append(hit.chunk.source_id)
            relevant_found = [source for source in ranked_sources if source in expected]
            first_rank = next((idx + 1 for idx, source in enumerate(ranked_sources) if source in expected), None)
            recall = len(set(relevant_found)) / len(expected) if expected else 1.0
            precision = len(relevant_found) / top_k
            rows.append({
                "id": str(query["id"]),
                "query": str(query["query"]),
                "expected_source_ids": expected,
                "retrieved_source_ids": ranked_sources,
                "hit_at_k": bool(relevant_found),
                "recall_at_k": round(recall, 4),
                "precision_at_k": round(precision, 4),
                "reciprocal_rank": round(1.0 / first_rank, 4) if first_rank else 0.0,
            })
    total = len(rows)
    metrics = {
        "queries": total,
        "top_k": top_k,
        "hit_rate_at_k": round(sum(row["hit_at_k"] for row in rows) / total, 4),
        "mean_recall_at_k": round(sum(row["recall_at_k"] for row in rows) / total, 4),
        "mean_precision_at_k": round(sum(row["precision_at_k"] for row in rows) / total, 4),
        "mean_reciprocal_rank": round(sum(row["reciprocal_rank"] for row in rows) / total, 4),
    }
    return {
        "benchmark": "EthicsBrain retrieval provenance/ranking benchmark",
        "dataset": Path(dataset).name,
        "warning": payload.get("warning", "Synthetic test set; expand with reviewed domain-specific queries."),
        "retrieval_method": "BM25-style lexical ranking",
        "metrics": metrics,
        "queries": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out-dir", type=Path, default=Path("reports/retrieval"))
    args = parser.parse_args(argv)
    report = run_retrieval_benchmark(args.dataset)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.out_dir / "retrieval_benchmark.json"
    md_path = args.out_dir / "retrieval_benchmark.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    metrics = report["metrics"]
    lines = [
        "# EthicsBrain Retrieval Benchmark", "",
        f"> **Limitation:** {report['warning']}", "",
        f"Method: `{report['retrieval_method']}`", "",
        f"- Queries: {metrics['queries']}", f"- Top-k: {metrics['top_k']}",
        f"- Hit rate@k: {metrics['hit_rate_at_k']}", f"- Mean recall@k: {metrics['mean_recall_at_k']}",
        f"- Mean precision@k: {metrics['mean_precision_at_k']}",
        f"- Mean reciprocal rank: {metrics['mean_reciprocal_rank']}", "",
        "## Queries", "", "| Query ID | Hit@k | Recall@k | Precision@k | Reciprocal rank | Retrieved sources |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for row in report["queries"]:
        lines.append(f"| `{row['id']}` | {row['hit_at_k']} | {row['recall_at_k']} | {row['precision_at_k']} | {row['reciprocal_rank']} | {', '.join(row['retrieved_source_ids'])} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote {json_path} and {md_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
