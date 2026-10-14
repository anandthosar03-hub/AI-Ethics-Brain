"""Minimal local evidence ingestion, retrieval, and cited-answer verification example."""
from __future__ import annotations

from ethicsbrain.provenance import EvidenceStore
from ethicsbrain.verification import verify_response


class DemoEvaluator:
    """Deterministic demo evaluator only; replace with a tested semantic evaluator."""
    def evaluate(self, claim, evidence):
        from ethicsbrain.verification import EvidenceEvaluation
        claim_words = set(claim.lower().split())
        evidence_words = set(" ".join(evidence.values()).lower().split())
        overlap = len(claim_words & evidence_words) / max(1, len(claim_words))
        if overlap >= 0.45:
            return EvidenceEvaluation("supported", min(0.99, overlap), "Demo lexical overlap only; not real semantic verification.")
        return EvidenceEvaluation("insufficient_evidence", overlap, "Demo evaluator could not establish support.")


def main() -> None:
    store = EvidenceStore("data/evidence_store.json")
    if not store.all_chunks():
        store.add_document(
            source_id="example-ai-tool-policy",
            title="Example AI tool authorization policy",
            publisher="EthicsBrain local demo",
            uri="https://example.org/ai-tool-policy",
            published_at="2026-01-01",
            text=(
                "AI-generated text must not grant permissions by itself. "
                "Sensitive tool actions should be checked by an independent authorization layer. "
                "Use explicit allowlists, validate arguments, enforce least privilege, and require human approval for high-impact actions. "
                "If authorization fails or is unavailable, do not execute the action."
            ),
        )
    query = "How should sensitive AI tool actions be authorized?"
    hits = store.search(query, top_k=3)
    print("Retrieved sources:")
    for source in store.format_sources(hits):
        print(f"- [{source['evidence_id']}] {source['title']} ({source['uri']}) score={source['relevance_score']}")
        print(f"  source_sha256={source['document_sha256']} chunk_sha256={source['chunk_sha256']}")
    print("\nContext for the model:\n")
    print(EvidenceStore.prompt_context(hits))
    if hits:
        first_id = hits[0].evidence_id
        answer = f"Sensitive tool actions should require independent authorization [{first_id}]."
        report = verify_response(answer, EvidenceStore.context(hits), DemoEvaluator())
        print("\nVerification report (demo lexical evaluator, not a semantic guarantee):")
        print(report.to_dict())


if __name__ == "__main__":
    main()
