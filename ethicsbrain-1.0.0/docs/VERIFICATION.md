# Claim-level evidence verification

## Design goals

EthicsBrain v1.0.0 treats a citation as a pointer to evidence, not proof that a claim is true. `verify_response` splits output into sentence-like claims, extracts evidence IDs in square brackets (for example `[E1]`), rejects missing or unknown IDs, and optionally delegates semantic support checking to an `EvidenceEvaluator`.

Status values per claim:

- `supported`: configured evaluator predicts support at or above the configured minimum confidence.
- `contradicted`: configured evaluator predicts contradiction at or above the configured minimum confidence.
- `conflicting_evidence`: supplied passages appear to both support and contradict the claim.
- `insufficient_evidence`: cited passages do not strongly support or contradict the claim, or the score is below threshold.
- `missing_citation`: no evidence ID is attached to the claim.
- `invalid_citation`: one or more evidence IDs are absent from the caller-provided context.
- `unverified`: no semantic evaluator is configured, or evaluator execution fails.
- `abstained`: response explicitly says that the information cannot be established; this is not treated as a factual claim.

`make_verification_check` converts any non-supported claim verdict into a high-severity `Finding` compatible with `GuardrailBrain`. Use this with care: a strict output check can block entire answers if citations are missing or the verifier returns uncertainty.

## Limits

The core contract accepts any evaluator implementing `evaluate(claim, evidence) -> EvidenceEvaluation`. The optional `TransformersNliEvaluator` runs a three-way Natural Language Inference model locally. NLI measures relationships between text passages; it does not independently validate source provenance, currentness, or ground truth. The starter thresholds are initial values, not generally calibrated. Evaluate on representative, held-out examples before deployment.

## Benchmark commands

```bash
python -m ethicsbrain.benchmark --out-dir reports/benchmark
python -m ethicsbrain.verification_benchmark --out-dir reports/verification
```

The first command is dependency-free. The second requires `pip install -e ".[nli]"` and downloads model weights if they are not cached. Both reports clearly label the current dataset as synthetic starter coverage.
