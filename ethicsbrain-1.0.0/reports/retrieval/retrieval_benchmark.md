# EthicsBrain Retrieval Benchmark

> **Limitation:** Synthetic AI safety/governance examples only. Retrieval scores do not measure truth, entailment, or real-world retrieval quality.

Method: `BM25-style lexical ranking`

- Queries: 8
- Top-k: 3
- Hit rate@k: 1.0
- Mean recall@k: 0.9375
- Mean precision@k: 0.375
- Mean reciprocal rank: 1.0

## Queries

| Query ID | Hit@k | Recall@k | Precision@k | Reciprocal rank | Retrieved sources |
|---|---:|---:|---:|---:|---|
| `q_prompt_injection` | True | 1.0 | 0.3333 | 1.0 | prompt-injection, secret-handling, nli-evaluation |
| `q_tool_permissions` | True | 1.0 | 0.3333 | 1.0 | action-authorization, prompt-injection, retrieval-provenance |
| `q_audit_privacy` | True | 1.0 | 0.3333 | 1.0 | audit-privacy, secret-handling, retrieval-provenance |
| `q_provenance` | True | 1.0 | 0.3333 | 1.0 | retrieval-provenance, secret-handling, prompt-injection |
| `q_nli` | True | 1.0 | 0.3333 | 1.0 | nli-evaluation, secret-handling, action-authorization |
| `q_secrets` | True | 1.0 | 0.3333 | 1.0 | secret-handling, retrieval-provenance, nli-evaluation |
| `q_hash_integrity` | True | 0.5 | 0.3333 | 1.0 | nli-evaluation, prompt-injection, secret-handling |
| `q_bypass` | True | 1.0 | 0.6667 | 1.0 | action-authorization, prompt-injection, secret-handling |
