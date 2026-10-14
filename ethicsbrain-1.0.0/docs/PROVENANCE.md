# Evidence Retrieval and Provenance in EthicsBrain v1.0.0

## What it does

`EvidenceStore` is a local, dependency-free document store and lexical retriever. It records the source ID, title, publisher, URI, publication date as supplied, retrieval timestamp, full-document SHA-256, per-chunk SHA-256, stable chunk ID, chunk offsets, and optional user metadata. Source versions are preserved by content hash: new content under the same `source_id` creates a new version instead of silently overwriting the old version.

It uses BM25-style lexical scoring. The score ranks passages in this corpus; it is not a calibrated probability, semantic similarity measure, source reliability score, or proof that a claim is true.

## Ingest a local document

```powershell
python -m ethicsbrain.provenance --store data/evidence_store.json add `
  --source-id ai-tool-policy `
  --title "AI tool authorization policy" `
  --publisher "Example Security Team" `
  --uri "https://example.org/replace-with-real-source" `
  --published-at "2026-01-01" `
  --file .\documents\ai_tool_policy.txt
```

The URI and publication date are supplied metadata. EthicsBrain does not fetch the URI or verify the publisher; replace the placeholder with a real source and verify it independently before use. Input files must be UTF-8 text or Markdown.

## Retrieve evidence and make it citeable

```python
from ethicsbrain.provenance import EvidenceStore
from ethicsbrain.verification import verify_response
from ethicsbrain.nli import TransformersNliEvaluator

store = EvidenceStore("data/evidence_store.json")
hits = store.search("How should sensitive AI tool actions be authorized?", top_k=5)
context = store.context(hits)                # {"E...": "retrieved passage", ...}
prompt_evidence = store.prompt_context(hits)  # provenance-rich prompt text
source_cards = store.format_sources(hits)    # metadata and SHA-256 values

# Supply prompt_evidence to your model adapter as untrusted reference material.
# `answer` is the generated response and should cite retrieved IDs like [Eabc123...].
answer = "Sensitive tool actions should require independent authorization [Eabc123def456]."
evaluator = TransformersNliEvaluator(device=-1)  # optional dependencies and model download
report = verify_response(answer, context, evaluator, minimum_confidence=0.75)
print(report.to_dict())
print(source_cards)
```

Use actual IDs from `hits`; the ID in the illustrative answer above is only a placeholder. Pass only retrieved evidence to `verify_response`, so the verifier rejects fabricated IDs. If no semantic evaluator is configured, cited claims remain `unverified`.

## Check the index

```powershell
python -m ethicsbrain.provenance --store data/evidence_store.json verify-integrity
python -m ethicsbrain.provenance --store data/evidence_store.json search "prompt injection tool authorization allowlist" --top-k 5
python -m ethicsbrain.provenance --store data/evidence_store.json manifest
```

Integrity validation checks stored document hashes, chunk hashes, and offsets. It catches many accidental or uncoordinated edits, but it does not prove a source is authentic, authoritative, current, or truthful. The content-addressed IDs are not digital signatures. For tamper-evidence against a privileged attacker, use signed manifests and a separately protected key or external append-only log.

## Evidence quality and known limits

- Lexical retrieval may miss synonyms and paraphrases. Consider a reviewed hybrid BM25 + embedding retriever later; preserve the exact source/chunk IDs regardless of ranking method.
- Retrieval ranking and NLI entailment are separate tasks. A relevant passage may not support the exact claim.
- Dates/publishers are not independently verified, and the library does not fetch URLs.
- Old and new source versions are preserved; applications must decide freshness policy explicitly.
- Retrieved text is untrusted input. Prompt injection can be embedded in a document; never let a retrieved passage override system policy or grant tool permissions.
- SHA-256 demonstrates content consistency relative to the stored hash, not the truth or legal authenticity of a document.
- The JSON file stores complete document text. Protect it as data, keep `data/` out of public Git commits, and do not ingest secrets or documents without permission.
