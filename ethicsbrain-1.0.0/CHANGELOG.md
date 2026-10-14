# Changelog

## 1.0.0 — Consolidated AI safety and governance release

This is the single integrated flagship release, incorporating the capabilities previously developed across the 0.1–0.4 series.

- Unified provider-neutral input/output guardrails, OpenAI-compatible local reference gateway, evidence verification, provenance-aware retrieval, benchmarks, and local monitoring dashboard.
- Added `ActionBroker`: registered-handler execution only, explicit allowlist, argument validation, short-lived proposals, host-authenticated human approval callback, single-use execution state, expiry, replay prevention, and argument-redacted proposal metadata.
- Added immutable action-proposal snapshots so caller-side changes to returned metadata do not alter internal proposal state.
- Added JSON policy `to_dict`/`from_dict`/`from_json`/`save_json` support, unknown-key rejection, type validation, a reviewed example config, and a policy CLI.
- Added hash-chained audit records and `verify_audit_log`, CLI verification, and dashboard hash-chain status. The hash chain is integrity-evident only when its final checkpoint is trusted externally.
- Fixed NLI threshold behavior: weak/ambiguous results remain `insufficient_evidence`; support/contradiction require configurable thresholds and score separation; strong disagreement across sources is surfaced as conflicting evidence.
- Added tests for action approval and replay protection, proposal expiry, argument validation, policy serialization, audit tampering, and NLI thresholds.
- Preserved a dependency-free core runtime; model-based NLI remains optional.
- Rewrote setup and security documentation around actual trust boundaries and test scope.

## 0.4.0 — Retrieval provenance, evidence evaluation, and monitoring dashboard

- Added a local evidence store with version-preserving ingestion, stable chunk IDs, source metadata, SHA-256 hashes, text offsets, lexical retrieval, and integrity checks.
- Added optional NLI evaluation, retrieval ranking metrics, and a local read-only dashboard.

## 0.3.0 — Safety benchmark + evidence verification

- Added claim-level verification statuses, optional local Transformers NLI evaluation, synthetic benchmarks, and fail-closed output-check integration.

## 0.2.0 — Enforcement gateway prototype

- Added a reference OpenAI-compatible gateway with bearer-token authentication, pinned upstream model, size limits, role restrictions, and guarded outputs.

## 0.1.0 — Initial release

- Added provider-neutral guardrail middleware, pattern checks, citation syntax checks, advisory action authorization, and privacy-conscious audit records.
