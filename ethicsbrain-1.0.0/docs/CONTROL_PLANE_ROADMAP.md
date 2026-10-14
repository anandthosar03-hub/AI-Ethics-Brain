# EthicsBrain control plane: v1.0 baseline and future engineering

EthicsBrain v1.0.0 integrates the capabilities developed in the earlier prototype iterations. Use this document to distinguish current repository features from deployment work still required.

## Available in this repository

- Provider-agnostic request/response guardrails with transparent pattern checks and custom fail-closed hooks.
- Local OpenAI-compatible reference gateway with bearer token, pinned upstream, role restrictions, size limits, and streaming/tool/multimodal rejection.
- Evidence store with source metadata, chunk IDs, hashes, version history, offsets, lexical retrieval, and integrity checks.
- Claim-level response verification with optional local NLI evaluator, cautious thresholds, and explicit unverified/contradicted/conflicting outcomes.
- ActionBroker with registered handlers, action allowlist, argument validator, short TTL, authenticated approval callback, one-time execution state, expiry, and replay protection.
- Metadata-only audit records with hash-chain links, verifier, and local dashboard status.
- Synthetic safety, verification, and retrieval benchmark runners.

## Still required before production use

### Deployment enforcement

Replace or place the reference gateway behind a production server/reverse proxy with TLS, authenticated identity, authorization, quotas, concurrency limits, timeouts, secrets management, safe error handling, monitoring, and patch management. Keep provider credentials on trusted server-side components. Use host/network egress rules where feasible to prevent controlled workloads from calling providers directly.

### Evaluator validity

Expand synthetic suites into independently reviewed normal-use, privacy, injection, harmful-content, source-contradiction, and high-impact domain cases. Maintain a held-out test set. Measure false accepts, false blocks, precision/recall, per-category failures, latency, calibration, and drift across model/evaluator updates. Set thresholds per domain rather than treating defaults as universal.

### Evidence quality

Add trusted source connectors and access control before retrieval; source authority/freshness review; robust claim segmentation; passage-level citations; independent verification; deterministic checks for arithmetic, dates and structured data; and abstention/human review when evidence is absent, stale, or conflicting.

### Durable multi-instance action execution

The included broker keeps proposals in memory for one Python process. Multi-worker deployments require persistent state, transactional compare-and-set transitions, action-bound authenticated approvals, durable idempotency keys, tenant/resource authorization, and a hardened executor. Every side effect must reauthorize at the last point before execution.

### Audit durability

The hash chain detects changed records relative to a trusted chain head, but an actor able to replace the entire log and recompute all hashes can forge an unanchored history. Export periodic final-hash checkpoints to a separate trusted system, centralize access-controlled logs, define retention, and alert on verification failures. Legacy logs without event hashes are not retroactively verified.

## Unavoidable boundary

EthicsBrain is not a universal controller over unrelated AI models, browsers, applications, accounts, unmanaged devices, or third-party services. Enforcement applies only to request paths, registered actions, credentials, and network/device policies controlled by the deployment owner. Even layered controls reduce and measure risk; they cannot guarantee perfect truth or detection of all harmful behavior.
