# Operations guide

## Local development

- Keep the gateway/dashboard bound to `127.0.0.1`.
- Use a local `.venv`, keep `.env` files untracked, and use fake/synthetic documents for smoke tests.
- Run unit tests and safety/retrieval/verification benchmarks after changing policy, rules, NLI checkpoints, or retrieval code.
- Keep benchmark output and the exact policy version alongside every evaluation run.

## Log integrity

`AuditLogger` creates a SHA-256 hash chain for records written by v1.0.0. Use `python -m ethicsbrain.audit_cli logs/audit.jsonl` to check the chain. Hash chaining detects changed records relative to a trusted chain head; it does not provide a digital signature. Periodically checkpoint the last hash outside the log, for example in a restricted central log service. Legacy rows without the chain fields are intentionally reported as unverifiable rather than silently accepted.

The logger stores content fingerprints, not content, by default. Hashes are pseudonymous identifiers and may still be sensitive. If correlating fingerprints is not necessary, do not log content hashes.

## Production readiness gates

Before any shared/production use, require all of the following:

1. Threat model and data-flow review approved by the system owner.
2. TLS, identity-aware authentication/authorization, rate/concurrency limits, request quotas, timeouts, and safe error handling at the gateway.
3. Secrets in a managed secret store; provider credentials are not shared with clients.
4. Network egress controls and evidence that controlled workloads cannot reach upstream model APIs by an unapproved route.
5. Validated, domain-specific guardrail/evidence evaluators with false-negative and false-positive metrics on held-out tests.
6. Durable action proposals, authenticated and action-bound approvals, idempotency, and audit checkpoints for multi-instance action execution.
7. Least-privilege handler credentials, strict argument schemas, resource scoping, sandboxing and human review for high-impact actions.
8. Privacy/retention policy, audit access controls, backup/restore procedure, monitoring alerts, and incident response runbook.
9. Independent security review and load/adversarial tests against the actual deployment, not just the simulated unit tests.

The repository's reference HTTP gateway and dashboard are not a replacement for a hardened production server stack.
