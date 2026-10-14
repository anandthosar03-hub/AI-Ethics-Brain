# Threat model — EthicsBrain v1.0.0

## Intended protections

- Catch selected credential-like strings, sensitive identifier patterns, and prompt-injection/high-risk patterns before model invocation.
- Scan returned text for selected output risks, citation syntax, and configured custom evaluator rules.
- Constrain registered tool actions through an explicit allowlist, per-action argument validation, short-lived proposals, authenticated approval callbacks, and one-time execution state.
- Track evidence source versions, content hashes, chunk identifiers, and retrieval provenance.
- Provide privacy-minimizing audit metadata and hash-chain checks for newly written logs.
- Make guardrail and retrieval behavior testable through synthetic benchmarks and inspectable in a local dashboard.

## Assumptions and deployment requirements

- The host routes every controlled model request through `GuardrailBrain` or the reference gateway.
- The host routes every governed side effect through the `ActionBroker` and does not expose an unguarded path to the same handler or credentials.
- `Policy.allowed_actions` is configured deliberately; empty allowlist is the default.
- The host supplies authenticated, action-bound human approval for sensitive actions. The framework does not provide user identity or approval UI.
- The host validates action arguments, scopes permissions to a user/tenant/resource, and applies process, filesystem, and network isolation where needed.
- Model adapters follow their contract and return text; source connectors and evidence permissions are configured by the application owner.

## Out of scope / not guaranteed

- Controlling third-party models/apps/accounts outside the protected request path.
- Preventing model-internal behavior or modifying hosted model weights.
- Complete detection of prompt injection, malware requests, personal data, toxicity, bias, deception, or hallucinations.
- Proving factual truth from citation syntax, content hashes, or an NLI score.
- Authentication of human approvers, durable multi-worker action state, process isolation, sandboxing, network egress enforcement, or endpoint protection.
- Production safety certification, legal compliance, or suitability for autonomous high-impact decisions.
- Defending an unanchored hash-chained log against an attacker who can replace the whole file and recompute every hash.

## Recommended production controls

Use least privilege, authenticated identities, explicit allowlists, isolated execution, strict schemas, tenant/resource checks, timeouts, rate limits, idempotency keys, secrets management, TLS, monitored human review, audit checkpoints stored externally, data minimization, retention controls, and independent adversarial testing. Set measurable acceptance thresholds for false accepts, false blocks, latency, model/evaluator failure, and bypass tests before deployment.
