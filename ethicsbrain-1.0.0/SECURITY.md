# Security Policy

EthicsBrain v1.0.0 is an integrated AI safety framework prototype, not a stand-alone security boundary or safety certification. Do not make it the only protection for systems with sensitive data, valuable credentials, or consequential side effects.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, personal information, production data, or raw customer prompts. For this standalone project, first reproduce the issue with synthetic data and report the affected version, policy configuration, expected behavior, actual behavior, and a minimal proof of concept without secrets. Until the repository owner configures a private reporting channel, do not submit sensitive reports publicly.

## Deployment guidance

Use least privilege, explicit action allowlists, strict argument schemas, authenticated action-bound human approvals, network/process isolation, timeouts, rate limits, secret management, and independently reviewed adversarial test suites. Keep dependencies and deployment images patched. The reference gateway and dashboard bind to loopback by default and are not hardened for internet exposure. Do not treat a passing unit test suite or hash-chain check as a safety certification.
