"""Built-in guardrail checks. Rules are intentionally explainable and imperfect."""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Iterable

from .models import ActionRequest, Finding
from .policy import Policy

# Treat these as high-risk request patterns, not a complete taxonomy of harmfulness.
_PROMPT_INJECTION: tuple[tuple[str, str], ...] = (
    (r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", "instruction_override"),
    (r"\b(?:reveal|print|show|expose)\s+(?:the\s+)?(?:system|developer)\s+prompt\b", "prompt_extraction"),
    (r"\b(?:bypass|disable|turn\s+off)\s+(?:your\s+)?(?:safety|guardrails|policy|restrictions)\b", "safeguard_bypass"),
    (r"\b(?:exfiltrate|leak|print)\s+(?:all\s+)?(?:secrets|api\s+keys|credentials|tokens)\b", "secret_extraction"),
)
_HARMFUL_REQUESTS: tuple[tuple[str, str], ...] = (
    (r"\b(?:steal|exfiltrate|dump)\b.{0,60}\b(?:passwords?|credentials?|access tokens?|api keys)\b", "credential_theft"),
    (r"\b(?:write|create|build|deploy)\b.{0,50}\b(?:ransomware|credential stealer|password stealer|keylogger)\b", "malware_creation"),
    (r"\b(?:disable|evade|bypass)\b.{0,40}\b(?:endpoint detection|antivirus|edr|security monitoring)\b", "security_evasion"),
)

# Obvious high-confidence secret formats. Generic token matching is intentionally
# conservative to avoid treating every long string as a secret.
_SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private_key_material"),
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key_id"),
    (r"\bsk-[A-Za-z0-9_-]{24,}\b", "api_key_like_token"),
    (r"\bgh[pousr]_[A-Za-z0-9]{30,}\b", "github_token"),
    (r"\bAIza[0-9A-Za-z_-]{30,}\b", "google_api_key"),
)
_SENSITIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b\d{3}-\d{2}-\d{4}\b", "us_ssn_like_identifier"),
    (r"\b(?:\d[ -]*?){13,19}\b", "payment_card_like_number"),
)
_CITATION = re.compile(r"\[([A-Za-z][A-Za-z0-9_-]{0,31})\]")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+(?=\S)")
_EXEMPT_GROUNDING = re.compile(
    r"\b(?:i don['’]t know|i cannot determine|i can['’]t determine|"
    r"not enough information|insufficient information|i cannot verify|"
    r"i can['’]t verify|cannot be established from the provided evidence)\b",
    re.IGNORECASE,
)


def _find_patterns(text: str, patterns: Iterable[tuple[str, str]], category: str, severity: str, message: str) -> list[Finding]:
    found: list[Finding] = []
    for pattern, rule_id in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            found.append(Finding(rule_id=rule_id, category=category, severity=severity, message=message))  # type: ignore[arg-type]
    return found


def inspect_prompt(prompt: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    if len(prompt) > policy.max_prompt_chars:
        findings.append(Finding("prompt_too_long", "anomaly", "high", f"Prompt exceeds {policy.max_prompt_chars} characters."))
    if policy.block_prompt_injection:
        findings += _find_patterns(
            prompt, _PROMPT_INJECTION, "prompt_injection", "high",
            "Prompt resembles a prompt-injection or instruction-override attempt.",
        )
    if policy.block_harmful_requests:
        findings += _find_patterns(
            prompt, _HARMFUL_REQUESTS, "harmful_request", "high",
            "Prompt matches a high-risk request pattern; review the intent and application context.",
        )
    findings += _find_patterns(
        prompt, _SECRET_PATTERNS, "privacy", "critical",
        "Prompt appears to contain credential or private-key material; do not forward it to a model.",
    )
    if policy.block_sensitive_identifiers:
        findings += _find_patterns(
            prompt, _SENSITIVE_PATTERNS, "privacy", "high",
            "Prompt contains a string resembling a sensitive personal or payment identifier; review or redact it before model processing.",
        )
    return _deduplicate(findings)


def inspect_output(text: str, context: dict[str, str], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    if len(text) > policy.max_output_chars:
        findings.append(Finding("output_too_long", "anomaly", "high", f"Output exceeds {policy.max_output_chars} characters."))

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    counts = Counter(lines)
    if lines and max(counts.values()) >= policy.repeated_line_limit:
        findings.append(Finding("repetitive_output", "anomaly", "medium", "Output contains a line repeated unusually often."))

    if policy.block_secret_leaks:
        findings += _find_patterns(
            text, _SECRET_PATTERNS, "privacy", "critical",
            "Output appears to contain credential or private-key material.",
        )
    if policy.block_sensitive_identifiers:
        findings += _find_patterns(
            text, _SENSITIVE_PATTERNS, "privacy", "high",
            "Output contains a string resembling a sensitive personal or payment identifier.",
        )

    if policy.grounding_mode != "off":
        findings += _grounding_findings(text, context, policy.grounding_mode)

    return _deduplicate(findings)


def _grounding_findings(text: str, context: dict[str, str], mode: str) -> list[Finding]:
    if not text.strip():
        return [Finding("empty_model_output", "quality", "high", "The model returned an empty response.")]

    valid_ids = {str(key) for key in context.keys()}
    used_ids = set(_CITATION.findall(text))
    unknown = used_ids - valid_ids
    if unknown:
        return [Finding(
            "unknown_evidence_reference", "grounding", "high",
            "Output cites evidence IDs that were not supplied: " + ", ".join(sorted(unknown)) + ".",
        )]

    substantive = [s.strip() for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    # In strict mode, no sources means the framework cannot verify factual claims.
    if mode == "strict" and not valid_ids:
        if substantive and all(_EXEMPT_GROUNDING.search(sentence) for sentence in substantive):
            return []
        return [Finding("grounding_context_missing", "grounding", "high", "Strict grounding is enabled but no evidence context was supplied.")]

    missing = [s for s in substantive if not _CITATION.search(s) and not _EXEMPT_GROUNDING.search(s)]
    if missing:
        severity = "high" if mode == "strict" else "low"
        return [Finding(
            "uncited_claim", "grounding", severity,
            f"{len(missing)} sentence(s) lack an evidence citation in grounding mode '{mode}'.",
        )]
    return []


def inspect_action(action: ActionRequest, policy: Policy, approved: bool = False) -> tuple[bool, bool, list[Finding], str]:
    name = action.name.strip().lower().replace(" ", "_")
    serialized = json.dumps({"name": action.name, "arguments": action.arguments, "reason": action.reason}, default=str).lower()

    if not name:
        finding = Finding("action_name_missing", "action_governance", "high", "An action must have a non-empty name.")
        return False, False, [finding], "Action name is required."

    if name in {item.lower() for item in policy.action_names_always_blocked}:
        finding = Finding("action_explicitly_denied", "action_governance", "critical", "Action is on the explicit denylist.")
        return False, False, [finding], "Action is explicitly denied by policy."

    # Optional allowlist is strongly recommended for production agent systems.
    if policy.allowed_actions is not None and name not in {item.lower() for item in policy.allowed_actions}:
        finding = Finding("action_not_allowlisted", "action_governance", "high", "Action is not in the configured allowlist.")
        return False, False, [finding], "Action is not allowlisted."

    sensitive = any(term in name or term in serialized for term in policy.action_risk_terms)
    if sensitive and not approved:
        finding = Finding("human_approval_required", "action_governance", "high", "Action appears to have external, destructive, or privileged side effects.")
        return False, True, [finding], "Explicit human approval is required before executing this action."
    if sensitive and approved:
        finding = Finding("human_approval_recorded", "action_governance", "medium", "Caller marked this action as human-approved; enforce the approval workflow in the host application.")
        return True, False, [finding], "Action permitted by policy after caller-supplied approval."
    return True, False, [], "Action permitted by policy."


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            result.append(finding)
    return result
