"""Provider-agnostic guardrail middleware."""
from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from typing import Any

from .audit import AuditLogger
from .checks import inspect_action, inspect_output, inspect_prompt
from .models import ActionDecision, ActionRequest, Finding, GuardrailReport, ModelRequest, RunResult
from .policy import Policy

ModelCallable = Callable[[ModelRequest], str]
PromptCheck = Callable[[str], Iterable[Finding]]
OutputCheck = Callable[[str, dict[str, str]], Iterable[Finding]]

_BLOCKING_SEVERITIES = {"high", "critical"}


class GuardrailBrain:
    """Wrap a model callback with input/output checks and action authorization.

    The model is invoked only when input checks pass. Its returned text is checked
    before it reaches the caller. Tools are never executed by this class; every
    proposed action must be authorized here and then enforced by the host app.
    """

    def __init__(
        self,
        policy: Policy | None = None,
        audit_log_path: str | None = None,
        *,
        prompt_checks: Iterable[PromptCheck] = (),
        output_checks: Iterable[OutputCheck] = (),
    ) -> None:
        self.policy = policy or Policy()
        self.audit = AuditLogger(audit_log_path)
        self.prompt_checks = tuple(prompt_checks)
        self.output_checks = tuple(output_checks)

    def run(
        self,
        prompt: str,
        model: ModelCallable,
        *,
        context: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RunResult:
        request_id = uuid.uuid4().hex
        if not isinstance(prompt, str):
            return self._early_block(request_id, Finding(
                "invalid_prompt_type", "reliability", "critical",
                "Prompt must be a string; the model was not called.",
            ))
        if not prompt.strip():
            return self._early_block(request_id, Finding(
                "empty_prompt", "quality", "high",
                "An empty prompt cannot be processed.",
            ))
        if context is None:
            evidence: dict[str, str] = {}
        elif (not isinstance(context, dict) or any(not isinstance(key, str) or not isinstance(value, str)
                                                   for key, value in context.items())):
            return self._early_block(request_id, Finding(
                "invalid_evidence_context", "reliability", "critical",
                "Evidence context must map string IDs to string passages.",
            ), prompt=prompt)
        else:
            evidence = dict(context)
        context_size = sum(len(key) + len(value) for key, value in evidence.items())
        if context_size > self.policy.max_context_chars:
            return self._early_block(request_id, Finding(
                "context_too_large", "anomaly", "high",
                f"Evidence context exceeds {self.policy.max_context_chars} characters.",
            ), prompt=prompt)
        if metadata is not None and not isinstance(metadata, dict):
            return self._early_block(request_id, Finding(
                "invalid_request_metadata", "reliability", "high",
                "Request metadata must be a dictionary.",
            ), prompt=prompt)

        findings = inspect_prompt(prompt, self.policy)
        findings.extend(self._run_prompt_checks(prompt))
        if self._has_blocking_finding(findings):
            report = GuardrailReport(request_id, "blocked", findings, self.policy.version)
            self._record("model_request", report, prompt=prompt)
            return RunResult(False, self._safe_block_message(findings), report)

        request = ModelRequest(prompt=prompt, context=dict(evidence), metadata=dict(metadata or {}))
        try:
            raw_text = model(request)
            if not isinstance(raw_text, str):
                raise TypeError("Model adapter must return a string")
        except Exception:
            finding = Finding(
                "model_adapter_error", "reliability", "high",
                "The model adapter failed. Details are withheld from the end-user result.",
            )
            report = GuardrailReport(request_id, "blocked", [finding], self.policy.version)
            self._record("model_request", report, prompt=prompt)
            return RunResult(False, "The model could not complete this request safely.", report)

        output_findings = inspect_output(raw_text, evidence, self.policy)
        output_findings.extend(self._run_output_checks(raw_text, evidence))
        # Strict grounding always blocks missing citations; warn-mode findings remain visible.
        blocked = self._has_blocking_finding(output_findings)
        if self.policy.grounding_mode == "strict" and any(f.category == "grounding" for f in output_findings):
            blocked = True
        status = "blocked" if blocked else "allow"
        report = GuardrailReport(request_id, status, output_findings, self.policy.version)
        self._record("model_request", report, prompt=prompt, output=raw_text)
        if blocked:
            return RunResult(False, self._safe_block_message(output_findings), report)
        return RunResult(True, raw_text, report)

    def authorize_action(self, action: ActionRequest, *, approved_by_human: bool = False) -> ActionDecision:
        """Authorize, reject, or require approval for a proposed tool action.

        This method does not run the action. The host application must check the
        returned decision immediately before any external side effect.
        """
        allowed, needs_approval, findings, reason = inspect_action(action, self.policy, approved_by_human)
        self.audit.record(
            event="action_authorization",
            request_id=uuid.uuid4().hex,
            status="allow" if allowed else ("review" if needs_approval else "blocked"),
            rule_ids=[item.rule_id for item in findings],
            extra={"action_name": action.name[:100]},
        )
        return ActionDecision(allowed, needs_approval, reason, findings)


    def _early_block(self, request_id: str, finding: Finding, *, prompt: str = "") -> RunResult:
        report = GuardrailReport(request_id, "blocked", [finding], self.policy.version)
        self._record("model_request", report, prompt=prompt)
        return RunResult(False, self._safe_block_message(report.findings), report)

    def _run_prompt_checks(self, prompt: str) -> list[Finding]:
        findings: list[Finding] = []
        for checker in self.prompt_checks:
            try:
                result = checker(prompt)
                for finding in result:
                    if not isinstance(finding, Finding):
                        raise TypeError("Custom prompt checks must yield Finding objects")
                    findings.append(finding)
            except Exception:
                findings.append(Finding(
                    "custom_prompt_check_failed", "reliability", "critical",
                    "A custom prompt evaluator failed; request blocked (fail-closed).",
                ))
        return findings

    def _run_output_checks(self, text: str, context: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for checker in self.output_checks:
            try:
                result = checker(text, dict(context))
                for finding in result:
                    if not isinstance(finding, Finding):
                        raise TypeError("Custom output checks must yield Finding objects")
                    findings.append(finding)
            except Exception:
                findings.append(Finding(
                    "custom_output_check_failed", "reliability", "critical",
                    "A custom output evaluator failed; response blocked (fail-closed).",
                ))
        return findings

    @staticmethod
    def _has_blocking_finding(findings: list[Finding]) -> bool:
        return any(item.severity in _BLOCKING_SEVERITIES for item in findings)

    @staticmethod
    def _safe_block_message(findings: list[Finding]) -> str:
        categories = sorted({item.category for item in findings})
        if "grounding" in categories:
            return "Response withheld because its evidence-grounding checks did not pass."
        if "privacy" in categories:
            return "Request or response withheld by a privacy guardrail."
        if "prompt_injection" in categories or "harmful_request" in categories:
            return "Request blocked by the configured safety policy."
        if "anomaly" in categories:
            return "Request or response blocked by an anomaly guardrail."
        return "Request blocked by the configured AI safety policy."

    def _record(self, event: str, report: GuardrailReport, *, prompt: str = "", output: str = "") -> None:
        self.audit.record(
            event=event,
            request_id=report.request_id,
            status=report.status,
            prompt=prompt,
            output=output,
            rule_ids=[item.rule_id for item in report.findings],
        )
