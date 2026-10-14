"""Typed data structures used by EthicsBrain."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
DecisionStatus = Literal["allow", "blocked", "review"]


@dataclass(frozen=True)
class Finding:
    """A structured, explainable guardrail finding."""

    rule_id: str
    category: str
    severity: Severity
    message: str


@dataclass
class GuardrailReport:
    """Decision and findings for a single request."""

    request_id: str
    status: DecisionStatus
    findings: list[Finding] = field(default_factory=list)
    policy_version: str = "1.0.0"

    @property
    def allowed(self) -> bool:
        return self.status == "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status,
            "policy_version": self.policy_version,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in self.findings
            ],
        }


@dataclass(frozen=True)
class ModelRequest:
    """Provider-neutral payload passed to your model adapter."""

    prompt: str
    context: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunResult:
    """Safe result returned to application code."""

    ok: bool
    text: str
    report: GuardrailReport


@dataclass(frozen=True)
class ActionRequest:
    """A proposed agent/tool action. It is never executed by EthicsBrain."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


@dataclass
class ActionDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "reason": self.reason,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "severity": f.severity,
                    "message": f.message,
                }
                for f in self.findings
            ],
        }
