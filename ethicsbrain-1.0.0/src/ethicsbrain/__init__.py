"""EthicsBrain: provider-agnostic AI safety and governance framework."""

__version__ = "1.0.0"
from .brain import GuardrailBrain
from .audit import AuditLogger, verify_audit_log
from .governance import ActionBroker, ActionExecutionError, ActionGovernanceError, ActionProposal
from .models import ActionDecision, ActionRequest, Finding, GuardrailReport, ModelRequest, RunResult
from .policy import Policy
from .verification import (
    ClaimVerdict,
    EvidenceEvaluation,
    EvidenceEvaluator,
    VerificationReport,
    make_verification_check,
    verify_response,
)

__all__ = [
    "ActionBroker", "ActionDecision", "ActionExecutionError", "ActionGovernanceError",
    "ActionProposal", "ActionRequest", "AuditLogger", "ClaimVerdict",
    "EvidenceEvaluation", "EvidenceEvaluator", "Finding",
    "GuardrailBrain", "GuardrailReport", "ModelRequest", "Policy", "RunResult",
    "VerificationReport", "make_verification_check", "verify_audit_log", "verify_response",
]
