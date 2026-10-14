"""Enforced, single-use action execution broker.

The broker is designed so registered actions can only be reached through this API
within a Python process. It does not stop an application from creating a separate,
unprotected execution path; deployment code must keep raw tool handlers private.
"""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from .audit import AuditLogger
from .checks import inspect_action
from .models import ActionDecision, ActionRequest, Finding
from .policy import Policy

ProposalStatus = Literal["ready", "awaiting_approval", "approved", "denied", "executing", "executed", "failed", "expired"]
ActionHandler = Callable[[dict[str, Any]], Any]
ArgumentsValidator = Callable[[dict[str, Any]], bool]
ApprovalAuthorizer = Callable[[str, ActionRequest, object | None], bool]


class ActionGovernanceError(RuntimeError):
    """Raised when an action is not permitted to execute."""


class ActionExecutionError(RuntimeError):
    """Raised when an authorized handler fails; internal details are not exposed."""


@dataclass(frozen=True)
class ActionProposal:
    """Immutable, argument-redacted snapshot of a proposed action."""

    proposal_id: str
    action_name: str
    status: ProposalStatus
    created_at: float
    expires_at: float
    decision: ActionDecision
    approved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return safe metadata; action arguments are intentionally excluded."""
        return {
            "proposal_id": self.proposal_id,
            "action_name": self.action_name,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approved_by": self.approved_by,
            "decision": self.decision.to_dict(),
            "arguments_included": False,
        }


@dataclass
class _ActionRecord:
    proposal_id: str
    action_name: str
    status: ProposalStatus
    created_at: float
    expires_at: float
    decision: ActionDecision
    _action: ActionRequest = field(repr=False, default_factory=lambda: ActionRequest(""))
    _argument_digest: str = field(repr=False, default="")
    approved_by: str | None = None

    def view(self) -> ActionProposal:
        # Deep copy nested decisions/findings so callers cannot mutate broker state.
        return ActionProposal(
            proposal_id=self.proposal_id, action_name=self.action_name, status=self.status,
            created_at=self.created_at, expires_at=self.expires_at,
            decision=copy.deepcopy(self.decision), approved_by=self.approved_by,
        )


@dataclass(frozen=True)
class _Registration:
    handler: ActionHandler
    validator: ArgumentsValidator


def _normalize_name(name: str) -> str:
    return "_".join(name.strip().lower().split())


def _action_digest(action: ActionRequest) -> str:
    try:
        payload = json.dumps(
            {"name": _normalize_name(action.name), "arguments": action.arguments, "reason": action.reason},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Action payload must contain JSON-serializable values") from None
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ActionBroker:
    """Policy-enforced action registry with time-limited human approval and replay protection.

    Args:
        policy: A policy that explicitly allowlists each registered action.
        approval_authorizer: Host-supplied callback that verifies the human approver's
            identity/authorization. If omitted, sensitive actions cannot be approved.
        audit_log_path: Optional metadata-only JSONL audit path.
        proposal_ttl_seconds: Lifetime of a proposal, in seconds.

    This class does not provide identity management. Do not implement the authorizer as
    ``lambda *_: True`` in production; integrate it with a real authenticated approval UI.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        approval_authorizer: ApprovalAuthorizer | None = None,
        audit_log_path: str | None = None,
        proposal_ttl_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if proposal_ttl_seconds < 1:
            raise ValueError("proposal_ttl_seconds must be positive")
        self.policy = policy
        self.approval_authorizer = approval_authorizer
        self.audit = AuditLogger(audit_log_path)
        self.proposal_ttl_seconds = proposal_ttl_seconds
        self._clock = clock
        self._handlers: dict[str, _Registration] = {}
        self._proposals: dict[str, _ActionRecord] = {}
        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        handler: ActionHandler,
        *,
        validate_arguments: ArgumentsValidator | None = None,
    ) -> None:
        """Register an application-owned handler for an explicitly allowlisted action."""
        if not isinstance(name, str):
            raise ValueError("Action name must be a string")
        normalized = _normalize_name(name)
        if not normalized:
            raise ValueError("Action name is required")
        if not callable(handler):
            raise TypeError("handler must be callable")
        if normalized in {_normalize_name(x) for x in self.policy.action_names_always_blocked}:
            raise ValueError("Explicitly denied actions cannot be registered")
        if self.policy.allowed_actions is not None:
            allowlisted = {_normalize_name(x) for x in self.policy.allowed_actions}
            if normalized not in allowlisted:
                raise ValueError("Action must be present in policy.allowed_actions before registration")
        validator = validate_arguments or (lambda _arguments: True)
        with self._lock:
            if normalized in self._handlers:
                raise ValueError(f"Action already registered: {normalized}")
            self._handlers[normalized] = _Registration(handler, validator)

    def propose(self, action: ActionRequest) -> ActionProposal:
        """Validate a proposed action and create a short-lived proposal record."""
        if not isinstance(action, ActionRequest):
            raise TypeError("action must be an ActionRequest")
        if not isinstance(action.name, str):
            raise ValueError("action name must be a string")
        if not isinstance(action.arguments, dict) or not all(isinstance(key, str) for key in action.arguments):
            raise ValueError("action arguments must be a dictionary with string keys")
        normalized = _normalize_name(action.name)
        copied_action = ActionRequest(
            name=normalized, arguments=copy.deepcopy(action.arguments), reason=str(action.reason),
        )
        now = self._clock()
        proposal_id = secrets.token_urlsafe(24)
        digest = _action_digest(copied_action)
        registration_exists = normalized in self._handlers
        allowed, needs_approval, findings, reason = inspect_action(copied_action, self.policy, approved=False)
        if not registration_exists:
            allowed, needs_approval = False, False
            findings = list(findings) + [Finding(
                "action_handler_not_registered", "action_governance", "high",
                "No registered handler exists for this action.",
            )]
            reason = "No registered handler exists for this action."
        if allowed:
            status: ProposalStatus = "ready"
        elif needs_approval:
            status = "awaiting_approval"
        else:
            status = "denied"
        decision = ActionDecision(allowed, needs_approval, reason, findings)
        proposal = _ActionRecord(
            proposal_id=proposal_id, action_name=normalized, status=status,
            created_at=now, expires_at=now + self.proposal_ttl_seconds,
            decision=decision, _action=copied_action, _argument_digest=digest,
        )
        with self._lock:
            self._proposals[proposal_id] = proposal
        self._audit(proposal, "action_proposed", status, findings)
        return proposal.view()

    def approve(self, proposal_id: str, *, approver_id: str, proof: object | None = None) -> ActionProposal:
        """Approve a sensitive proposal only after a host-authenticated approval check."""
        with self._lock:
            proposal = self._get_active(proposal_id)
            if proposal.status != "awaiting_approval":
                raise ActionGovernanceError("Proposal is not awaiting approval")
            if not approver_id or self.approval_authorizer is None:
                raise ActionGovernanceError("A configured authenticated approval authorizer is required")
            try:
                authenticated = self.approval_authorizer(approver_id, copy.deepcopy(proposal._action), proof)
            except Exception:
                authenticated = False
            if authenticated is not True:
                self._audit(proposal, "approval_rejected", "denied", proposal.decision.findings)
                raise ActionGovernanceError("Human approval could not be authenticated")
            if _action_digest(proposal._action) != proposal._argument_digest:
                proposal.status = "denied"
                raise ActionGovernanceError("Proposal integrity check failed")
            allowed, needs_approval, findings, reason = inspect_action(proposal._action, self.policy, approved=True)
            if not allowed or needs_approval:
                proposal.status = "denied"
                proposal.decision = ActionDecision(False, False, reason, findings)
                raise ActionGovernanceError("Current policy does not permit this action")
            proposal.status = "approved"
            proposal.approved_by = approver_id
            proposal.decision = ActionDecision(True, False, reason, findings)
            self._audit(proposal, "action_approved", "allow", findings)
            return proposal.view()

    def deny(self, proposal_id: str, *, reviewer_id: str = "") -> ActionProposal:
        """Deny a pending proposal. Host code should authenticate reviewer_id."""
        with self._lock:
            proposal = self._get_active(proposal_id)
            if proposal.status not in ("awaiting_approval", "ready"):
                raise ActionGovernanceError("Proposal cannot be denied in its current state")
            proposal.status = "denied"
            proposal.decision = ActionDecision(False, False, "Denied by human review.", [Finding(
                "human_review_denied", "action_governance", "high", "Action denied by human review.",
            )])
            proposal.approved_by = reviewer_id or None
            self._audit(proposal, "action_denied", "blocked", proposal.decision.findings)
            return proposal.view()

    def execute(self, proposal_id: str) -> Any:
        """Execute a ready/approved action once, after rechecking current policy and inputs."""
        with self._lock:
            proposal = self._get_active(proposal_id)
            if proposal.status not in ("ready", "approved"):
                raise ActionGovernanceError(f"Proposal is not executable (status={proposal.status})")
            if _action_digest(proposal._action) != proposal._argument_digest:
                proposal.status = "denied"
                raise ActionGovernanceError("Proposal integrity check failed")
            registration = self._handlers.get(proposal.action_name)
            if registration is None:
                proposal.status = "denied"
                raise ActionGovernanceError("Registered handler no longer exists")
            is_approved = proposal.status == "approved"
            allowed, needs_approval, findings, reason = inspect_action(proposal._action, self.policy, approved=is_approved)
            if not allowed or needs_approval:
                proposal.decision = ActionDecision(False, needs_approval, reason, findings)
                proposal.status = "awaiting_approval" if needs_approval else "denied"
                self._audit(proposal, "action_execution_denied", "review" if needs_approval else "blocked", findings)
                raise ActionGovernanceError(reason)
            try:
                arguments = copy.deepcopy(proposal._action.arguments)
                if not isinstance(arguments, dict) or registration.validator(arguments) is not True:
                    proposal.status = "denied"
                    self._audit(proposal, "action_arguments_rejected", "blocked", [Finding(
                        "action_arguments_invalid", "action_governance", "high", "Action arguments failed validation.",
                    )])
                    raise ActionGovernanceError("Action arguments failed validation")
            except ActionGovernanceError:
                raise
            except Exception:
                proposal.status = "denied"
                raise ActionGovernanceError("Action argument validation failed") from None
            # Reserve state while under lock: concurrent callers cannot execute twice.
            proposal.status = "executing"
            self._audit(proposal, "action_execution_started", "allow", findings)
            handler = registration.handler
        try:
            result = handler(arguments)
        except Exception:
            with self._lock:
                proposal.status = "failed"
                self._audit(proposal, "action_execution_failed", "blocked", [Finding(
                    "action_handler_failed", "reliability", "high", "The action handler failed; details are withheld.",
                )])
            raise ActionExecutionError("The authorized action handler failed") from None
        with self._lock:
            proposal.status = "executed"
            self._audit(proposal, "action_execution_completed", "allow", findings)
        return result

    def get_proposal(self, proposal_id: str) -> dict[str, Any]:
        """Return safe, argument-redacted proposal metadata."""
        with self._lock:
            proposal = self._proposals.get(proposal_id)
            if proposal is None:
                raise KeyError("Unknown proposal")
            return proposal.view().to_dict()

    def _get_active(self, proposal_id: str) -> _ActionRecord:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError("Unknown proposal")
        if self._clock() >= proposal.expires_at and proposal.status not in ("executing", "executed", "failed", "denied", "expired"):
            proposal.status = "expired"
            self._audit(proposal, "action_proposal_expired", "blocked", [Finding(
                "action_proposal_expired", "action_governance", "medium", "Action proposal expired.",
            )])
        if proposal.status == "expired":
            raise ActionGovernanceError("Action proposal expired")
        return proposal

    def _audit(self, proposal: _ActionRecord, event: str, status: str, findings: list[Finding]) -> None:
        self.audit.record(
            event=event,
            request_id=proposal.proposal_id,
            status=status,
            rule_ids=[finding.rule_id for finding in findings],
            extra={"action_name": proposal.action_name, "proposal_status": proposal.status},
        )
