"""Configurable policy and conservative, transparent pattern checks.

These rules are deliberately small and auditable. They are not semantic classifiers.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import json
from pathlib import Path
from typing import Any, Literal

GroundingMode = Literal["off", "warn", "strict"]


@dataclass
class Policy:
    """Runtime policy. Tune rules to your application and risk tolerance.

    `grounding_mode="strict"` requires valid evidence citations on each substantive
    sentence whenever the model is asked to answer. Citation presence is not proof
    that the cited evidence entails a claim.
    """

    version: str = "1.0.0"
    max_prompt_chars: int = 20_000
    max_context_chars: int = 60_000
    max_output_chars: int = 12_000
    grounding_mode: GroundingMode = "warn"
    block_prompt_injection: bool = True
    block_harmful_requests: bool = True
    block_secret_leaks: bool = True
    block_sensitive_identifiers: bool = True
    repeated_line_limit: int = 5
    # Empty by default: no tool action is authorized until explicitly allowlisted.
    # Set to None only if you intentionally want open-by-default action handling.
    allowed_actions: set[str] | None = field(default_factory=set)
    action_names_always_blocked: set[str] = field(default_factory=lambda: {
        "exfiltrate_credentials",
        "steal_credentials",
        "deploy_ransomware",
        "disable_security_controls",
        "wipe_host",
        "delete_backups_and_logs",
    })
    action_risk_terms: tuple[str, ...] = (
        "delete", "remove", "wipe", "drop_database", "transfer", "payment",
        "purchase", "send_email", "send_message", "publish", "deploy", "shell",
        "execute", "run_command", "grant_permission", "revoke_permission",
        "modify_account", "write_file", "database_write", "change_password",
        "hiring_decision", "medical_decision", "credit_decision", "legal_decision",
        "education_decision", "housing_decision", "eligibility_decision",
        "employee_termination", "facial_recognition_match", "rank_applicant",
    )

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("version must be a non-empty string")
        for name in ("max_prompt_chars", "max_context_chars", "max_output_chars", "repeated_line_limit"):
            value = getattr(self, name)
            if type(value) is not int:
                raise ValueError(f"{name} must be an integer")
        for name in ("block_prompt_injection", "block_harmful_requests", "block_secret_leaks", "block_sensitive_identifiers"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if self.max_prompt_chars < 1 or self.max_context_chars < 1 or self.max_output_chars < 1:
            raise ValueError("Character limits must be positive")
        if self.repeated_line_limit < 2:
            raise ValueError("repeated_line_limit must be at least 2")
        if self.grounding_mode not in ("off", "warn", "strict"):
            raise ValueError("grounding_mode must be off, warn, or strict")
        if self.allowed_actions is not None and not isinstance(self.allowed_actions, (set, frozenset)):
            raise ValueError("allowed_actions must be a set of strings or None")
        if self.allowed_actions is not None and not all(isinstance(item, str) and item.strip() for item in self.allowed_actions):
            raise ValueError("allowed_actions must contain non-empty strings or be None")
        if not isinstance(self.action_names_always_blocked, (set, frozenset)):
            raise ValueError("action_names_always_blocked must be a set of strings")
        if not all(isinstance(item, str) and item.strip() for item in self.action_names_always_blocked):
            raise ValueError("action_names_always_blocked must contain non-empty strings")
        if not isinstance(self.action_risk_terms, tuple):
            raise ValueError("action_risk_terms must be a tuple of strings")
        if not all(isinstance(item, str) and item.strip() for item in self.action_risk_terms):
            raise ValueError("action_risk_terms must contain non-empty strings")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible policy snapshot suitable for review/versioning."""
        return {
            "version": self.version,
            "max_prompt_chars": self.max_prompt_chars,
            "max_context_chars": self.max_context_chars,
            "max_output_chars": self.max_output_chars,
            "grounding_mode": self.grounding_mode,
            "block_prompt_injection": self.block_prompt_injection,
            "block_harmful_requests": self.block_harmful_requests,
            "block_secret_leaks": self.block_secret_leaks,
            "block_sensitive_identifiers": self.block_sensitive_identifiers,
            "repeated_line_limit": self.repeated_line_limit,
            "allowed_actions": sorted(self.allowed_actions) if self.allowed_actions is not None else None,
            "action_names_always_blocked": sorted(self.action_names_always_blocked),
            "action_risk_terms": list(self.action_risk_terms),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Policy":
        """Create a policy from JSON data, rejecting unknown keys and invalid types."""
        if not isinstance(payload, dict):
            raise ValueError("Policy configuration must be a JSON object")
        known = {item.name for item in fields(cls)}
        unknown = set(payload) - known
        if unknown:
            raise ValueError("Unknown policy fields: " + ", ".join(sorted(unknown)))
        data = dict(payload)
        if "allowed_actions" in data and data["allowed_actions"] is not None:
            if not isinstance(data["allowed_actions"], list):
                raise ValueError("allowed_actions must be a JSON array or null")
            if not all(isinstance(item, str) and item.strip() for item in data["allowed_actions"]):
                raise ValueError("allowed_actions must contain non-empty strings")
            data["allowed_actions"] = set(data["allowed_actions"])
        if "action_names_always_blocked" in data:
            if not isinstance(data["action_names_always_blocked"], list):
                raise ValueError("action_names_always_blocked must be a JSON array")
            if not all(isinstance(item, str) and item.strip() for item in data["action_names_always_blocked"]):
                raise ValueError("action_names_always_blocked must contain non-empty strings")
            data["action_names_always_blocked"] = set(data["action_names_always_blocked"])
        if "action_risk_terms" in data:
            if not isinstance(data["action_risk_terms"], list):
                raise ValueError("action_risk_terms must be a JSON array")
            if not all(isinstance(item, str) and item.strip() for item in data["action_risk_terms"]):
                raise ValueError("action_risk_terms must contain non-empty strings")
            data["action_risk_terms"] = tuple(data["action_risk_terms"])
        return cls(**data)

    @classmethod
    def from_json(cls, path: str | Path) -> "Policy":
        """Load policy from a UTF-8 JSON file."""
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not load policy JSON: {exc}") from exc
        return cls.from_dict(payload)

    def save_json(self, path: str | Path) -> None:
        """Persist a reviewable policy file. Store it in version control, without secrets."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
