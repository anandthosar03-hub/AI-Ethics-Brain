"""Privacy-conscious, hash-chained JSON Lines audit trail.

The hash chain can detect record changes relative to a trusted chain head. It is not a
signature, and replacing the complete file while recomputing hashes is possible without
an independently stored checkpoint. Multi-process writers should use a process-safe,
centralized logging service rather than this local reference logger.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class _PathState:
    lock: threading.Lock
    last_hash: str | None = None
    loaded: bool = False


_PATH_STATES: dict[str, _PathState] = {}
_PATH_STATES_GUARD = threading.Lock()
_SAFE_EXTRA_KEYS = {"action_name", "proposal_status"}


def _canonical_json(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _read_last_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        last_line = ""
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last_line = line
        if not last_line:
            return None
        parsed = json.loads(last_line)
        value = parsed.get("event_hash") if isinstance(parsed, dict) else None
        return value if isinstance(value, str) else None
    except (OSError, json.JSONDecodeError):
        # Verification will report a malformed/legacy prefix; do not claim it is valid.
        return None


def _safe_extra(extra: dict[str, Any] | None) -> dict[str, str | int | float | bool]:
    """Keep only known metadata keys and small primitive values; drop everything else."""
    safe: dict[str, str | int | float | bool] = {}
    if not isinstance(extra, dict):
        return safe
    for key in _SAFE_EXTRA_KEYS:
        value = extra.get(key)
        if isinstance(value, str):
            # These are identifiers/statuses, not free-form descriptions. Drop characters
            # that could smuggle multiline data or obvious secrets into metadata.
            safe[key] = re.sub(r"[^A-Za-z0-9_.:-]", "_", value)[:100]
        elif type(value) in (int, float, bool):
            safe[key] = value
    return safe


class AuditLogger:
    """Write minimal metadata without raw prompts, completions, or arbitrary caller metadata."""

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path else None
        self._state: _PathState | None = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            key = str(self.path.resolve())
            with _PATH_STATES_GUARD:
                state = _PATH_STATES.get(key)
                if state is None:
                    state = _PathState(lock=threading.Lock())
                    _PATH_STATES[key] = state
                self._state = state
            with state.lock:
                if not state.loaded:
                    state.last_hash = _read_last_hash(self.path)
                    state.loaded = True
        else:
            self._lock = threading.Lock()

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]

    def record(
        self,
        *,
        event: str,
        request_id: str,
        status: str,
        prompt: str = "",
        output: str = "",
        rule_ids: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if not self.path or not self._state:
            return
        state = self._state
        with state.lock:
            previous_hash = state.last_hash
            entry: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": str(event)[:100],
                "request_id": str(request_id)[:128],
                "status": str(status)[:40],
                "prompt_sha256_16": self.digest(prompt) if isinstance(prompt, str) and prompt else None,
                "output_sha256_16": self.digest(output) if isinstance(output, str) and output else None,
                "rule_ids": [str(item)[:100] for item in (rule_ids or [])[:100]],
                "extra": _safe_extra(extra),
                "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                ((previous_hash or "ETHICSBRAIN-GENESIS") + "\n" + _canonical_json(entry)).encode("utf-8")
            ).hexdigest()
            entry["event_hash"] = event_hash
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
            state.last_hash = event_hash


def verify_audit_log(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify event hash and previous-hash links in a JSONL audit log.

    Returns counts and line-specific errors. A valid hash chain detects modification
    only relative to a trusted checkpoint; it is not a signature or non-repudiation
    mechanism and cannot defend against an attacker who can replace the entire file.
    """
    target = Path(path)
    checked = 0
    previous_hash: str | None = None
    errors: list[str] = []
    if not target.exists():
        return {"ok": False, "events_checked": 0, "errors": ["Audit log does not exist."], "final_hash": None}
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return {"ok": False, "events_checked": 0, "errors": [f"Cannot read audit log: {exc}"], "final_hash": None}
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f"Line {line_number}: invalid JSON.")
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("event_hash"), str):
            errors.append(f"Line {line_number}: missing event_hash (legacy or malformed record).")
            previous_hash = None
            continue
        stored_hash = entry.get("event_hash")
        linked_previous = entry.get("previous_hash")
        if linked_previous != previous_hash:
            errors.append(f"Line {line_number}: previous_hash does not match the prior event.")
        unsigned = dict(entry)
        unsigned.pop("event_hash", None)
        expected_hash = hashlib.sha256(
            ((linked_previous or "ETHICSBRAIN-GENESIS") + "\n" + _canonical_json(unsigned)).encode("utf-8")
        ).hexdigest()
        if stored_hash != expected_hash:
            errors.append(f"Line {line_number}: event hash mismatch.")
        checked += 1
        previous_hash = stored_hash
    return {"ok": not errors, "events_checked": checked, "errors": errors, "final_hash": previous_hash}
