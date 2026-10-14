"""Evidence-aware claim verification for EthicsBrain.

The core module has no third-party dependencies. Semantic verification is supplied
through an EvidenceEvaluator plug-in (see ``ethicsbrain.nli`` for an optional local
Transformers implementation). If no evaluator is configured, cited claims remain
unverified; citation presence alone is never treated as proof of factual support.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Literal, Mapping, Protocol, Sequence


EvaluationStatus = Literal["supported", "contradicted", "insufficient_evidence", "conflicting_evidence"]
ClaimStatus = Literal[
    "supported", "contradicted", "insufficient_evidence", "conflicting_evidence",
    "missing_citation", "invalid_citation", "unverified", "abstained",
]
OverallStatus = Literal[
    "verified", "partially_verified", "contradicted", "conflicting_evidence",
    "insufficient_evidence", "missing_citation", "invalid_citation", "unverified",
]

_CITATION = re.compile(r"\[([A-Za-z][A-Za-z0-9_-]{0,31})\]")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+(?=\S)")
_ABSTENTION = re.compile(
    r"\b(?:i don't know|i do not know|i cannot determine|i can't determine|"
    r"not enough information|insufficient information|i cannot verify|i can't verify|"
    r"unable to verify|cannot be established from the provided evidence)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EvidenceEvaluation:
    """Result from an evidence evaluator for a single claim.

    ``confidence`` is a model/evaluator score, not a calibrated probability unless
    the selected evaluator has been empirically calibrated for the relevant domain.
    """

    status: EvaluationStatus
    confidence: float
    explanation: str = ""

    def __post_init__(self) -> None:
        if self.status not in ("supported", "contradicted", "insufficient_evidence", "conflicting_evidence"):
            raise ValueError(f"Unsupported evidence status: {self.status}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


class EvidenceEvaluator(Protocol):
    """Plug-in contract for a semantic entailment/contradiction evaluator."""

    def evaluate(self, claim: str, evidence: Mapping[str, str]) -> EvidenceEvaluation:
        """Assess whether the supplied evidence supports or contradicts a claim."""


@dataclass
class ClaimVerdict:
    claim: str
    citation_ids: list[str]
    status: ClaimStatus
    confidence: float | None = None
    explanation: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class VerificationReport:
    status: OverallStatus
    claims: list[ClaimVerdict] = field(default_factory=list)
    minimum_confidence: float = 0.75
    evaluator: str = "none"

    @property
    def ok(self) -> bool:
        return bool(self.claims) and all(claim.status in ("supported", "abstained") for claim in self.claims)

    @property
    def supported_claims(self) -> int:
        return sum(claim.status == "supported" for claim in self.claims)

    @property
    def total_claims(self) -> int:
        return len(self.claims)

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "ok": self.ok,
            "supported_claims": self.supported_claims,
            "total_claims": self.total_claims,
            "minimum_confidence": self.minimum_confidence,
            "evaluator": self.evaluator,
            "claims": [claim.to_dict() for claim in self.claims],
        }


def verify_response(
    text: str,
    evidence: Mapping[str, str],
    evaluator: EvidenceEvaluator | None = None,
    *,
    minimum_confidence: float = 0.75,
) -> VerificationReport:
    """Verify each sentence against only the evidence IDs cited in that sentence.

    This does not independently establish ground truth. It tests claim-to-evidence
    support using the configured evaluator and returns ``unverified`` if none exists.
    Missing/unknown citations never count as supported. An empty response also fails.
    """
    if not 0.0 <= minimum_confidence <= 1.0:
        raise ValueError("minimum_confidence must be between 0 and 1")
    if not isinstance(text, str) or not text.strip():
        return VerificationReport("unverified", [ClaimVerdict("", [], "unverified", None, "Empty response.")], minimum_confidence, _evaluator_name(evaluator))

    normalized_evidence = {str(key): str(value) for key, value in evidence.items()}
    sentences = [part.strip() for part in _SENTENCE_SPLIT.split(text.strip()) if part.strip()]
    claims: list[ClaimVerdict] = []

    for sentence in sentences:
        if _ABSTENTION.search(sentence):
            claims.append(ClaimVerdict(sentence, _CITATION.findall(sentence), "abstained", 1.0, "The response explicitly abstains from making a verifiable claim."))
            continue

        citation_ids = list(dict.fromkeys(_CITATION.findall(sentence)))
        claim_text = _CITATION.sub("", sentence).strip()
        if not citation_ids:
            claims.append(ClaimVerdict(claim_text, [], "missing_citation", None, "No evidence ID is attached to this claim."))
            continue

        unknown_ids = [item for item in citation_ids if item not in normalized_evidence]
        if unknown_ids:
            claims.append(ClaimVerdict(claim_text, citation_ids, "invalid_citation", None, "Unknown evidence IDs: " + ", ".join(unknown_ids)))
            continue

        if evaluator is None:
            claims.append(ClaimVerdict(claim_text, citation_ids, "unverified", None, "Evidence IDs exist, but no semantic evidence evaluator is configured."))
            continue

        cited_evidence = {key: normalized_evidence[key] for key in citation_ids}
        try:
            judgment = evaluator.evaluate(claim_text, cited_evidence)
            if not isinstance(judgment, EvidenceEvaluation):
                raise TypeError("EvidenceEvaluator must return EvidenceEvaluation")
            status: ClaimStatus = judgment.status
            if status in ("supported", "contradicted", "conflicting_evidence") and judgment.confidence < minimum_confidence:
                status = "insufficient_evidence"
            claims.append(ClaimVerdict(claim_text, citation_ids, status, judgment.confidence, judgment.explanation))
        except Exception:
            # Fail closed: a broken semantic evaluator must never imply verification.
            claims.append(ClaimVerdict(claim_text, citation_ids, "unverified", None, "Evidence evaluator failed; claim was not verified."))

    statuses = {claim.status for claim in claims}
    if statuses <= {"supported", "abstained"} and any(item.status == "supported" for item in claims):
        overall: OverallStatus = "verified"
    elif statuses <= {"supported", "abstained"}:
        overall = "unverified"
    elif "conflicting_evidence" in statuses:
        overall = "conflicting_evidence"
    elif "contradicted" in statuses:
        overall = "contradicted"
    elif "invalid_citation" in statuses:
        overall = "invalid_citation"
    elif "missing_citation" in statuses:
        overall = "missing_citation"
    elif "unverified" in statuses:
        overall = "unverified"
    elif "insufficient_evidence" in statuses:
        overall = "partially_verified" if "supported" in statuses else "insufficient_evidence"
    elif "supported" in statuses:
        overall = "partially_verified"
    else:
        overall = "unverified"

    return VerificationReport(overall, claims, minimum_confidence, _evaluator_name(evaluator))


def make_verification_check(
    evaluator: EvidenceEvaluator,
    *,
    minimum_confidence: float = 0.75,
):
    """Create a GuardrailBrain output-check hook that blocks unverified claims.

    All non-supported factual claims return a high-severity grounding Finding, so
    GuardrailBrain will withhold the response. Pass this only when the application
    supplies cited evidence in ``context`` and the evaluator has been tested.
    """
    from .models import Finding

    def check(text: str, context: dict[str, str]) -> list[Finding]:
        report = verify_response(text, context, evaluator, minimum_confidence=minimum_confidence)
        if report.ok:
            return []
        return [Finding(
            rule_id="semantic_evidence_verification_failed",
            category="grounding",
            severity="high",
            message=f"Claim verification did not pass (status={report.status}; supported={report.supported_claims}/{report.total_claims}).",
        )]

    return check


def _evaluator_name(evaluator: EvidenceEvaluator | None) -> str:
    if evaluator is None:
        return "none"
    return evaluator.__class__.__name__
