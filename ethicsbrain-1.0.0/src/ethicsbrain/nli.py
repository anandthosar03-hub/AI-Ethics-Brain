"""Optional local Natural Language Inference evaluator based on Transformers.

Install with: ``pip install 'ethicsbrain[nli]'``.
The configured model must expose NLI labels (entailment, contradiction, neutral).
A score is not automatically a calibrated probability; validate the selected model
on representative and adversarial data before using it as a blocking control.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .verification import EvidenceEvaluation


class TransformersNliEvaluator:
    """Evaluate evidence passages against claims using a local Transformers NLI model.

    ``model_name`` defaults to a small DeBERTa NLI checkpoint. The model is downloaded
    by Transformers on first use unless already cached. Set ``device=-1`` for CPU or
    ``device=0`` for the first supported GPU. The evaluator runs evidence as premise
    and the claim as hypothesis.
    """

    def __init__(
        self,
        model_name: str = "cross-encoder/nli-deberta-v3-small",
        *,
        device: int = -1,
        max_length: int = 512,
        entailment_threshold: float = 0.70,
        contradiction_threshold: float = 0.70,
        minimum_margin: float = 0.15,
    ) -> None:
        if max_length < 32:
            raise ValueError("max_length must be at least 32")
        for name, value in (("entailment_threshold", entailment_threshold),
                            ("contradiction_threshold", contradiction_threshold),
                            ("minimum_margin", minimum_margin)):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        self.entailment_threshold = entailment_threshold
        self.contradiction_threshold = contradiction_threshold
        self.minimum_margin = minimum_margin
        try:
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - depends on optional install
            raise ImportError("Install the optional NLI dependencies: pip install 'ethicsbrain[nli]'") from exc

        self.model_name = model_name
        self.max_length = max_length
        self._classifier = pipeline("text-classification", model=model_name, tokenizer=model_name, device=device)
        raw_id2label = self._classifier.model.config.id2label
        self._id2label = {str(index): self._normalize_label(str(label)) for index, label in raw_id2label.items()}
        labels = set(self._id2label.values())
        if not {"entailment", "contradiction", "neutral"}.issubset(labels):
            # The Hugging Face model card for this specific checkpoint documents the
            # class order explicitly even when config.id2label is generic LABEL_n.
            if model_name == "cross-encoder/nli-deberta-v3-small":
                self._id2label = {"0": "contradiction", "1": "entailment", "2": "neutral"}
            else:
                raise ValueError(
                    "The selected model does not expose recognized NLI labels. Expected entailment, contradiction, neutral; "
                    f"found {sorted(labels)}. Choose a three-way NLI model or extend the explicit label mapping."
                )

    def evaluate(self, claim: str, evidence: Mapping[str, str]) -> EvidenceEvaluation:
        if not evidence:
            return EvidenceEvaluation("insufficient_evidence", 0.0, "No cited evidence was supplied.")

        entailments: list[float] = []
        contradictions: list[float] = []
        neutral_scores: list[float] = []
        for source_id, premise in evidence.items():
            scores = self._predict(str(premise), claim)
            entailments.append(scores["entailment"])
            contradictions.append(scores["contradiction"])
            neutral_scores.append(scores["neutral"])

        best_entailment = max(entailments, default=0.0)
        best_contradiction = max(contradictions, default=0.0)
        best_neutral = max(neutral_scores, default=0.0)
        support_threshold = getattr(self, "entailment_threshold", 0.70)
        contradiction_threshold = getattr(self, "contradiction_threshold", 0.70)
        minimum_margin = getattr(self, "minimum_margin", 0.15)
        # Strong support and strong contradiction across sources is surfaced as a conflict.
        if best_entailment >= support_threshold and best_contradiction >= contradiction_threshold:
            return EvidenceEvaluation(
                "conflicting_evidence", min(best_entailment, best_contradiction),
                "Different cited evidence passages appear to both support and contradict the claim.",
            )
        if (best_entailment >= support_threshold
                and best_entailment - max(best_contradiction, best_neutral) >= minimum_margin):
            return EvidenceEvaluation(
                "supported", best_entailment,
                "NLI model predicts entailment with the configured threshold and score margin.",
            )
        if (best_contradiction >= contradiction_threshold
                and best_contradiction - max(best_entailment, best_neutral) >= minimum_margin):
            return EvidenceEvaluation(
                "contradicted", best_contradiction,
                "NLI model predicts contradiction with the configured threshold and score margin.",
            )
        score = max(best_entailment, best_contradiction, best_neutral)
        return EvidenceEvaluation(
            "insufficient_evidence", score,
            "NLI scores did not meet a configured threshold and separation margin.",
        )

    def _predict(self, premise: str, hypothesis: str) -> dict[str, float]:
        # Hugging Face text-classification pipelines accept text_pair for sequence-pair models.
        output: Any = self._classifier(
            {"text": premise, "text_pair": hypothesis},
            truncation=True,
            max_length=self.max_length,
            top_k=None,
        )
        # Normalize output shape across supported Transformers versions.
        if isinstance(output, list) and output and isinstance(output[0], list):
            output = output[0]
        if isinstance(output, dict):
            output = [output]
        scores: dict[str, float] = {}
        for item in output:
            label = self._normalize_label(str(item["label"]))
            if label.startswith("label_"):
                label_index = label.removeprefix("label_")
                label = self._id2label.get(label_index, label)
            scores[label] = float(item["score"])
        if not {"entailment", "contradiction", "neutral"}.issubset(scores):
            raise RuntimeError(f"NLI pipeline returned unexpected labels: {sorted(scores)}")
        return scores

    @staticmethod
    def _normalize_label(label: str) -> str:
        return label.strip().lower().replace(" ", "_").replace("-", "_")
