from __future__ import annotations

import unittest

from ethicsbrain import (
    EvidenceEvaluation,
    GuardrailBrain,
    Policy,
    make_verification_check,
    verify_response,
)
from ethicsbrain.benchmark import run_safety_benchmark
from ethicsbrain.verification_benchmark import DEFAULT_DATASET as VERIFICATION_DATASET, run_verification_benchmark


class FixedEvaluator:
    def __init__(self, status="supported", confidence=0.95):
        self.status = status
        self.confidence = confidence

    def evaluate(self, claim, evidence):
        return EvidenceEvaluation(self.status, self.confidence, "fixed evaluator for test")


class BrokenEvaluator:
    def evaluate(self, claim, evidence):
        raise RuntimeError("simulated evaluator failure")


class VerificationTests(unittest.TestCase):
    def test_citation_without_evaluator_is_unverified_not_supported(self):
        report = verify_response("Sensitive tool actions require authorization [E1].", {"E1": "Sensitive tool actions require independent authorization."})
        self.assertFalse(report.ok)
        self.assertEqual(report.claims[0].status, "unverified")

    def test_missing_citation_fails_verification(self):
        report = verify_response("Sensitive tool actions require authorization.", {"E1": "Sensitive tool actions require independent authorization."}, FixedEvaluator())
        self.assertFalse(report.ok)
        self.assertEqual(report.claims[0].status, "missing_citation")

    def test_unknown_citation_fails_verification(self):
        report = verify_response("Sensitive tool actions require authorization [E7].", {"E1": "Sensitive tool actions require independent authorization."}, FixedEvaluator())
        self.assertEqual(report.claims[0].status, "invalid_citation")

    def test_supported_claim_passes_when_evaluator_confidence_is_high(self):
        report = verify_response("Sensitive tool actions require authorization [E1].", {"E1": "Sensitive tool actions require independent authorization."}, FixedEvaluator())
        self.assertTrue(report.ok)
        self.assertEqual(report.status, "verified")

    def test_low_confidence_support_becomes_insufficient_evidence(self):
        report = verify_response(
            "Sensitive tool actions require authorization [E1].", {"E1": "Sensitive tool actions require independent authorization."},
            FixedEvaluator(confidence=0.40), minimum_confidence=0.75,
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.claims[0].status, "insufficient_evidence")

    def test_contradicted_claim_fails(self):
        report = verify_response(
            "The gateway allows arbitrary upstream model selection [E1].", {"E1": "The gateway uses a server-configured upstream model and rejects client-supplied model selection."},
            FixedEvaluator(status="contradicted"),
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.status, "contradicted")

    def test_evaluator_failure_fails_closed(self):
        report = verify_response("Sensitive tool actions require authorization [E1].", {"E1": "Sensitive tool actions require independent authorization."}, BrokenEvaluator())
        self.assertFalse(report.ok)
        self.assertEqual(report.claims[0].status, "unverified")

    def test_abstention_does_not_require_citation(self):
        report = verify_response("I cannot determine this from the supplied evidence.", {}, FixedEvaluator())
        self.assertTrue(report.ok)
        self.assertEqual(report.claims[0].status, "abstained")

    def test_guardrail_hook_blocks_unsupported_claim(self):
        hook = make_verification_check(FixedEvaluator(status="insufficient_evidence"))
        brain = GuardrailBrain(Policy(grounding_mode="off"), output_checks=[hook])
        result = brain.run(
            "Answer with evidence", lambda req: "The model may execute any requested command without review [E1].",
            context={"E1": "Sensitive tool actions require independent authorization and must not execute when approval is missing."},
        )
        self.assertFalse(result.ok)
        self.assertIn("semantic_evidence_verification_failed", {f.rule_id for f in result.report.findings})

    def test_safety_benchmark_runs_and_catches_current_regressions(self):
        report = run_safety_benchmark()
        self.assertEqual(report["metrics"]["total_cases"], 10)
        self.assertEqual(report["metrics"]["failed_cases"], 0)

    def test_semantic_benchmark_loads_cases_and_returns_confusion_matrix(self):
        report = run_verification_benchmark(VERIFICATION_DATASET, FixedEvaluator())
        self.assertEqual(report["metrics"]["total_cases"], 7)
        self.assertIn("confusion_matrix_rows_actual_columns_predicted", report)
        self.assertGreaterEqual(report["metrics"]["failed_cases"], 1)


if __name__ == "__main__":
    unittest.main()
