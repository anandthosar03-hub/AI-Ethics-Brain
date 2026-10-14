from __future__ import annotations
import unittest
from ethicsbrain.nli import TransformersNliEvaluator


class NliThresholdTests(unittest.TestCase):
    def make_evaluator(self, fake_scores):
        evaluator = TransformersNliEvaluator.__new__(TransformersNliEvaluator)
        evaluator.entailment_threshold = 0.70
        evaluator.contradiction_threshold = 0.70
        evaluator.minimum_margin = 0.15
        evaluator._predict = lambda premise, hypothesis: fake_scores[premise]
        return evaluator

    def test_ambiguous_scores_return_insufficient_evidence(self):
        evaluator = self.make_evaluator({
            "weak": {"entailment": 0.62, "contradiction": 0.30, "neutral": 0.08},
        })
        result = evaluator.evaluate("claim", {"E1": "weak"})
        self.assertEqual(result.status, "insufficient_evidence")

    def test_strong_support_with_margin_is_supported(self):
        evaluator = self.make_evaluator({
            "support": {"entailment": 0.88, "contradiction": 0.04, "neutral": 0.08},
        })
        result = evaluator.evaluate("claim", {"E1": "support"})
        self.assertEqual(result.status, "supported")

    def test_strong_conflicting_sources_are_flagged(self):
        evaluator = self.make_evaluator({
            "support": {"entailment": 0.91, "contradiction": 0.02, "neutral": 0.07},
            "contradiction": {"entailment": 0.02, "contradiction": 0.90, "neutral": 0.08},
        })
        result = evaluator.evaluate("claim", {"E1": "support", "E2": "contradiction"})
        self.assertEqual(result.status, "conflicting_evidence")


if __name__ == "__main__":
    unittest.main()
