from __future__ import annotations
import unittest
from ethicsbrain.retrieval_benchmark import run_retrieval_benchmark

class RetrievalBenchmarkTests(unittest.TestCase):
    def test_starter_retrieval_benchmark_reports_metrics(self):
        report = run_retrieval_benchmark()
        self.assertEqual(report["metrics"]["queries"], 8)
        self.assertIn("mean_reciprocal_rank", report["metrics"])
        self.assertTrue(all("retrieved_source_ids" in row for row in report["queries"]))

if __name__ == "__main__":
    unittest.main()
