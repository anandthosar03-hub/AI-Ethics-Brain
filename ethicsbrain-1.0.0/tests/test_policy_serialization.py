from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ethicsbrain import Policy


class PolicySerializationTests(unittest.TestCase):
    def test_consolidated_release_version(self):
        import ethicsbrain
        self.assertEqual(ethicsbrain.__version__, "1.0.0")

    def test_round_trip_json(self):
        policy = Policy(grounding_mode="strict", allowed_actions={"read_docs", "search_docs"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            policy.save_json(path)
            restored = Policy.from_json(path)
        self.assertEqual(restored.to_dict(), policy.to_dict())

    def test_unknown_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown policy fields"):
            Policy.from_dict({"unknown_override": True})

    def test_bad_grounding_mode_rejected(self):
        with self.assertRaises(ValueError):
            Policy.from_dict({"grounding_mode": "always_allow"})

    def test_allowed_actions_needs_json_array_or_null(self):
        with self.assertRaisesRegex(ValueError, "JSON array or null"):
            Policy.from_dict({"allowed_actions": "read_docs"})

    def test_policy_cli_example_loads(self):
        path = Path(__file__).resolve().parents[1] / "configs" / "policy.example.json"
        loaded = Policy.from_json(path)
        self.assertEqual(loaded.grounding_mode, "strict")
        self.assertEqual(loaded.allowed_actions, {"search_docs", "read_dashboard"})

    def test_wrong_scalar_types_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "max_prompt_chars must be an integer"):
            Policy.from_dict({"max_prompt_chars": "large"})
        with self.assertRaisesRegex(ValueError, "block_secret_leaks must be a boolean"):
            Policy.from_dict({"block_secret_leaks": 1})
        with self.assertRaisesRegex(ValueError, "max_context_chars must be an integer"):
            Policy.from_dict({"max_context_chars": "huge"})


if __name__ == "__main__":
    unittest.main()
