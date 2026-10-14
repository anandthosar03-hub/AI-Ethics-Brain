from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ethicsbrain.audit import AuditLogger, verify_audit_log


class AuditIntegrityTests(unittest.TestCase):
    def test_new_events_form_valid_hash_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            logger = AuditLogger(path)
            logger.record(event="test", request_id="one", status="allow", prompt="private prompt")
            logger.record(event="test", request_id="two", status="blocked", output="private output")
            report = verify_audit_log(path)
            self.assertTrue(report["ok"], report["errors"])
            self.assertEqual(report["events_checked"], 2)

    def test_arbitrary_extra_fields_are_not_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            logger = AuditLogger(path)
            logger.record(
                event="action", request_id="one", status="allow",
                extra={"secret": "this must be dropped", "action_name": "read_docs\nsecret"},
            )
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("this must be dropped", content)
            self.assertNotIn("read_docs\nsecret", content)
            report = verify_audit_log(path)
            self.assertTrue(report["ok"], report["errors"])

    def test_edits_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            logger = AuditLogger(path)
            logger.record(event="test", request_id="one", status="allow")
            contents = path.read_text(encoding="utf-8").replace('"status": "allow"', '"status": "blocked"')
            path.write_text(contents, encoding="utf-8")
            report = verify_audit_log(path)
            self.assertFalse(report["ok"])
            self.assertTrue(any("hash mismatch" in error for error in report["errors"]))

    def test_legacy_record_is_not_claimed_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.jsonl"
            path.write_text('{"event":"legacy","status":"allow"}\n', encoding="utf-8")
            report = verify_audit_log(path)
            self.assertFalse(report["ok"])
            self.assertTrue(any("missing event_hash" in error for error in report["errors"]))


if __name__ == "__main__":
    unittest.main()
