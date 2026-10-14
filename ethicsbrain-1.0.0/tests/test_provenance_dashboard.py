from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from ethicsbrain.dashboard import collect_dashboard_data, make_handler
from ethicsbrain.provenance import EvidenceStore


class EvidenceStoreTests(unittest.TestCase):
    def test_ingest_retrieve_and_source_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            store = EvidenceStore(path)
            text = (
                "Sensitive AI tool actions must be checked by an independent authorization layer. "
                "Use an explicit allowlist and validate action arguments before execution. "
                "High-impact operations require human approval, and denied actions must never execute. "
            ) * 4
            chunks = store.add_document(
                source_id="ai-tool-policy", title="AI tool authorization guide", text=text,
                uri="https://example.org/ai-tool-policy", publisher="Example Security Team",
                published_at="2025-01-01", chunk_size=180, overlap=30,
            )
            self.assertGreater(len(chunks), 1)
            hits = store.search("independent authorization allowlist validates sensitive tool actions", top_k=3)
            self.assertTrue(hits)
            self.assertEqual(hits[0].chunk.source_id, "ai-tool-policy")
            self.assertTrue(hits[0].chunk.evidence_id.startswith("E"))
            self.assertEqual(EvidenceStore.context(hits)[hits[0].chunk.evidence_id], hits[0].chunk.text)
            self.assertEqual(hits[0].chunk.uri, "https://example.org/ai-tool-policy")
            self.assertEqual(len(hits[0].chunk.document_sha256), 64)
            self.assertTrue(store.verify_integrity()["ok"])
            reopened = EvidenceStore(path)
            self.assertEqual(len(reopened.all_chunks()), len(chunks))
            self.assertTrue(reopened.verify_integrity()["ok"])

    def test_integrity_detects_modified_stored_chunk(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            store = EvidenceStore(path)
            store.add_document(
                source_id="source", title="Example", text=("Evidence text for checking a hash. " * 20),
                chunk_size=150, overlap=10,
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["chunks"][0]["text"] = "Modified content not matching hash"
            path.write_text(json.dumps(payload), encoding="utf-8")
            reopened = EvidenceStore(path)
            report = reopened.verify_integrity()
            self.assertFalse(report["ok"])
            self.assertTrue(any(row["type"] == "chunk_hash_mismatch" for row in report["errors"]))

    def test_rejects_bad_chunking_and_empty_query_returns_no_hits(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EvidenceStore(Path(temp) / "evidence.json")
            with self.assertRaises(ValueError):
                store.add_document(source_id="a", title="b", text="c", chunk_size=10)
            self.assertEqual(store.search("!!!"), [])

    def test_readding_changed_source_preserves_old_version(self):
        with tempfile.TemporaryDirectory() as temp:
            store = EvidenceStore(Path(temp) / "evidence.json")
            store.add_document(source_id="guide", title="Guide", text="First source version with AI safety policy guidance.")
            store.add_document(source_id="guide", title="Guide", text="Second source version with updated AI safety policy guidance.")
            manifest = store.source_manifest()
            self.assertEqual(len(manifest), 2)
            self.assertNotEqual(manifest[0]["document_sha256"], manifest[1]["document_sha256"])


class DashboardTests(unittest.TestCase):
    def test_dashboard_summary_uses_only_safe_event_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            audit = root / "audit.jsonl"
            audit.write_text("\n".join([
                json.dumps({"timestamp": "2026-10-15T00:00:00Z", "event": "model_request", "request_id": "a1", "status": "blocked", "rule_ids": ["prompt_injection"], "extra": {"prompt": "PRIVATE PROMPT"}}),
                json.dumps({"timestamp": "2026-10-15T00:00:01Z", "event": "action_authorization", "request_id": "a2", "status": "review", "rule_ids": ["needs_approval"]}),
            ]) + "\n", encoding="utf-8")
            reports = root / "reports"
            reports.mkdir()
            (reports / "safety_benchmark.json").write_text(json.dumps({"benchmark": "test", "metrics": {"total_cases": 4, "passed_cases": 4, "failed_cases": 0, "accuracy": 1.0}}), encoding="utf-8")
            store_path = root / "evidence.json"
            store = EvidenceStore(store_path)
            store.add_document(source_id="src", title="Test source", text="This is a test evidence document.", publisher="Unit Test")
            data = collect_dashboard_data(audit_path=audit, reports_dir=reports, evidence_store_path=store_path)
            self.assertEqual(data["summary"]["events_total"], 2)
            self.assertEqual(data["summary"]["requests_blocked"], 1)
            self.assertEqual(data["summary"]["actions_review"], 1)
            self.assertEqual(data["summary"]["benchmark_count"], 1)
            self.assertEqual(data["summary"]["evidence_sources"], 1)
            self.assertTrue(data["provenance_integrity"]["ok"])
            self.assertNotIn("extra", data["events"][0])
            self.assertNotIn("PRIVATE PROMPT", json.dumps(data))

    def test_dashboard_http_routes_are_read_only_and_available(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            handler = make_handler(audit_path=root / "missing.jsonl", reports_dir=root, evidence_store_path=root / "missing.json")
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                with urlopen(base + "/health", timeout=3) as response:
                    self.assertEqual(json.loads(response.read()), {"ok": True})
                with urlopen(base + "/api/summary", timeout=3) as response:
                    summary = json.loads(response.read())
                    self.assertEqual(summary["summary"]["events_total"], 0)
                with urlopen(base + "/", timeout=3) as response:
                    self.assertIn(b"EthicsBrain Safety Monitor", response.read())
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
