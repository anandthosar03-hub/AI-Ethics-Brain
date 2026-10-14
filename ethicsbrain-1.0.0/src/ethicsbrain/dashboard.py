"""Local, read-only monitoring dashboard for EthicsBrain audit and benchmark files.

Usage: python -m ethicsbrain.dashboard --audit logs/audit.jsonl --reports-dir reports
The default bind address is loopback. Do not expose this reference dashboard to a network
without adding authentication, TLS, and deployment hardening.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .provenance import EvidenceStore
from .audit import verify_audit_log


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EthicsBrain Safety Monitor</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141c2f;--line:#2a3650;--ink:#e8edf7;--muted:#9aa9c3;--accent:#8bb8ff;--ok:#72d5ad;--warn:#ffd27d;--bad:#ff8a8a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1200px;margin:0 auto;padding:24px}header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px}h1{margin:0;font-size:clamp(1.6rem,3vw,2.3rem)}h2{font-size:1.1rem;margin:0 0 12px}.muted{color:var(--muted)}.pill{border:1px solid var(--line);border-radius:99px;padding:5px 10px;color:var(--muted);font-size:.85rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin:16px 0}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}.metric{font-size:1.75rem;font-weight:750;margin:4px 0}.good{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.section{margin-top:18px}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}code{overflow-wrap:anywhere;color:#bad1ff}.status{display:inline-block;padding:2px 7px;border-radius:6px;background:#202b40}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}button{background:#233756;border:1px solid #3b5279;color:var(--ink);border-radius:9px;padding:8px 12px;cursor:pointer}button:hover{background:#2d4568}.error{color:var(--bad);white-space:pre-wrap}.empty{color:var(--muted);padding:12px 0}footer{margin-top:28px;color:var(--muted);font-size:.8rem}
</style></head><body><main>
<header><div><h1>EthicsBrain Safety Monitor</h1><div class="muted">Local read-only view of guardrail events, evidence provenance, and benchmark results.</div></div><div class="actions"><span class="pill" id="updated">Loading…</span><button id="refresh">Refresh data</button></div></header>
<div id="error" class="error"></div><div id="metrics" class="grid"></div>
<section class="section panel"><h2>Audit log integrity</h2><div id="auditIntegrity" class="muted">Loading audit hash-chain status…</div></section>
<section class="section panel"><h2>Evidence provenance integrity</h2><div id="integrity" class="muted">Loading evidence index status…</div><div class="scroll"><table><thead><tr><th>Source</th><th>Publisher</th><th>Published</th><th>Retrieved</th><th>Document SHA-256</th><th>Chunks</th></tr></thead><tbody id="sources"></tbody></table></div></section>
<section class="section panel"><h2>Benchmark reports</h2><div class="scroll"><table><thead><tr><th>Report</th><th>Evaluator</th><th>Cases</th><th>Primary metric</th><th>Failed</th><th>Warning</th></tr></thead><tbody id="benchmarks"></tbody></table></div></section>
<section class="section panel"><h2>Recent events</h2><div class="muted">Raw prompts and model responses are intentionally not shown. Only metadata recorded in the audit log is displayed.</div><div class="scroll"><table><thead><tr><th>Time</th><th>Event</th><th>Status</th><th>Rule IDs</th><th>Request ID</th></tr></thead><tbody id="events"></tbody></table></div></section>
<footer>EthicsBrain is a monitoring aid, not proof of model safety or factual truth. Benchmark scores are meaningful only in the context of dataset coverage and test quality.</footer>
</main><script>
const $=id=>document.getElementById(id);const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function metric(label,value,kind=''){return `<div class="card"><div class="muted">${esc(label)}</div><div class="metric ${kind}">${esc(value)}</div></div>`}
async function refresh(){ $('error').textContent='';try{const r=await fetch('/api/summary',{cache:'no-store'});if(!r.ok)throw new Error('Dashboard endpoint returned '+r.status);const d=await r.json();$('updated').textContent='Updated '+new Date(d.generated_at).toLocaleTimeString();const s=d.summary;$('metrics').innerHTML=[metric('Audit events',s.events_total),metric('Model requests allowed',s.requests_allowed,'good'),metric('Model requests blocked',s.requests_blocked,s.requests_blocked?'bad':''),metric('Actions awaiting review',s.actions_review,s.actions_review?'warn':''),metric('Benchmark reports',s.benchmark_count),metric('Evidence sources',s.evidence_sources),metric('Evidence chunks',s.evidence_chunks)].join('');
const a=d.audit_integrity;$('auditIntegrity').innerHTML=a?`Hash-chain check: <b class="${a.ok?'good':'bad'}">${a.ok?'PASS':'FAIL'}</b> · ${esc(a.events_checked)} events checked · ${esc(a.errors?.length||0)} issues. <span class="muted">${esc(a.final_hash||'')}</span>`:'No audit log configured.';
const p=d.provenance_integrity;$('integrity').innerHTML=p?`Integrity check: <b class="${p.ok?'good':'bad'}">${p.ok?'PASS':'FAIL'}</b> · ${esc(p.sources_checked)} sources checked · ${esc(p.chunks_checked)} chunks checked · ${esc(p.errors?.length||0)} issues. <span class="muted">${esc(p.note||'')}</span>`:'No evidence store configured.';
$('sources').innerHTML=(d.sources||[]).map(x=>`<tr><td>${esc(x.title)}<br><code>${esc(x.source_id)}</code></td><td>${esc(x.publisher||'—')}</td><td>${esc(x.published_at||'—')}</td><td>${esc(x.retrieved_at||'—')}</td><td><code>${esc(x.document_sha256)}</code></td><td>${esc(x.chunk_count)}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No indexed evidence sources.</td></tr>';
$('benchmarks').innerHTML=(d.benchmarks||[]).map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.evaluator||'—')}</td><td>${esc(x.total_cases??'—')}</td><td>${esc(x.primary_metric_name||'Score')}: ${esc(x.primary_metric??'—')}</td><td>${esc(x.failed_cases??'—')}</td><td>${esc(x.warning||'—')}</td></tr>`).join('')||'<tr><td colspan="6" class="empty">No benchmark JSON reports found.</td></tr>';
$('events').innerHTML=(d.events||[]).map(x=>`<tr><td>${esc(x.timestamp||'—')}</td><td>${esc(x.event||'—')}</td><td><span class="status">${esc(x.status||'—')}</span></td><td><code>${esc((x.rule_ids||[]).join(', ')||'—')}</code></td><td><code>${esc(x.request_id||'—')}</code></td></tr>`).join('')||'<tr><td colspan="5" class="empty">No audit events found.</td></tr>';
}catch(e){$('error').textContent='Could not load dashboard data: '+e.message}}
$('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,15000);
</script></body></html>'''


def _load_audit(path: Path | None, *, limit: int = 1000) -> tuple[list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    if path is None or not path.exists():
        return events, errors
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"Skipped invalid audit JSON at line {line_number}")
                    continue
                # Intentionally publish only known metadata fields. Never forward arbitrary `extra`.
                events.append({
                    "timestamp": raw.get("timestamp"),
                    "event": raw.get("event"),
                    "request_id": raw.get("request_id"),
                    "status": raw.get("status"),
                    "rule_ids": list(raw.get("rule_ids", [])) if isinstance(raw.get("rule_ids", []), list) else [],
                })
    except OSError as exc:
        errors.append(f"Could not read audit file: {exc}")
    return events[-limit:][::-1], errors


def _load_benchmarks(directory: Path | None) -> tuple[list[dict[str, Any]], list[str]]:
    reports: list[dict[str, Any]] = []
    errors: list[str] = []
    if directory is None or not directory.exists():
        return reports, errors
    try:
        paths = sorted(p for p in directory.rglob("*.json") if "benchmark" in p.name.lower())
    except OSError as exc:
        return reports, [f"Could not scan benchmark reports: {exc}"]
    for path in paths[:100]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            metrics = data.get("metrics", {}) if isinstance(data, dict) else {}
            # Accept both safety and semantic benchmark report schemas.
            total = metrics.get("total_cases", metrics.get("queries"))
            correct = metrics.get("passed_cases", metrics.get("correct_cases"))
            failed = metrics.get("failed_cases")
            accuracy = metrics.get("accuracy")
            primary_metric_name = "Accuracy"
            primary_metric = accuracy
            if primary_metric is None and metrics.get("hit_rate_at_k") is not None:
                primary_metric_name = f"Hit rate@{metrics.get('top_k', '?')}"
                primary_metric = metrics.get("hit_rate_at_k")
            if primary_metric is None and isinstance(total, (int, float)) and total and correct is not None:
                primary_metric = round(float(correct) / float(total), 4)
            reports.append({
                "name": str(path.relative_to(directory)),
                "evaluator": data.get("evaluator", data.get("retrieval_method", "built-in guardrails")),
                "total_cases": total,
                "primary_metric_name": primary_metric_name,
                "primary_metric": primary_metric,
                "failed_cases": failed if failed is not None else (total - correct if total is not None and correct is not None else None),
                "warning": data.get("warning", ""),
            })
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            errors.append(f"Skipped benchmark report {path.name}: {exc}")
    return reports, errors


def collect_dashboard_data(
    *,
    audit_path: str | Path | None = "logs/audit.jsonl",
    reports_dir: str | Path | None = "reports",
    evidence_store_path: str | Path | None = "data/evidence_store.json",
    event_limit: int = 100,
) -> dict[str, Any]:
    """Collect dashboard-safe metadata without surfacing raw prompts or outputs."""
    events, audit_errors = _load_audit(Path(audit_path) if audit_path else None, limit=max(event_limit, 1))
    benchmarks, benchmark_errors = _load_benchmarks(Path(reports_dir) if reports_dir else None)
    sources: list[dict[str, Any]] = []
    provenance_integrity: dict[str, Any] | None = None
    evidence_count = 0
    if evidence_store_path:
        store_path = Path(evidence_store_path)
        if store_path.exists():
            try:
                store = EvidenceStore(store_path)
                sources = store.source_manifest()
                provenance_integrity = store.verify_integrity()
                evidence_count = len(store.all_chunks())
            except (OSError, ValueError, TypeError) as exc:
                provenance_integrity = {"ok": False, "sources_checked": 0, "chunks_checked": 0, "errors": [{"type": "store_load_error", "message": str(exc)}], "note": "The evidence store could not be read."}
    all_events, _ = _load_audit(Path(audit_path) if audit_path else None, limit=1_000_000)
    audit_integrity = None
    if audit_path and Path(audit_path).exists():
        audit_integrity = verify_audit_log(audit_path)
    statuses = Counter(event.get("status") for event in all_events)
    event_types = Counter(event.get("event") for event in all_events)
    summary = {
        "events_total": len(all_events),
        "requests_allowed": sum(1 for event in all_events if event.get("event") == "model_request" and event.get("status") == "allow"),
        "requests_blocked": sum(1 for event in all_events if event.get("event") == "model_request" and event.get("status") == "blocked"),
        "actions_allowed": sum(1 for event in all_events if event.get("event") == "action_authorization" and event.get("status") == "allow"),
        "actions_blocked": sum(1 for event in all_events if event.get("event") == "action_authorization" and event.get("status") == "blocked"),
        "actions_review": sum(1 for event in all_events if event.get("event") == "action_authorization" and event.get("status") == "review"),
        "status_counts": dict(statuses),
        "event_type_counts": dict(event_types),
        "benchmark_count": len(benchmarks),
        "evidence_sources": len(sources),
        "evidence_chunks": evidence_count,
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "events": events[:event_limit],
        "benchmarks": benchmarks,
        "sources": sources,
        "provenance_integrity": provenance_integrity,
        "audit_integrity": audit_integrity,
        "warnings": audit_errors + benchmark_errors,
    }


def make_handler(*, audit_path: str | Path | None, reports_dir: str | Path | None, evidence_store_path: str | Path | None):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "EthicsBrainDashboard/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            # Avoid unnecessary request detail logging; standard server errors remain visible.
            return

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            route = urlparse(self.path).path
            if route == "/" or route == "/index.html":
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if route == "/health":
                self._send(200, b'{"ok":true}', "application/json; charset=utf-8")
                return
            if route in ("/api/summary", "/api/events", "/api/benchmarks", "/api/evidence"):
                data = collect_dashboard_data(audit_path=audit_path, reports_dir=reports_dir, evidence_store_path=evidence_store_path)
                if route == "/api/events":
                    output: Any = data["events"]
                elif route == "/api/benchmarks":
                    output = data["benchmarks"]
                elif route == "/api/evidence":
                    output = {"sources": data["sources"], "integrity": data["provenance_integrity"], "chunks": data["summary"]["evidence_chunks"]}
                else:
                    output = data
                body = json.dumps(output, ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
                return
            self._send(404, b'{"error":"not found"}', "application/json; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            self._send(405, b'{"error":"read-only dashboard"}', "application/json; charset=utf-8")

    return DashboardHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=Path(os.environ.get("ETHICSBRAIN_AUDIT_PATH", "logs/audit.jsonl")))
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"))
    parser.add_argument("--evidence-store", type=Path, default=Path("data/evidence_store.json"))
    parser.add_argument("--host", default="127.0.0.1", help="Defaults to loopback; do not expose without adding authentication/TLS")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: the reference dashboard has no authentication. Binding beyond loopback can expose metadata.")
    handler = make_handler(audit_path=args.audit, reports_dir=args.reports_dir, evidence_store_path=args.evidence_store)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"EthicsBrain dashboard listening on http://{args.host}:{args.port}")
    print("Read-only reference interface. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
