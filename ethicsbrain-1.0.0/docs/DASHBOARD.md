# EthicsBrain v1.0.0 Safety Monitoring Dashboard

## Start the local dashboard

From the repository root:

```powershell
python -m ethicsbrain.dashboard `
  --audit logs/audit.jsonl `
  --reports-dir reports `
  --evidence-store data/evidence_store.json `
  --host 127.0.0.1 `
  --port 8765
```

Open `http://127.0.0.1:8765`. Stop the server with Ctrl+C. The dashboard refreshes every 15 seconds and has no third-party runtime dependencies.

## What it shows

- Audit event totals; model requests allowed/blocked; tool actions allowed/blocked/reviewed.
- Recent event metadata with request IDs, status, and rule IDs.
- Benchmark metrics from matching `*_benchmark.json` files under the reports directory.
- Evidence source manifest: publisher/title/date fields as supplied, document hash, and chunk count.
- On-demand evidence store integrity checks: document hashes, chunk hashes, and text offsets.

The viewer is read-only. It deliberately filters arbitrary audit `extra` data and does not display raw prompts or completions. It can show only events your application actually writes to the configured audit file; it is not an operating-system-wide monitor.

## Security constraints

- Default binding is loopback (`127.0.0.1`). Keep it there for local development.
- This reference dashboard has no authentication and no TLS. Do not bind it to a LAN, public interface, shared host, or cloud environment as-is.
- If remote access is required, place it behind authenticated access control and TLS, restrict network access, review logs for sensitive metadata, and deploy a hardened server.
- Audit files and benchmark reports can contain request IDs and policy details. Protect them and apply retention limits.
- The dashboard reports recorded decisions and benchmark outputs; it does not prove the underlying model is safe.
