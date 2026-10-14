"""Verify the hash chain in an existing EthicsBrain JSONL audit log."""
from __future__ import annotations

import sys

from ethicsbrain.audit import verify_audit_log

if len(sys.argv) != 2:
    raise SystemExit("Usage: python examples/verify_audit_log.py PATH_TO_AUDIT_JSONL")

report = verify_audit_log(sys.argv[1])
print(report)
if not report["ok"]:
    raise SystemExit(1)
