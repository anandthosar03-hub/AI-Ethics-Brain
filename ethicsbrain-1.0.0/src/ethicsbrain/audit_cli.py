"""Verify a local EthicsBrain audit hash chain."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .audit import verify_audit_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Path to JSONL audit log")
    args = parser.parse_args(argv)
    result = verify_audit_log(args.path)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
