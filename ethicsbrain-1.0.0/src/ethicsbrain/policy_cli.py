"""Command-line utilities for validating and creating EthicsBrain policy files."""
from __future__ import annotations

import argparse
from pathlib import Path

from .policy import Policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate_parser = commands.add_parser("validate", help="validate a JSON policy")
    validate_parser.add_argument("path", type=Path)
    default_parser = commands.add_parser("create-default", help="write a default policy JSON file")
    default_parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    if args.command == "create-default":
        Policy().save_json(args.path)
        print(f"Wrote default policy to {args.path}")
        print("The default policy has an empty action allowlist; register no tools until explicitly configured.")
        return 0

    try:
        policy = Policy.from_json(args.path)
    except ValueError as exc:
        print(f"Invalid policy: {exc}")
        return 2
    print(f"Policy valid: {args.path}")
    print(f"Policy version: {policy.version}")
    print(f"Grounding mode: {policy.grounding_mode}")
    print(f"Allowlisted actions: {len(policy.allowed_actions or []) if policy.allowed_actions is not None else 'OPEN (not recommended)'}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
