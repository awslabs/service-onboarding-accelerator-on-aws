#!/usr/bin/env python3
"""Recompute advisory model findings and inject deterministic disclosure into reports."""
import argparse
from pathlib import Path
import re
import sys

from threat_model_integrity import write_audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.slug):
        parser.error("invalid service slug")
    root = Path.cwd() / ".service-approval" / args.slug
    try:
        audit = write_audit(root)
    except (OSError, ValueError) as exc:
        print(f"Cannot audit threat model: {exc}", file=sys.stderr)
        return 2
    print(f"AWS Threat Model integrity: {len(audit['findings'])} advisory findings, {len(audit['repairs'])} recorded repairs. See {root / 'threat-model-integrity.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
