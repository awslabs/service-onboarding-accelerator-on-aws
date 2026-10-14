#!/usr/bin/env python3
"""Fetch the latest published AWS Threat Model and print an intake inputs fragment."""
import argparse
import json
import sys
from pathlib import Path

from threat_model_source import SourceError, atomic_write, save_latest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    parser.add_argument("--output", type=Path, help="Optional path for the inputs fragment (under .service-approval)")
    args = parser.parse_args()
    if args.output and not args.output.resolve().is_relative_to((Path.cwd() / ".service-approval").resolve()):
        parser.error("--output must be under the workspace's ignored .service-approval directory")
    try:
        inputs = save_latest(args.service, Path.cwd())
        result = json.dumps(inputs, indent=2) + "\n"
        if args.output:
            atomic_write(args.output, result.encode())
        print(result, end="")
    except (SourceError, OSError) as exc:
        print(f"AWS THREAT MODEL REQUIRED — pipeline cannot start: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
