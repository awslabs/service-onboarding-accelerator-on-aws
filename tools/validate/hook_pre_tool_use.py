#!/usr/bin/env python3
"""Reject downstream artifact writes when the AWS Threat Model input is absent."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_threat_model_input import check_artifact_prerequisite


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (ValueError, EOFError):
        return 0
    if event.get("tool_name") not in ("Write", "Edit", "fs_write"):
        return 0
    tool_input = event.get("tool_input", {})
    path = tool_input.get("file_path") or tool_input.get("path")
    if not isinstance(path, str) or not path:
        return 0
    errors = check_artifact_prerequisite(path)
    if errors:
        print("AWS THREAT MODEL REQUIRED — downstream write blocked.", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
