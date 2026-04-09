#!/usr/bin/env python3
"""
PostToolUse hook: validate artifacts written to .service-approval/.

Reads JSON from stdin (Claude Code hook protocol), dispatches to
validate_controls or validate_state based on file path.

Exit codes:
    0 — pass (or not our concern)
    2 — validation failed (errors on stderr for Claude to auto-fix)
"""

import json
import os
import sys

# Allow sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    if tool_name not in ("Write", "Edit"):
        sys.exit(0)

    tool_input = hook_input.get("tool_input", {})
    file_path = tool_input.get("file_path", "")
    if not file_path:
        sys.exit(0)

    norm = file_path.replace("\\", "/")

    if "/.service-approval/controls/" in norm or "/service-approval/controls/" in norm:
        from validate_controls import validate_file
        errors = validate_file(file_path)
    elif "/.service-approval/state/" in norm or "/service-approval/state/" in norm:
        from validate_state import validate_state_file
        errors = validate_state_file(file_path)
    else:
        sys.exit(0)

    if errors:
        print(f"HOOK VALIDATION FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
