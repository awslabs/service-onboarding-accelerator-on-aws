#!/usr/bin/env python3
"""
Stop hook: cross-artifact validation after generation phase.

Runs validate_cross.py against .service-approval/controls/ when Claude
signals completion. Only fires if controls directory exists.

Reports warnings to stdout (non-blocking) by default. Set environment
variable VALIDATE_CROSS_STRICT=1 to block on errors (exit 2).

Exit codes:
    0 — pass, or warnings reported (non-blocking)
    2 — strict mode: cross-validation failed (errors on stderr)
"""

import json
import os
import sys

# Allow sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    cwd = os.getcwd()
    controls_dir = os.path.join(cwd, ".service-approval", "controls")
    if not os.path.isdir(controls_dir):
        sys.exit(0)

    # Only run if there are actual control files (not just iac/)
    has_controls = False
    for subdir in ("preventive", "detective", "remediation", "proactive"):
        if os.path.isdir(os.path.join(controls_dir, subdir)):
            has_controls = True
            break

    if not has_controls:
        sys.exit(0)

    # --- Cross-validation ---
    from validate_cross import validate_all
    cross_errors = validate_all(controls_dir)

    # --- Deployability validation ---
    from validate_deployable import validate_deployable, check_aws_credentials

    has_creds, _ = check_aws_credentials()
    deploy_errors = validate_deployable(
        controls_dir, tier1_only=(not has_creds),
    )

    all_errors = cross_errors + deploy_errors

    if not all_errors:
        sys.exit(0)

    strict = os.environ.get("VALIDATE_CROSS_STRICT", "0") == "1" or \
             os.environ.get("VALIDATE_DEPLOYABLE_STRICT", "0") == "1"

    if strict:
        # Block: send errors to stderr so Claude can auto-fix
        if cross_errors:
            print(f"CROSS-VALIDATION FAILED ({len(cross_errors)} errors):", file=sys.stderr)
            for e in cross_errors:
                print(f"  {e}", file=sys.stderr)
        if deploy_errors:
            print(f"DEPLOYABILITY VALIDATION FAILED ({len(deploy_errors)} errors):", file=sys.stderr)
            for e in deploy_errors:
                print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    else:
        # Non-blocking: report via stdout JSON for Claude's awareness
        result = {}
        if cross_errors:
            result["cross_validation"] = {
                "decision": "warn",
                "reason": f"Cross-validation found {len(cross_errors)} issue(s). "
                          "Set VALIDATE_CROSS_STRICT=1 to block.",
                "errors": cross_errors,
            }
        if deploy_errors:
            result["deployability"] = {
                "decision": "warn",
                "reason": f"Deployability validation found {len(deploy_errors)} issue(s). "
                          "Set VALIDATE_DEPLOYABLE_STRICT=1 to block.",
                "errors": deploy_errors,
            }
        if not has_creds:
            result["tier2_skipped"] = True
            result["tier2_fix"] = "Run: aws sso login --profile delegated-admin"
        print(json.dumps(result))
        sys.exit(0)


if __name__ == "__main__":
    main()
