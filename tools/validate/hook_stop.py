#!/usr/bin/env python3
"""
Stop hook: cross-artifact validation after generation phase.

Runs validate_cross.py against .service-approval/<slug>/05-generate/ when Claude
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

from _hook_log import log_hook_fire  # noqa: E402


def main():
    cwd = os.getcwd()
    output_dir = os.path.join(cwd, ".service-approval")
    if not os.path.isdir(output_dir):
        sys.exit(0)

    # Find all service directories with controls
    service_dirs = []
    for item in os.listdir(output_dir):
        if item.startswith("_") or item == "plans":
            continue
        service_path = os.path.join(output_dir, item)
        if not os.path.isdir(service_path):
            continue
        # Check for 05-generate/ with actual control files
        controls_dir = os.path.join(service_path, "05-generate")
        if os.path.isdir(controls_dir):
            has_controls = any(
                os.path.isdir(os.path.join(controls_dir, subdir))
                for subdir in ("preventive", "detective", "responsive", "proactive")
            )
            if has_controls:
                service_dirs.append(controls_dir)

    if not service_dirs:
        sys.exit(0)

    # --- Run validations for each service ---
    from validate_cross import validate_all
    from validate_deployable import validate_deployable, check_aws_credentials
    from validate_pipeline_integrity import validate_pipeline
    from pathlib import Path

    has_creds, _ = check_aws_credentials()
    cross_errors = []
    deploy_errors = []

    for controls_dir in service_dirs:
        # Cross-validation
        cross_errors.extend(validate_all(controls_dir))

        # Deployability validation
        deploy_errors.extend(
            validate_deployable(controls_dir, tier1_only=(not has_creds))
        )

    # Pipeline integrity validation (runs once per repo, iterates services internally)
    integrity_errors = validate_pipeline(Path(cwd))

    all_errors = cross_errors + deploy_errors + integrity_errors

    if not all_errors:
        # Log a pass entry to each service's log so the audit trail isn't
        # silent on a clean run.
        for controls_dir in service_dirs:
            # controls_dir = .../service-approval/<slug>/05-generate
            log_hook_fire(
                "stop",
                "pass",
                "all integrity + cross + deploy checks passed",
                file_path=controls_dir,
            )
        sys.exit(0)

    # Strict-by-default: integrity failures always block.
    # Set VALIDATE_STRICT=0 to fall back to warn-only for cross/deploy checks.
    strict = os.environ.get("VALIDATE_STRICT", "1") != "0" or \
             os.environ.get("VALIDATE_CROSS_STRICT", "0") == "1" or \
             os.environ.get("VALIDATE_DEPLOYABLE_STRICT", "0") == "1" or \
             bool(integrity_errors)

    if strict:
        # Block: send errors to stderr so Claude can auto-fix
        if integrity_errors:
            print(f"PIPELINE INTEGRITY FAILED ({len(integrity_errors)} errors):", file=sys.stderr)
            for e in integrity_errors:
                print(f"  {e}", file=sys.stderr)
        if cross_errors:
            print(f"CROSS-VALIDATION FAILED ({len(cross_errors)} errors):", file=sys.stderr)
            for e in cross_errors:
                print(f"  {e}", file=sys.stderr)
        if deploy_errors:
            print(f"DEPLOYABILITY VALIDATION FAILED ({len(deploy_errors)} errors):", file=sys.stderr)
            for e in deploy_errors:
                print(f"  {e}", file=sys.stderr)
        # Log to each service's audit trail so a post-mortem can find the
        # exact failures without re-grepping the session JSONL.
        for controls_dir in service_dirs:
            log_hook_fire(
                "stop",
                "fail",
                f"integrity={len(integrity_errors)} cross={len(cross_errors)} "
                f"deploy={len(deploy_errors)}",
                file_path=controls_dir,
                extra={
                    "first_integrity": integrity_errors[0][:200] if integrity_errors else None,
                    "first_cross": cross_errors[0][:200] if cross_errors else None,
                    "first_deploy": deploy_errors[0][:200] if deploy_errors else None,
                },
            )
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
        for controls_dir in service_dirs:
            log_hook_fire(
                "stop",
                "warn",
                f"cross={len(cross_errors)} deploy={len(deploy_errors)} "
                f"(non-strict mode)",
                file_path=controls_dir,
            )
        print(json.dumps(result))
        sys.exit(0)


if __name__ == "__main__":
    main()
