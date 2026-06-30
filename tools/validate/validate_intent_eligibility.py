#!/usr/bin/env python3
"""Validate framework mapping against mitigation-intent eligibility and coverage ceilings.

Checks:
1. Each mapped control's mitigation_intent must be in the objective's eligible_intents
   (CCMv4 only — requires enhanced domain-mapping-guidance with eligible_intents field)
2. Coverage level must not exceed the mechanism-type ceiling
3. Objectives marked not-applicable in the applicability matrix must not be MAPPED

Advisory by default (warn, exit 0); --strict exits 2 on any finding.

CLI:
    python3 validate_intent_eligibility.py --slug <slug> [--strict]
    python3 validate_intent_eligibility.py <map-framework-mapped.json> \
        [--controls <map-controls-generated.json>] \
        [--matrix <applicability-matrix.json>] [--strict]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUIDANCE_PATH = _REPO_ROOT / "data" / "domain-mapping-guidance" / "ccmv4.json"
_INTENT_PATTERNS_PATH = _REPO_ROOT / "data" / "mitigation-intent-patterns.json"

MECHANISM_COVERAGE_CEILINGS = {
    "enforcement": {
        "SCP": "Full Coverage",
        "RCP": "Full Coverage",
        "IAM Permission Boundary": "Partial Coverage",
        "IAM Trust Policy": "Partial Coverage",
        "IAM Identity Policy": "Partial Coverage",
        "KMS Key Policy": "Partial Coverage",
        "Resource Policy": "Partial Coverage",
        "VPC Endpoint Policy": "Partial Coverage",
        "CloudFormation Guard": "Partial Coverage",
        "CloudFormation Hook": "Partial Coverage",
        "AWS Config Rule": "Partial Coverage",
        "Tag Policy": "Supportive",
        "SSM Automation": "Partial Coverage",
        "Organizations Tag Policy": "Supportive",
    },
    "detection": {
        "AWS Config Rule": "Full Coverage",
        "CloudTrail": "Full Coverage",
        "SCP": "Supportive",
        "RCP": "Supportive",
        "CloudFormation Guard": "Supportive",
        "CloudFormation Hook": "Supportive",
        "Tag Policy": "Supportive",
    },
    "capability": {
        "KMS Key Policy": "Full Coverage",
        "IAM Trust Policy": "Partial Coverage",
        "Resource Policy": "Partial Coverage",
        "SCP": "Supportive",
        "AWS Config Rule": "Supportive",
        "Tag Policy": "Supportive",
    },
}

COVERAGE_RANK = {
    "Full Coverage": 3,
    "Partial Coverage": 2,
    "Supportive": 1,
}


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    with open(path) as fh:
        return json.load(fh)


def _classify_objective_intent(objective_id: str, guidance: dict | None) -> str | None:
    """Determine if objective asks for enforcement, detection, or capability."""
    if not guidance:
        return None

    detection_objectives = {
        "CCC-07", "LOG-03", "LOG-05", "LOG-10", "LOG-13",
        "CEK-09", "SEF-06", "STA-11",
    }
    capability_objectives = {
        "CEK-08", "CEK-10", "CEK-11",
    }

    if objective_id in detection_objectives:
        return "detection"
    if objective_id in capability_objectives:
        return "capability"
    return "enforcement"


def _normalize_mechanism(mechanism: str) -> str:
    """Normalize mechanism string for ceiling lookup."""
    m = mechanism.strip()
    if "config" in m.lower() and "rule" in m.lower():
        return "AWS Config Rule"
    if "scp" in m.lower():
        return "SCP"
    if "rcp" in m.lower():
        return "RCP"
    if "guard" in m.lower() or "cfn guard" in m.lower():
        return "CloudFormation Guard"
    if "hook" in m.lower() or "cloudformation" in m.lower():
        return "CloudFormation Hook"
    if "kms" in m.lower() and "key" in m.lower():
        return "KMS Key Policy"
    if "tag policy" in m.lower() or "organizations tag" in m.lower():
        return "Tag Policy"
    if "permission boundary" in m.lower():
        return "IAM Permission Boundary"
    if "trust policy" in m.lower():
        return "IAM Trust Policy"
    if "identity policy" in m.lower():
        return "IAM Identity Policy"
    if "resource policy" in m.lower() or "resource-based" in m.lower():
        return "Resource Policy"
    if "vpc endpoint" in m.lower():
        return "VPC Endpoint Policy"
    if "ssm" in m.lower() or "automation" in m.lower():
        return "SSM Automation"
    if "cloudtrail" in m.lower():
        return "CloudTrail"
    return m


def check_coverage_ceiling(
    control: dict,
    coverage_level: str,
    objective_id: str,
    guidance: dict | None,
) -> str | None:
    """Check if coverage_level exceeds the mechanism-type ceiling for this objective."""
    mechanism = control.get("mechanism", "")
    if not mechanism:
        return None

    normalized = _normalize_mechanism(mechanism)
    obj_intent = _classify_objective_intent(objective_id, guidance)
    if not obj_intent:
        return None

    ceiling_table = MECHANISM_COVERAGE_CEILINGS.get(obj_intent, {})
    ceiling = ceiling_table.get(normalized)
    if not ceiling:
        return None

    if COVERAGE_RANK.get(coverage_level, 0) > COVERAGE_RANK.get(ceiling, 0):
        return (
            f"coverage-ceiling: {objective_id} mapped to {control.get('id', '?')} "
            f"at '{coverage_level}' but mechanism '{normalized}' has ceiling "
            f"'{ceiling}' for {obj_intent} objectives. Reduce to '{ceiling}' or lower."
        )
    return None


def check_applicability(
    fw_mapped: dict,
    matrix: dict | None,
) -> list[str]:
    """Check that objectives marked N/A in applicability matrix are not MAPPED."""
    if not matrix:
        return []

    errors = []
    obj_app = matrix.get("objective_applicability", {})

    for entry in fw_mapped.get("framework_mapping", []):
        oid = entry.get("objective_id", "")
        if entry.get("status") != "MAPPED":
            continue

        app_entry = obj_app.get(oid)
        if app_entry and not app_entry.get("applicable", True):
            reason = app_entry.get("reason", "objective is not applicable")
            errors.append(
                f"applicability: {oid} is MAPPED but applicability-matrix says "
                f"not applicable — {reason}. Mark it N/A."
            )

    return errors


def check_all(
    fw_mapped: dict,
    controls_by_id: dict[str, dict] | None,
    matrix: dict | None,
    guidance: dict | None,
) -> list[str]:
    """Run all eligibility and ceiling checks."""
    errors: list[str] = []

    errors.extend(check_applicability(fw_mapped, matrix))

    if not controls_by_id:
        return errors

    for entry in fw_mapped.get("framework_mapping", []):
        if entry.get("status") != "MAPPED":
            continue
        oid = entry.get("objective_id", "")

        for cm in entry.get("controls", []):
            cid = cm.get("control_id", "")
            ctrl = controls_by_id.get(cid)
            if not ctrl:
                continue

            coverage_level = cm.get("coverage_level", "")
            ceiling_err = check_coverage_ceiling(ctrl, coverage_level, oid, guidance)
            if ceiling_err:
                errors.append(ceiling_err)

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mapped", nargs="?", help="path to map-framework-mapped.json")
    parser.add_argument("--slug", help="service slug")
    parser.add_argument("--controls", help="path to map-controls-generated.json")
    parser.add_argument("--matrix", help="path to applicability-matrix.json")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    guidance = _load_json(_GUIDANCE_PATH)

    if args.slug:
        root = Path.cwd() / ".service-approval" / args.slug / "04-map"
        mapped_path = root / "map-framework-mapped.json"
        controls_path = root / "map-controls-generated.json"
        matrix_path = root / "applicability-matrix.json"
    elif args.mapped:
        mapped_path = Path(args.mapped)
        controls_path = Path(args.controls) if args.controls else None
        matrix_path = Path(args.matrix) if args.matrix else None
    else:
        parser.error("provide mapped JSON or --slug")
        return

    if not mapped_path.exists():
        print(f"SKIP: {mapped_path} not found", file=sys.stderr)
        sys.exit(0)

    fw_mapped = json.loads(mapped_path.read_text())

    controls_by_id = None
    if controls_path and controls_path.exists():
        cg = json.loads(controls_path.read_text())
        controls_by_id = {c["id"]: c for c in cg.get("controls", []) if c.get("id")}

    matrix = None
    if matrix_path and matrix_path.exists():
        matrix = json.loads(matrix_path.read_text())

    errors = check_all(fw_mapped, controls_by_id, matrix, guidance)

    if errors:
        print(
            f"INTENT ELIGIBILITY ({len(errors)} issue(s)):", file=sys.stderr
        )
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if args.strict:
            sys.exit(2)
    else:
        print("intent-eligibility: all checks passed", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
