#!/usr/bin/env python3
"""Compute the service applicability matrix from a Canopy threat model JSON.

Derives service capabilities by scanning mitigations and entities, then
evaluates objective-applicability-rules to determine which framework
objectives are applicable to the target service.

Usage:
    python3 scripts/compute-applicability-matrix.py <canopy-json> [--output <path>]
    python3 scripts/compute-applicability-matrix.py --slug <slug>

The Canopy JSON is the threat model export (with mitigations[], entities[],
threats[], implementations[] at top level).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CLASSIFICATION_RULES = _REPO_ROOT / "data" / "service-classification-rules.json"
_APPLICABILITY_RULES = _REPO_ROOT / "data" / "objective-applicability-rules.json"


def _load_json(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _text_matches_any(text: str, patterns: list[str]) -> bool:
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern.lower(), text_lower):
            return True
    return False


def derive_capabilities(canopy: dict, rules: dict) -> dict[str, bool]:
    """Scan Canopy mitigations and entities to derive service capabilities."""
    capabilities: dict[str, bool] = {}

    mitigation_statements = []
    for m in canopy.get("mitigations", []):
        stmt = m.get("statement", "")
        if stmt:
            mitigation_statements.append(stmt)

    entity_infos = []
    for e in canopy.get("entities", []):
        info = e.get("information", "")
        if info:
            entity_infos.append(info)

    all_mitigation_text = " ".join(mitigation_statements)
    all_entity_text = " ".join(entity_infos)

    for rule in rules.get("capability_rules", []):
        cap_id = rule["capability_id"]
        detect = rule.get("detect_by", {})

        found = False

        stmt_patterns = detect.get("mitigation_statement_contains_any", [])
        if stmt_patterns:
            for stmt in mitigation_statements:
                if _text_matches_any(stmt, stmt_patterns):
                    found = True
                    break

        if not found:
            entity_patterns = detect.get("entity_information_contains_any", [])
            if entity_patterns:
                for info in entity_infos:
                    if _text_matches_any(info, entity_patterns):
                        found = True
                        break

        capabilities[cap_id] = found

    return capabilities


def evaluate_applicability(
    capabilities: dict[str, bool],
    applicability_rules: dict,
) -> dict[str, dict]:
    """Evaluate which objectives are applicable given derived capabilities."""
    objective_applicability: dict[str, dict] = {}

    for rule in applicability_rules.get("rules", []):
        condition = rule.get("applicable_when", "never")
        reason = rule.get("reason", "")
        max_cov = rule.get("max_coverage", None)
        objective_ids = rule.get("objective_ids", [])
        exceptions = rule.get("exceptions", {})

        applicable = _evaluate_condition(condition, capabilities)

        for oid in objective_ids:
            if oid.endswith("*"):
                continue

            if oid in exceptions:
                exc = exceptions[oid]
                exc_applicable = _evaluate_condition(
                    exc.get("applicable_when", "never"), capabilities
                )
                objective_applicability[oid] = {
                    "applicable": exc_applicable,
                    "reason": exc.get("reason", reason),
                    "max_coverage": exc.get("max_coverage", max_cov),
                    "category": rule.get("category", ""),
                }
            else:
                objective_applicability[oid] = {
                    "applicable": applicable,
                    "reason": reason if not applicable else None,
                    "max_coverage": max_cov,
                    "category": rule.get("category", ""),
                }

    return objective_applicability


def _evaluate_condition(condition: str, capabilities: dict[str, bool]) -> bool:
    if condition == "never" or condition == "never_for_infra_controls":
        return False
    if condition == "always":
        return True

    if condition.startswith("service_has_capability:"):
        cap_expr = condition[len("service_has_capability:"):]
        return _eval_capability_expr(cap_expr, capabilities)

    if " OR " in condition:
        parts = condition.split(" OR ")
        return any(_evaluate_condition(p.strip(), capabilities) for p in parts)

    return False


def _eval_capability_expr(expr: str, capabilities: dict[str, bool]) -> bool:
    if " OR " in expr:
        parts = expr.split(" OR ")
        return any(_eval_capability_expr(p.strip(), capabilities) for p in parts)

    if expr.endswith(":*"):
        prefix = expr[:-1]
        return any(
            v for k, v in capabilities.items() if k.startswith(prefix)
        )

    return capabilities.get(expr, False)


def compute_matrix(canopy_path: Path, output_path: Path | None = None) -> dict:
    """Main entry: compute applicability matrix from Canopy JSON."""
    canopy = _load_json(canopy_path)
    classification_rules = _load_json(_CLASSIFICATION_RULES)
    applicability_rules = _load_json(_APPLICABILITY_RULES)

    service_name = canopy.get("metadata", {}).get("name", "unknown")

    capabilities = derive_capabilities(canopy, classification_rules)
    objective_applicability = evaluate_applicability(capabilities, applicability_rules)

    present_caps = {k: v for k, v in capabilities.items() if v}
    absent_caps = {k: v for k, v in capabilities.items() if not v}

    result = {
        "schema_version": "1.0",
        "service": service_name,
        "source_file": str(canopy_path.name),
        "derived_capabilities": {
            "present": sorted(present_caps.keys()),
            "absent": sorted(absent_caps.keys()),
        },
        "objective_applicability": objective_applicability,
        "summary": {
            "total_objectives_evaluated": len(objective_applicability),
            "applicable": sum(
                1 for v in objective_applicability.values() if v["applicable"]
            ),
            "not_applicable": sum(
                1 for v in objective_applicability.values() if not v["applicable"]
            ),
        },
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print(
            f"Applicability matrix written: {output_path}\n"
            f"  Service: {service_name}\n"
            f"  Capabilities present: {len(present_caps)}\n"
            f"  Objectives applicable: {result['summary']['applicable']}\n"
            f"  Objectives N/A: {result['summary']['not_applicable']}",
            file=sys.stderr,
        )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("canopy_json", nargs="?", help="Path to Canopy threat model JSON")
    parser.add_argument("--slug", help="Service slug (looks in .service-approval/<slug>/input/)")
    parser.add_argument("--output", "-o", help="Output path (default: stdout JSON)")
    args = parser.parse_args()

    if args.slug:
        input_dir = Path.cwd() / ".service-approval" / args.slug / "input"
        candidates = list(input_dir.glob("*.json"))
        if not candidates:
            print(f"ERROR: no JSON files in {input_dir}", file=sys.stderr)
            sys.exit(1)
        canopy_path = candidates[0]
        output_path = (
            Path.cwd()
            / ".service-approval"
            / args.slug
            / "04-map"
            / "applicability-matrix.json"
        )
    elif args.canopy_json:
        canopy_path = Path(args.canopy_json)
        output_path = Path(args.output) if args.output else None
    else:
        parser.error("Provide a Canopy JSON path or --slug")
        return

    if not canopy_path.exists():
        print(f"ERROR: file not found: {canopy_path}", file=sys.stderr)
        sys.exit(1)

    result = compute_matrix(canopy_path, output_path)

    if not output_path:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
