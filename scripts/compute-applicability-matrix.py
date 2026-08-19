#!/usr/bin/env python3
"""Compute the service applicability matrix from an AWS Threat Model threat model.

Screens framework objectives for applicability to a target service BEFORE
mapping. Three risk-averse principles, all encoded here so the decision is
auditable:

  1. Capability flags are derived from AWS Threat Model mitigation STATEMENTS only —
     never entity 'information'/description prose. A statement is a normative
     assertion about how the service must be configured; entity information is
     descriptive prose (e.g. a Layer "custom runtime ... reused across
     functions") that must NEVER assert a customer capability. Reading prose
     is what flipped a serverless service to customer-managed-patching.
  2. Each flag is three-valued — present / absent / unknown. An UNKNOWN
     capability never forces an objective N/A; it defers to the KB default.
     Only a POSITIVE structural reason (intrinsic org objective, or a category
     fact) marks an objective N/A.
  3. Every applicability decision cites the rule + evidence that drove it
     (`derived_from`) — there is no unexplained N/A.

Usage:
    python3 scripts/compute-applicability-matrix.py <threat-model-json> [--output <path>]
    python3 scripts/compute-applicability-matrix.py --slug <slug>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CAPABILITY_RULES = _REPO_ROOT / "data" / "service-capability-rules.json"
_CATEGORY_RULES = _REPO_ROOT / "data" / "service-category-rules.json"
_APPLICABILITY_RULES = _REPO_ROOT / "data" / "objective-applicability-rules.json"

sys.path.insert(0, str(_REPO_ROOT))
try:
    from tools import paths
except ImportError:
    print("ERROR: tools.paths module not found. Run from the repo root with the "
          "project venv.", file=sys.stderr)
    sys.exit(1)

# Three-valued capability state.
PRESENT = "present"
ABSENT = "absent"
UNKNOWN = "unknown"


def _load_json(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _mitigation_statements(threat_model: dict) -> list[str]:
    """Return the mitigation STATEMENTS only — entity prose is deliberately excluded."""
    out = []
    for m in threat_model.get("mitigations", []) or []:
        if isinstance(m, dict):
            stmt = m.get("statement")
            if isinstance(stmt, str) and stmt.strip():
                out.append(stmt)
    return out


def _matches_any(statements: list[str], patterns: list[str]) -> str | None:
    """Return the first statement matching any pattern (regex, case-insensitive), else None."""
    for stmt in statements:
        low = stmt.lower()
        for pat in patterns:
            if re.search(pat.lower(), low):
                return stmt
    return None


def derive_capabilities(threat_model: dict, capability_rules: dict) -> dict[str, dict]:
    """Derive three-valued capability flags from mitigation statements only.

    Returns capability_id -> {state, evidence} where state is present / absent /
    unknown and evidence is the statement that drove present/absent (None for
    unknown). Absent wins over present when both match (a statement may mention
    a capability only to say AWS owns it).
    """
    statements = _mitigation_statements(threat_model)
    caps: dict[str, dict] = {}
    for rule in capability_rules.get("capability_rules", []):
        cap_id = rule["capability_id"]
        absent_hit = _matches_any(statements, rule.get("absent_when", []) or [])
        present_hit = _matches_any(statements, rule.get("present_when", []) or [])
        if absent_hit:
            caps[cap_id] = {"state": ABSENT, "evidence": absent_hit}
        elif present_hit:
            caps[cap_id] = {"state": PRESENT, "evidence": present_hit}
        else:
            caps[cap_id] = {"state": UNKNOWN, "evidence": None}
    return caps


def _is_present(caps: dict[str, dict], cap_id: str) -> bool:
    return caps.get(cap_id, {}).get("state") == PRESENT


def derive_categories(caps: dict[str, dict], category_rules: dict) -> list[str]:
    """Derive the service's category label(s) from present capability flags.

    Multi-label: a service may match several category rules. A rule matches when
    all `all_present` flags are present, at least one `any_present` is present,
    none of `none_present` are present, and (when given) at least one
    `also_any_present` is present. Best-effort: no match simply yields no label.
    """
    cats: list[str] = []
    for rule in category_rules.get("category_rules", []):
        cond = rule.get("match_when", {})
        all_present = cond.get("all_present", [])
        any_present = cond.get("any_present", [])
        none_present = cond.get("none_present", [])
        also_any = cond.get("also_any_present", [])

        if all_present and not all(_is_present(caps, c) for c in all_present):
            continue
        if any_present and not any(_is_present(caps, c) for c in any_present):
            continue
        if none_present and any(_is_present(caps, c) for c in none_present):
            continue
        if also_any and not any(_is_present(caps, c) for c in also_any):
            continue
        cats.append(rule["category"])
    return cats


def evaluate_applicability(
    caps: dict[str, dict],
    categories: list[str],
    applicability_rules: dict,
) -> dict[str, dict]:
    """Evaluate per-objective applicability. Only positive structural reasons
    mark N/A; unknown capability defers to the KB default (no entry emitted).

    Precedence for an objective touched by both a category_na rule and a
    capability_unlock rule: a definitively PRESENT unlock capability wins (the
    service demonstrably has the capability), so the objective stays applicable.
    """
    result: dict[str, dict] = {}

    # 1. Intrinsic N/A — always, capability-independent.
    for rule in applicability_rules.get("intrinsic_na_rules", []):
        for oid in rule.get("objective_ids", []):
            result[oid] = {
                "applicable": False,
                "reason": rule.get("reason", ""),
                "max_coverage": None,
                "category": rule.get("category", "intrinsic"),
                "derived_from": {"rule": "intrinsic_na", "category": rule.get("category", "")},
            }

    # 2. Capability-unlock — record which objectives have a PRESENT unlock, so a
    #    category_na rule cannot override a demonstrated capability.
    unlocked: dict[str, dict] = {}
    for rule in applicability_rules.get("capability_unlock_rules", []):
        req = rule.get("requires_any_capability", [])
        present_caps = [c for c in req if _is_present(caps, c)]
        if not present_caps:
            continue  # absent/unknown -> no override; KB default stands.
        for oid in rule.get("objective_ids", []):
            unlocked[oid] = {
                "applicable": True,
                "reason": rule.get("reason_when_present", ""),
                "max_coverage": rule.get("max_coverage"),
                "category": "capability_unlock",
                "derived_from": {
                    "rule": "capability_unlock",
                    "capability": present_caps[0],
                    "evidence": caps.get(present_caps[0], {}).get("evidence"),
                },
            }

    # 3. Category N/A — fires only when the service carries a listed category AND
    #    the objective is not unlocked by a present capability.
    for rule in applicability_rules.get("category_na_rules", []):
        na_cats = set(rule.get("na_for_categories", []))
        hit_cat = na_cats & set(categories)
        if not hit_cat:
            continue
        for oid in rule.get("objective_ids", []):
            if oid in unlocked:
                continue  # present capability beats the category fact.
            result[oid] = {
                "applicable": False,
                "reason": rule.get("reason", ""),
                "max_coverage": None,
                "category": sorted(hit_cat)[0],
                "derived_from": {
                    "rule": "category_na",
                    "category": sorted(hit_cat)[0],
                },
            }

    # Unlock entries win over any category_na entry written above.
    result.update(unlocked)
    return result


def compute_matrix(threat_model_path: Path, output_path: Path | None = None) -> dict:
    threat_model = _load_json(threat_model_path)
    capability_rules = _load_json(_CAPABILITY_RULES)
    category_rules = _load_json(_CATEGORY_RULES)
    applicability_rules = _load_json(_APPLICABILITY_RULES)

    service_name = (threat_model.get("metadata") or {}).get("name", "unknown")

    caps = derive_capabilities(threat_model, capability_rules)
    categories = derive_categories(caps, category_rules)
    objective_applicability = evaluate_applicability(caps, categories, applicability_rules)

    present = sorted(k for k, v in caps.items() if v["state"] == PRESENT)
    absent = sorted(k for k, v in caps.items() if v["state"] == ABSENT)
    unknown = sorted(k for k, v in caps.items() if v["state"] == UNKNOWN)

    result = {
        "schema_version": "2.0",
        "service": service_name,
        "source_file": threat_model_path.name,
        "service_categories": categories,
        "derived_capabilities": {
            "present": present,
            "absent": absent,
            "unknown": unknown,
            "evidence": {k: v["evidence"] for k, v in caps.items() if v["evidence"]},
        },
        "objective_applicability": objective_applicability,
        "summary": {
            "total_objectives_screened": len(objective_applicability),
            "not_applicable": sum(
                1 for v in objective_applicability.values() if not v["applicable"]
            ),
            "unlocked_applicable": sum(
                1 for v in objective_applicability.values() if v["applicable"]
            ),
            "note": "Objectives not listed here defer to the KB default (unknown never forces N/A).",
        },
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print(
            f"Applicability matrix written: {output_path}\n"
            f"  Service: {service_name}\n"
            f"  Categories: {categories or '(none derived)'}\n"
            f"  Capabilities present/absent/unknown: "
            f"{len(present)}/{len(absent)}/{len(unknown)}\n"
            f"  Objectives forced N/A: {result['summary']['not_applicable']}",
            file=sys.stderr,
        )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("threat_model_json", nargs="?", help="Path to AWS Threat Model threat model JSON")
    parser.add_argument("--slug", help="Service slug (looks in .service-approval/<slug>/input/)")
    parser.add_argument("--output", "-o", help="Output path (default: stdout JSON)")
    args = parser.parse_args()

    if args.slug:
        try:
            svc_root = paths.service_root(args.slug)
        except paths.PathResolutionError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)
        input_dir = svc_root / "input"
        candidates = list(input_dir.glob("*.json")) if input_dir.exists() else []
        if not candidates:
            print(f"SKIP: no JSON files in {input_dir}", file=sys.stderr)
            sys.exit(0)
        threat_model_path = candidates[0]
        output_path: Path | None = svc_root / "04-map" / "applicability-matrix.json"
    elif args.threat_model_json:
        threat_model_path = Path(args.threat_model_json)
        output_path = Path(args.output) if args.output else None
    else:
        parser.error("Provide an AWS Threat Model JSON path or --slug")
        return

    if not threat_model_path.exists():
        print(f"ERROR: file not found: {threat_model_path}", file=sys.stderr)
        sys.exit(1)

    result = compute_matrix(threat_model_path, output_path)
    if not output_path:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
