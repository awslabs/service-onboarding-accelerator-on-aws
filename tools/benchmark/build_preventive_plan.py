#!/usr/bin/env python3
"""
Build a preventive-plan.json from a mapping + validated pair (deterministic part).

This is the deterministic core of the generate-preventive-recommend skill: given
the PRV controls and the verified condition keys, it computes each control's
preventability verdict (root-cause check) and, for feasible controls, ranks the
reference examples and picks the best anchor. The result is a schema-valid
preventive-plan.json.

It exists so the iteration harness can produce a baseline plan reproducibly (and
so the recommender skill has a reference implementation of its deterministic
steps). The skill still owns the judgement calls — doc-citation overrides for
condition keys absent from the SAR snapshot, anchor sanity — but the mechanical
verdict+anchor selection is here, tested, and identical every run.

CLI:
    python3 build_preventive_plan.py --mapping <mapping-results.json> \
        --validated <validated.json> --out <preventive-plan.json>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_TOOLS))
sys.path.insert(0, str(_TOOLS / "validate"))

import reference_index as ri  # noqa: E402
from validate_preventability import assess_control  # noqa: E402


_DECISION_BY_MECHANISM = {
    "SCP": "GENERATE_SCP",
    "RCP": "GENERATE_RCP",
}


def _generate_decision(mechanism: str) -> str:
    """Map a mechanism to its GENERATE_* decision (IAM family → GENERATE_IAM)."""
    return _DECISION_BY_MECHANISM.get(mechanism, "GENERATE_IAM")


def build_plan(mapping: dict, validated: dict) -> dict:
    """Return a schema-valid preventive-plan.json structure for the PRV controls."""
    decisions = []
    for control in mapping.get("controls", []):
        if (control.get("category") or "").upper() != "PRV":
            continue
        verdict = assess_control(control, validated)
        mechanism = control.get("mechanism", "")
        cid = control.get("id")

        if verdict["verdict"] == "NOT_PREVENTABLE":
            decisions.append({
                "control_id": cid,
                "mechanism": mechanism,
                "preventable": False,
                "decision": "ROUTE_DETECTIVE",
                "anchor": None,
                "route_to": "detective",
                "rationale": verdict["reason"],
            })
            continue

        keys = verdict["enforcing_condition_keys"]
        best = ri.best_anchor(mechanism, control.get("actions", []), keys)
        if best is None:
            decisions.append({
                "control_id": cid,
                "mechanism": mechanism,
                "preventable": True,
                "enforcing_condition_keys": keys,
                "decision": "REFER_TO_REFERENCE",
                "anchor": None,
                "route_to": None,
                "rationale": "preventable, but no reference example overlaps this "
                             "control's actions/keys — point the customer at the "
                             "closest reference rather than authoring",
            })
            continue

        decisions.append({
            "control_id": cid,
            "mechanism": mechanism,
            "preventable": True,
            "enforcing_condition_keys": keys,
            "decision": _generate_decision(mechanism),
            "anchor": {
                "example_id": best["id"],
                "repo": best["repo"],
                "url": best["source_url"],
            },
            "route_to": None,
            "rationale": f"condition key gates the target action; anchored to {best['id']}",
        })

    return {
        "_metadata": {
            "service": mapping.get("service", validated.get("service", "unknown")),
            "generated": "service-approval v3.0.0",
            "reference_index_version": ri.load_index().get("version", 1),
        },
        "decisions": decisions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", required=True)
    parser.add_argument("--validated", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    mapping = json.loads(Path(args.mapping).read_text())
    validated = json.loads(Path(args.validated).read_text())
    plan = build_plan(mapping, validated)
    Path(args.out).write_text(json.dumps(plan, indent=2) + "\n")

    from collections import Counter

    counts = Counter(d["decision"] for d in plan["decisions"])
    print(f"Wrote {args.out} — {dict(counts)}")


if __name__ == "__main__":
    main()
