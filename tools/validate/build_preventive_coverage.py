#!/usr/bin/env python3
"""
Build the deterministic preventive-coverage rollup.

Reads the recommender's plan (`preventive-plan.json`) and, when present, the
root-cause critic's report (`rootcause-report.json`), and produces a file-backed
accounting of how many preventive objectives we could anchor a policy for, how
many we referred to a reference example, and how many we routed to detective —
each with the per-control reason and citation already recorded upstream.

This replaces the hand-written prose narration in the report ("Of 12 preventive
objectives: 5 …, 1 …, 4 …") with a deterministic, traceable number. Every count
row resolves to a real control id and its citation, so a reader can verify each
number against the plan.

Bucketing (from each plan decision):
  - GENERATE_SCP / GENERATE_RCP / GENERATE_IAM  → "authored"
  - REFER_TO_REFERENCE                          → "referred"
  - ROUTE_DETECTIVE                             → "routed_to_detective"

The critic can route an objective to detective AFTER the plan was written (a
GENERATE_* control whose authored policy turned out not to enforce). When
`rootcause-report.json` lists a control under `routed_to_detective[]`, that
control is re-bucketed to "routed_to_detective" here so the rollup reflects the
final coverage, not the pre-critic plan.

CLI:
    python3 build_preventive_coverage.py --slug <slug>
    python3 build_preventive_coverage.py --plan <plan.json> [--rootcause <rc.json>] --out <out.json>
Exit codes: 0 ok (file written), 2 plan missing/unreadable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_GENERATE_DECISIONS = {"GENERATE_SCP", "GENERATE_RCP", "GENERATE_IAM"}
_CATEGORY_BY_DECISION = {
    "GENERATE_SCP": "authored",
    "GENERATE_RCP": "authored",
    "GENERATE_IAM": "authored",
    "REFER_TO_REFERENCE": "referred",
    "ROUTE_DETECTIVE": "routed_to_detective",
}


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _critic_routed_ids(rootcause: dict | None) -> dict[str, str]:
    """Map control_id → reason for every objective the critic routed to detective.

    The critic's report carries `routed_to_detective[]` ({control_id, reason}).
    These take precedence over the plan decision: a GENERATE_* control the critic
    routed is re-bucketed to routed_to_detective in the rollup.
    """
    out: dict[str, str] = {}
    if not isinstance(rootcause, dict):
        return out
    for row in rootcause.get("routed_to_detective", []) or []:
        if isinstance(row, dict) and row.get("control_id"):
            out[row["control_id"]] = row.get("reason", "routed to detective by root-cause critic")
    return out


def build_coverage(plan: dict, rootcause: dict | None = None) -> dict:
    """Build the preventive-coverage rollup dict from a plan (+ optional critic)."""
    service = (plan.get("_metadata") or {}).get("service", "unknown")
    critic_routed = _critic_routed_ids(rootcause)

    rows: list[dict] = []
    for d in plan.get("decisions", []) or []:
        if not isinstance(d, dict):
            continue
        cid = d.get("control_id")
        decision = d.get("decision")
        if not cid or decision not in _CATEGORY_BY_DECISION:
            continue

        # The critic's post-hoc routing wins over the plan's decision.
        if cid in critic_routed:
            category = "routed_to_detective"
            reason = critic_routed[cid]
            anchor = None
        else:
            category = _CATEGORY_BY_DECISION[decision]
            reason = d.get("rationale") or f"{decision} per recommender"
            anchor = d.get("anchor") if category != "routed_to_detective" else None

        citation = d.get("citation") or {"type": "service-doc", "id": cid}

        row = {
            "control_id": cid,
            "category": category,
            "mechanism": d.get("mechanism") or "unknown",
            "reason": reason,
            "citation": citation,
        }
        if anchor is not None:
            row["anchor"] = anchor
        rows.append(row)

    totals = {
        "objectives": len(rows),
        "authored": sum(1 for r in rows if r["category"] == "authored"),
        "referred": sum(1 for r in rows if r["category"] == "referred"),
        "routed_to_detective": sum(
            1 for r in rows if r["category"] == "routed_to_detective"
        ),
    }

    sources = ["preventive-plan.json"]
    if rootcause is not None:
        sources.append("rootcause-report.json")

    return {
        "_metadata": {
            "service": service,
            "generated": "service-approval v3.0.0",
            "sources": sources,
        },
        "totals": totals,
        "controls": rows,
    }


def build_for_slug(slug: str, root: Path | None = None) -> dict | None:
    """Build the rollup for a service slug under .service-approval/. Writes the
    file and returns the dict, or None when the plan is missing/unreadable."""
    base = (root or Path(os.getcwd())) / ".service-approval" / slug / "05-generate"
    plan = _load_json(base / "preventive-plan.json")
    if not isinstance(plan, dict):
        return None
    rootcause = _load_json(base / "preventive" / "rootcause-report.json")
    coverage = build_coverage(plan, rootcause if isinstance(rootcause, dict) else None)
    (base / "preventive-coverage.json").write_text(json.dumps(coverage, indent=2))
    return coverage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--plan", help="explicit preventive-plan.json path")
    parser.add_argument("--rootcause", help="explicit rootcause-report.json path")
    parser.add_argument("--out", help="output path (default: alongside the plan)")
    args = parser.parse_args()

    if args.slug:
        coverage = build_for_slug(args.slug)
        if coverage is None:
            print("ERROR: preventive-plan.json missing or unreadable", file=sys.stderr)
            return 2
        print(json.dumps(coverage["totals"], indent=2))
        return 0

    if not args.plan:
        parser.error("provide --slug OR --plan")
    plan = _load_json(Path(args.plan))
    if not isinstance(plan, dict):
        print(f"ERROR: {args.plan} missing or unreadable", file=sys.stderr)
        return 2
    rootcause = _load_json(Path(args.rootcause)) if args.rootcause else None
    coverage = build_coverage(plan, rootcause if isinstance(rootcause, dict) else None)
    out = Path(args.out) if args.out else Path(args.plan).parent / "preventive-coverage.json"
    out.write_text(json.dumps(coverage, indent=2))
    print(json.dumps(coverage["totals"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
