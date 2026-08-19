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


def _service_doc_citation(control: dict) -> dict:
    """Build a fallback service-doc citation when nothing richer is available.

    Honors a `citation` field already present on the mapping control (the
    map-generate-controls skill records the originating doc), falling back to
    a typed pointer at the upstream control id so the row still validates.
    """
    cit = control.get("citation")
    if isinstance(cit, dict) and cit.get("type") in {"threat_model", "reference", "catalog", "service-doc"}:
        return cit  # already typed by mapping
    cid = control.get("id", "unknown")
    return {"type": "service-doc", "id": cid}


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
                "source_control_id": cid,
                "mechanism": mechanism,
                "preventable": False,
                "decision": "ROUTE_DETECTIVE",
                "anchor": None,
                "citation": _service_doc_citation(control),
                "route_to": "detective",
                "rationale": verdict["reason"],
            })
            continue

        keys = verdict["enforcing_condition_keys"]
        best = ri.best_anchor(mechanism, control.get("actions", []), keys)
        if best is None:
            decisions.append({
                "control_id": cid,
                "source_control_id": cid,
                "mechanism": mechanism,
                "preventable": True,
                "enforcing_condition_keys": keys,
                "decision": "REFER_TO_REFERENCE",
                "anchor": None,
                "citation": _service_doc_citation(control),
                "route_to": None,
                "rationale": "preventable, but no reference example overlaps this "
                             "control's actions/keys — point the customer at the "
                             "closest reference rather than authoring",
            })
            continue

        # When we have a reference-repo anchor, the citation for the body is
        # the reference example. Mapping may carry a richer intent citation
        # (e.g. an AWS Threat Model mitigation alias) — honor it; otherwise fall back to
        # the reference itself as both intent and body source.
        intent_citation = control.get("citation")
        if not (isinstance(intent_citation, dict) and intent_citation.get("type") in
                {"threat_model", "reference", "catalog", "service-doc"}):
            intent_citation = {
                "type": "reference",
                "id": best["id"],
                "url": best["source_url"],
            }

        # An anchored GENERATE_* decision surfaces a policy URL to the customer,
        # so it must carry an applicability block (what the policy targets + how
        # to use it). Derive it deterministically from the control's real actions
        # and enforcing condition keys — the skill refines the prose per-run.
        actions = [a for a in (control.get("actions") or []) if a]
        action_phrase = ", ".join(actions) if actions else "the governed actions"
        key_phrase = ", ".join(keys) if keys else "the enforcing condition key"
        applicability = {
            "applies_to": (
                f"the {mechanism or 'policy'} target resources selected by "
                f"{key_phrase}, for {action_phrase}"
            ),
            "usage_notes": (
                f"apply only where {key_phrase} legitimately gates {action_phrase}; "
                f"do not apply it to resources whose owning teams must retain those "
                f"actions"
            ),
        }

        decisions.append({
            "control_id": cid,
            "source_control_id": cid,
            "mechanism": mechanism,
            "preventable": True,
            "enforcing_condition_keys": keys,
            "decision": _generate_decision(mechanism),
            "anchor": {
                "example_id": best["id"],
                "repo": best["repo"],
                "url": best["source_url"],
            },
            "citation": intent_citation,
            "route_to": None,
            "rationale": f"condition key gates the target action; anchored to {best['id']}",
            "applicability": applicability,
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
