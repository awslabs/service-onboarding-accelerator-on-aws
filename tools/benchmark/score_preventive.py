#!/usr/bin/env python3
"""
Score a preventive-generation run against the quality metrics.

The static-fixture iteration loop freezes hand-blessed mapping-results.json files
for a few services, runs the preventive sub-skills against them N times, and
scores each output so we can see quality go up and run-to-run variance go down as
the skill opinions are refined. This module computes the metrics for one output
directory and aggregates across runs.

Metrics per run (all in [0, 1], higher is better):
  - anchor_rate         : fraction of preventive policy artifacts carrying a
                          resolvable reference anchor (target -> 1.0)
  - rootcause_pass_rate : fraction of authored preventive controls whose
                          preventability verdict is FEASIBLE
  - action_real_rate    : fraction of target-service IAM actions across the
                          artifacts that are real (sourced), per CHECK-17
  - citation_rate       : fraction of preventive-plan decisions carrying a typed
                          citation (threat_model / reference / catalog / service-doc)
  - mapping_link_rate   : fraction of preventive-plan decisions whose
                          source_control_id traces back to a mapping control
  - disclosure_rate     : fraction of non-generating decisions (REFER /
                          ROUTE_DETECTIVE) that state an explicit rationale —
                          the "no silent un-anchored output" guarantee

Aggregation across runs reports mean and population variance of each metric; low
variance is the signal that the skill has become deterministic.

Reuses the pipeline validators so the scorer and the hooks agree on "good":
  validate_reference_anchor (anchor), validate_preventability (root cause),
  validate_controls.check_iam_action_sourcing_17 (action realness).

CLI:
    python3 score_preventive.py --run-dir <dir> --validated <validated.json> \
        --mapping <mapping-results.json> [--json]
    python3 score_preventive.py --aggregate <run-dir-1> <run-dir-2> ... \
        --validated <v> --mapping <m> [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_VALIDATE_DIR = Path(__file__).resolve().parents[1] / "validate"
sys.path.insert(0, str(_VALIDATE_DIR))

import validate_reference_anchor as vra  # noqa: E402
import validate_preventability as vp  # noqa: E402
from validate_controls import (  # noqa: E402
    _collect_statement_actions,
    _valid_action_set,
)


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _preventive_policy_files(run_dir: Path) -> list[Path]:
    """Policy JSON artifacts under <run_dir>/preventive/ (excludes doc/plan files)."""
    prev = run_dir / "preventive"
    if not prev.is_dir():
        return []
    out = []
    for p in sorted(prev.glob("*.json")):
        if p.name in vra._DOC_ONLY_BASENAMES:
            continue
        out.append(p)
    return out


def anchor_rate(run_dir: Path, known_ids: set[str]) -> tuple[float, int, int]:
    """Fraction of preventive policy artifacts with a resolvable anchor.

    Gap/skip stubs are excluded from the denominator (they emit no policy).
    Returns (rate, anchored, total). Rate is 1.0 when there are no policy files.
    """
    files = _preventive_policy_files(run_dir)
    total = 0
    anchored = 0
    for f in files:
        try:
            data = _load_json(f)
        except (OSError, ValueError):
            continue
        meta = data.get("_metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        if vra._is_gap_or_stub(meta, data):
            continue  # exempt; not a policy
        total += 1
        if not vra.check_artifact(str(f), known_ids):
            anchored += 1
    rate = 1.0 if total == 0 else anchored / total
    return rate, anchored, total


def rootcause_pass_rate(mapping: dict, validated: dict) -> tuple[float, int, int]:
    """Fraction of PRV controls whose preventability verdict is FEASIBLE.

    Returns (rate, feasible, total). Rate is 1.0 when there are no PRV controls.
    """
    results = vp.assess_mapping(mapping, validated)
    total = len(results)
    feasible = sum(1 for r in results if r["verdict"] == "FEASIBLE")
    rate = 1.0 if total == 0 else feasible / total
    return rate, feasible, total


def action_real_rate(run_dir: Path, validated: dict) -> tuple[float, int, int]:
    """Fraction of target-service actions in preventive artifacts that are real.

    Only target-service-prefixed, non-wildcard actions are counted (the ones the
    LLM might synthesize). Returns (rate, real, total). Rate is 1.0 when there are
    no such actions.
    """
    prefix = (validated.get("service_prefix") or validated.get("service") or "").strip()
    if not prefix or " " in prefix or any(c.isupper() for c in prefix):
        return 1.0, 0, 0
    valid = _valid_action_set(validated, prefix)
    total = 0
    real = 0
    for f in _preventive_policy_files(run_dir):
        try:
            data = _load_json(f)
        except (OSError, ValueError):
            continue
        for action, _sid in _collect_statement_actions(data):
            if action == "*" or "*" in action or ":" not in action:
                continue
            if action.split(":", 1)[0] != prefix:
                continue
            total += 1
            if action in valid:
                real += 1
    rate = 1.0 if total == 0 else real / total
    return rate, real, total


def _load_plan(run_dir: Path) -> dict:
    """Load preventive-plan.json from the run dir (or its parent).

    The plan sits next to the preventive/ output dir; tolerate either the
    run_dir itself or its parent holding it. Returns {} when absent.
    """
    for cand in (run_dir / "preventive-plan.json", run_dir.parent / "preventive-plan.json"):
        if cand.is_file():
            try:
                return _load_json(cand)
            except (OSError, ValueError):
                return {}
    return {}


def plan_metrics(plan: dict, mapping: dict) -> dict:
    """Citation / mapping-link / disclosure rates from preventive-plan.json.

    Rates default to 1.0 when there are no decisions (nothing to fault).
    """
    decisions = plan.get("decisions", []) or []
    total = len(decisions)
    # Real mapping-results.json keys the control id under `id`; the evidence
    # fixtures use `control_id`. Accept either so the link rate is computed
    # against actual control ids instead of {None}.
    mapping_ids = {
        (c.get("control_id") or c.get("id")) for c in (mapping.get("controls", []) or [])
        if isinstance(c, dict)
    }

    cited = 0
    linked = 0
    non_generating = 0
    disclosed = 0
    for d in decisions:
        if not isinstance(d, dict):
            continue
        cit = d.get("citation")
        if isinstance(cit, dict) and cit.get("type") and (cit.get("id") or cit.get("url")):
            cited += 1
        scid = d.get("source_control_id")
        if scid and (not mapping_ids or scid in mapping_ids):
            linked += 1
        if d.get("decision") in ("REFER_TO_REFERENCE", "ROUTE_DETECTIVE"):
            non_generating += 1
            if (d.get("rationale") or "").strip():
                disclosed += 1

    return {
        "citation_rate": 1.0 if total == 0 else round(cited / total, 4),
        "cited": cited,
        "mapping_link_rate": 1.0 if total == 0 else round(linked / total, 4),
        "linked": linked,
        "disclosure_rate": 1.0 if non_generating == 0 else round(disclosed / non_generating, 4),
        "disclosed": disclosed,
        "non_generating": non_generating,
        "decisions_total": total,
    }


def score_run(run_dir: Path, validated: dict, mapping: dict, known_ids: set[str]) -> dict:
    """Compute all metrics for one run output directory."""
    a_rate, a_ok, a_tot = anchor_rate(run_dir, known_ids)
    r_rate, r_ok, r_tot = rootcause_pass_rate(mapping, validated)
    x_rate, x_ok, x_tot = action_real_rate(run_dir, validated)
    pm = plan_metrics(_load_plan(run_dir), mapping)
    return {
        "run_dir": str(run_dir),
        "anchor_rate": round(a_rate, 4),
        "anchored": a_ok,
        "anchor_total": a_tot,
        "rootcause_pass_rate": round(r_rate, 4),
        "feasible": r_ok,
        "prv_total": r_tot,
        "action_real_rate": round(x_rate, 4),
        "actions_real": x_ok,
        "actions_total": x_tot,
        **pm,
    }


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _variance(xs: list[float]) -> float:
    if not xs:
        return 0.0
    m = _mean(xs)
    return sum((x - m) ** 2 for x in xs) / len(xs)


def aggregate(run_scores: list[dict]) -> dict:
    """Mean + population variance of each metric across runs."""
    metrics = (
        "anchor_rate", "rootcause_pass_rate", "action_real_rate",
        "citation_rate", "mapping_link_rate", "disclosure_rate",
    )
    out = {"runs": len(run_scores)}
    for mkey in metrics:
        vals = [r[mkey] for r in run_scores if mkey in r]
        out[mkey] = {"mean": round(_mean(vals), 4), "variance": round(_variance(vals), 6)}
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", help="a single 05-recommended-guidance-style output dir")
    parser.add_argument("--aggregate", nargs="+", help="multiple run dirs to aggregate")
    parser.add_argument("--validated", required=True, help="path to validated.json")
    parser.add_argument("--mapping", required=True, help="path to mapping-results.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    validated = _load_json(args.validated)
    mapping = _load_json(args.mapping)
    try:
        known_ids = vra._known_ids()
    except Exception:
        known_ids = set()

    if args.aggregate:
        scores = [score_run(Path(d), validated, mapping, known_ids) for d in args.aggregate]
        agg = aggregate(scores)
        if args.json:
            print(json.dumps({"per_run": scores, "aggregate": agg}, indent=2))
        else:
            for s in scores:
                print(f"{s['run_dir']}: anchor={s['anchor_rate']} "
                      f"rootcause={s['rootcause_pass_rate']} action={s['action_real_rate']} "
                      f"citation={s['citation_rate']} link={s['mapping_link_rate']} "
                      f"disclosure={s['disclosure_rate']}")
            print("--- aggregate ---")
            for k in ("anchor_rate", "rootcause_pass_rate", "action_real_rate",
                      "citation_rate", "mapping_link_rate", "disclosure_rate"):
                print(f"{k}: mean={agg[k]['mean']} variance={agg[k]['variance']}")
    elif args.run_dir:
        s = score_run(Path(args.run_dir), validated, mapping, known_ids)
        print(json.dumps(s, indent=2) if args.json else
              f"anchor={s['anchor_rate']} rootcause={s['rootcause_pass_rate']} "
              f"action={s['action_real_rate']} citation={s['citation_rate']} "
              f"link={s['mapping_link_rate']} disclosure={s['disclosure_rate']}")
    else:
        parser.error("provide --run-dir OR --aggregate")


if __name__ == "__main__":
    main()
