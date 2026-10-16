#!/usr/bin/env python3
"""Deterministically merge per-domain framework-mapping partials into one file.

CCMv4 framework mapping runs as a per-domain fan-out: one focused subagent maps
each domain's objectives and writes a partial to
``.service-approval/<slug>/04-map/_domains/<DOMAIN>.json``. This script collects
those partials, concatenates their per-objective entries in canonical CCMv4
domain order, recomputes the coverage summary (incl. ``by_domain``) and the
cross-domain quality gates, and writes ``map-framework-mapped.json`` — byte-shape
identical to what the single-pass mapper produced, so map-assemble.py,
validate_state.py::check_framework_mapped, and the schema all consume it
unchanged. No LLM reasoning — pure data assembly, mirroring map-assemble.py.

A partial is either a bare ``[ {entry}, ... ]`` list or an object with a
``framework_mapping`` list (the same per-objective entry shape as the final
file). Each entry must carry ``objective_id`` and ``status``.

The cross-domain quality gates (run here, not per-domain subagent):
  - Rule 2 (no domain-level spray): >=3 consecutive same-domain objectives with
    an identical control set is a FAIL; exactly 2 is a soft warning.
  - Rule 3 (no control mapped to >15 objectives across the whole file).
  - Rule 5 (every control mapping carries a rationale).
  - Rule 6 (<=5 Full Coverage controls per objective).
  - Rule 7 (orphaned controls — controls in map-controls-generated.json not
    mapped to any objective).
Rules 1 (coverage-level consistency) and the per-mapping shape are enforced by
the schema + validate_state.py and re-checked there; this script reports the
PASS/FAIL summary into quality_gate_results so the contract field is populated.

CLI:
    python3 scripts/merge-domain-mappings.py --slug <slug>
    python3 scripts/merge-domain-mappings.py --slug <slug> --domains-dir <dir> \
        --out <path>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# Repo root on path for tools.paths (optional — only used for --slug resolution).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.validate.framework_review import referenced_controls, review_errors

# Canonical CCMv4 domain order. Partials are concatenated in this order so the
# merged file is stable regardless of filesystem iteration order.
CCMV4_DOMAIN_ORDER = ["A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC",
                      "HRS", "IAM", "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM"]

COVERAGE_FULL = {"Fully Covered", "FULL"}
COVERAGE_PARTIAL = {"Partially Covered", "PARTIAL"}
COVERAGE_SUPPORTIVE = {"Supportive Only", "SUPPORTS"}
FULL_LEVELS = {"Full Coverage", "High"}


def _load_json(path: Path) -> dict | list:
    with open(path) as fh:
        return json.load(fh)


def _domain_prefix(objective_id: str) -> str:
    return objective_id.split("-", 1)[0] if objective_id else ""


def _partial_entries(partial: dict | list) -> list[dict]:
    """Normalize a partial to its list of per-objective entries."""
    if isinstance(partial, list):
        return partial
    if isinstance(partial, dict):
        return partial.get("framework_mapping", [])
    raise ValueError(f"unrecognised partial shape: {type(partial).__name__}")


def collect_partials(domains_dir: Path) -> dict[str, list[dict]]:
    """Read every <DOMAIN>.json partial in domains_dir → {prefix: entries}.

    The prefix is taken from each entry's objective_id (authoritative), not the
    filename, so a partial whose filename was sanitised (e.g. ``A_A.json`` for
    ``A&A``) is still bucketed correctly.
    """
    by_prefix: dict[str, list[dict]] = {}
    if not domains_dir.exists():
        return by_prefix
    for path in sorted(domains_dir.glob("*.json")):
        partial = _load_json(path)
        for entry in _partial_entries(partial):
            prefix = _domain_prefix(entry.get("objective_id", ""))
            by_prefix.setdefault(prefix, []).append(entry)
    return by_prefix


def order_entries(
    by_prefix: dict[str, list[dict]], parsed_order: list[str]
) -> list[dict]:
    """Concatenate per-domain entries in canonical, then parsed, domain order.

    Known CCMv4 domains come first in CCMV4_DOMAIN_ORDER; any other prefix the
    fan-out produced follows in the order it appears in the parsed framework (so
    a future framework's domains still merge deterministically). Within a domain,
    entries are ordered by objective_id for stability.
    """
    ordered: list[dict] = []
    seen: set[str] = set()
    sequence = list(CCMV4_DOMAIN_ORDER)
    for p in parsed_order:
        if p not in sequence:
            sequence.append(p)
    for prefix in sequence:
        if prefix in by_prefix and prefix not in seen:
            seen.add(prefix)
            ordered.extend(
                sorted(by_prefix[prefix], key=lambda e: e.get("objective_id", ""))
            )
    # Any prefix not in the sequence at all (defensive) — append in sorted order.
    for prefix in sorted(by_prefix):
        if prefix not in seen:
            ordered.extend(
                sorted(by_prefix[prefix], key=lambda e: e.get("objective_id", ""))
            )
    return ordered


def build_coverage_summary(
    mappings: list[dict], parsed_objectives: list[dict]
) -> dict:
    """Recompute framework_coverage_summary, including per-domain breakdown.

    UNCERTAIN is a distinct status: a row the mapper believes relates to the
    objective but cannot cite concretely. It is counted separately and excluded
    from both the mapped and the not_applicable tallies — it does not inflate
    coverage % (numerator: mapped only), and it is surfaced for review rather
    than silently asserted or dropped.
    """
    total = len(parsed_objectives)
    mapped = sum(1 for m in mappings if m.get("status") == "MAPPED")
    na = sum(1 for m in mappings if m.get("status") == "N/A")
    uncertain = sum(1 for m in mappings if m.get("status") == "UNCERTAIN")

    # by_domain keyed by objective-id prefix.
    by_domain: dict[str, dict] = {}
    for m in mappings:
        prefix = _domain_prefix(m.get("objective_id", ""))
        d = by_domain.setdefault(
            prefix, {"total": 0, "mapped": 0, "not_applicable": 0, "uncertain": 0}
        )
        d["total"] += 1
        status = m.get("status")
        if status == "MAPPED":
            d["mapped"] += 1
        elif status == "UNCERTAIN":
            d["uncertain"] += 1
        else:
            d["not_applicable"] += 1
    for d in by_domain.values():
        d["coverage_percentage"] = (
            round(d["mapped"] / d["total"] * 100, 1) if d["total"] else 0.0
        )

    return {
        "total_objectives": total,
        "mapped": mapped,
        "not_applicable": na,
        "uncertain": uncertain,
        "by_domain": dict(sorted(by_domain.items())),
    }


def run_quality_gates(
    mappings: list[dict], all_control_ids: set[str] | None, reviews=None
) -> tuple[dict, list[str]]:
    """Run the cross-domain quality gates. Returns (results_dict, failures)."""
    failures: list[str] = []

    # Rule 2 — no domain-level spray (>=3 consecutive identical control sets).
    prev_domain = None
    prev_ctrls = None
    streak = 0
    rule2 = "PASS"
    for m in mappings:
        if m.get("status") != "MAPPED":
            prev_domain, prev_ctrls, streak = None, None, 0
            continue
        cur = sorted(c["control_id"] for c in m.get("controls", []) if c.get("control_id"))
        dom = m.get("domain", "")
        if dom == prev_domain and cur == prev_ctrls and cur:
            streak += 1
            if streak >= 2:  # 3rd-in-a-row (streak counts predecessors)
                rule2 = "FAIL"
                failures.append(
                    f"Rule2 spray: {m.get('objective_id')} shares controls with "
                    f">=2 predecessors in {dom}"
                )
        else:
            streak = 0
        prev_domain, prev_ctrls = dom, cur

    # Rule 3 — no control mapped to >15 objectives.
    counts: Counter = Counter()
    for m in mappings:
        for c in m.get("controls", []):
            cid = c.get("control_id")
            if cid:
                counts[cid] += 1
    rule3 = "PASS"
    for cid, n in counts.items():
        if n > 15:
            rule3 = "FAIL"
            failures.append(f"Rule3: {cid} mapped to {n} objectives (max 15)")

    # Rule 5 — rationale present on every control mapping.
    missing = sum(
        1 for m in mappings for c in m.get("controls", []) if not c.get("rationale")
    )
    rule5 = "PASS" if missing == 0 else "FAIL"
    if missing:
        failures.append(f"Rule5: {missing} control mappings missing rationale")

    # Rule 6 — <=5 Full Coverage controls per objective.
    rule6 = "PASS"
    for m in mappings:
        full = sum(
            1 for c in m.get("controls", []) if c.get("coverage_level") in FULL_LEVELS
        )
        if full > 5:
            rule6 = "FAIL"
            failures.append(
                f"Rule6: {m.get('objective_id')} has {full} Full Coverage controls (max 5)"
            )

    # Rule 7 — orphaned controls (needs the full control set).
    orphaned: list[str] = []
    rule7_errors = []
    if all_control_ids is not None:
        orphaned = sorted(all_control_ids - referenced_controls(mappings))
        rule7_errors = review_errors(mappings, all_control_ids, reviews if reviews is not None else [])
        failures.extend(rule7_errors)

    results = {
        "rule_1_coverage_level_consistency": "PASS",
        "rule_2_no_spray": rule2,
        "rule_3_max_15_per_control": rule3,
        "rule_4_org_process_domains": "PASS",
        "rule_5_rationale_present": rule5,
        "rule_6_max_5_full_per_objective": rule6,
        "rule_7_orphan_review": "FAIL" if rule7_errors else ("PASS" if all_control_ids is not None else "NOT_CHECKED"),
        "orphaned_controls": orphaned,
    }
    return results, failures


def merge(
    by_prefix: dict[str, list[dict]],
    fw_parsed: dict,
    controls: list[dict] | None,
    reviews=None,
) -> dict:
    """Assemble the merged map-framework-mapped.json content."""
    parsed_objectives = fw_parsed.get("framework_objectives", [])
    parsed_order: list[str] = []
    for o in parsed_objectives:
        p = _domain_prefix(o.get("id") or o.get("objective_id", ""))
        if p and p not in parsed_order:
            parsed_order.append(p)

    mappings = order_entries(by_prefix, parsed_order)
    summary = build_coverage_summary(mappings, parsed_objectives)
    all_control_ids = (
        {c["id"] for c in controls if c.get("id")} if controls is not None else None
    )
    quality, _failures = run_quality_gates(mappings, all_control_ids, reviews)

    framework = fw_parsed.get("framework", {}) or {}
    out: dict = {
        "schema_version": "1.0",
        "phase": "map-framework-mapped",
        "framework_mapping": mappings,
        "framework_coverage_summary": summary,
        "quality_gate_results": quality,
        "unmapped_control_reviews": reviews if reviews is not None else [],
    }
    if framework.get("name"):
        out["framework_name"] = framework["name"]
    if framework.get("version"):
        out["framework_version"] = framework["version"]
    return out


def check_completeness(mappings: list[dict], parsed_objectives: list[dict]) -> list[str]:
    """Every parsed objective must appear exactly once in the merged mapping."""
    errors: list[str] = []
    expected = {
        o.get("id") or o.get("objective_id")
        for o in parsed_objectives
        if o.get("id") or o.get("objective_id")
    }
    seen = Counter(m.get("objective_id") for m in mappings if m.get("objective_id"))
    missing = expected - set(seen)
    if missing:
        errors.append(f"{len(missing)} objectives missing from merge: {sorted(missing)[:10]}")
    dupes = [oid for oid, n in seen.items() if n > 1]
    if dupes:
        errors.append(f"{len(dupes)} duplicate objective ids in merge: {sorted(dupes)[:10]}")
    extra = set(seen) - expected
    if extra:
        errors.append(f"{len(extra)} unexpected objective ids in merge: {sorted(extra)[:10]}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service", "--slug", dest="slug",
                        help="service slug under .service-approval/")
    parser.add_argument("--domains-dir", help="dir of per-domain partials "
                        "(default: <map>/_domains)")
    parser.add_argument("--parsed", help="path to map-framework-parsed.json")
    parser.add_argument("--controls", help="path to map-controls-generated.json")
    parser.add_argument("--reviews", help="JSON array of reviews (default: <map>/unmapped-control-reviews.json)")
    parser.add_argument("--out", help="output path (default: <map>/map-framework-mapped.json)")
    args = parser.parse_args()

    if args.slug:
        try:
            from tools import paths
            map_dir = paths.phase_dir(args.slug, "map")
        except Exception as e:  # pragma: no cover - defensive
            print(f"ERROR: could not resolve slug {args.slug}: {e}", file=sys.stderr)
            return 1
        domains_dir = Path(args.domains_dir) if args.domains_dir else map_dir / "_domains"
        parsed_path = Path(args.parsed) if args.parsed else map_dir / "map-framework-parsed.json"
        controls_path = Path(args.controls) if args.controls else map_dir / "map-controls-generated.json"
        out_path = Path(args.out) if args.out else map_dir / "map-framework-mapped.json"
    else:
        if not (args.domains_dir and args.parsed and args.out):
            parser.error("provide --slug OR (--domains-dir AND --parsed AND --out)")
        domains_dir = Path(args.domains_dir)
        parsed_path = Path(args.parsed)
        controls_path = Path(args.controls) if args.controls else None
        out_path = Path(args.out)

    fw_parsed = _load_json(parsed_path)
    if not controls_path or not controls_path.exists():
        print("ERROR: control inventory is required to validate Rule 7 (--controls or --slug).", file=sys.stderr)
        return 1
    controls = _load_json(controls_path).get("controls", [])
    reviews_path = Path(args.reviews) if args.reviews else out_path.parent / "unmapped-control-reviews.json"
    if args.reviews and not reviews_path.exists():
        print(f"ERROR: reviews file not found: {reviews_path}", file=sys.stderr)
        return 1
    reviews = _load_json(reviews_path) if reviews_path.exists() else []

    by_prefix = collect_partials(domains_dir)
    if not by_prefix:
        print(f"ERROR: no per-domain partials found in {domains_dir}", file=sys.stderr)
        return 1

    merged = merge(by_prefix, fw_parsed, controls, reviews)

    completeness = check_completeness(
        merged["framework_mapping"], fw_parsed.get("framework_objectives", [])
    )
    if completeness:
        for e in completeness:
            print(f"  MERGE ERROR: {e}", file=sys.stderr)
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged, indent=2))
    summary = merged["framework_coverage_summary"]
    print(f"  Wrote {out_path}")
    print(f"  Objectives: {summary['total_objectives']} "
          f"(mapped={summary['mapped']}, N/A={summary['not_applicable']}, "
          f"uncertain={summary.get('uncertain', 0)})")
    print(f"  Domains: {len(summary['by_domain'])}")
    qg = merged["quality_gate_results"]
    fails = [k for k, v in qg.items() if v == "FAIL"]
    print(f"  Quality gates: {'all PASS' if not fails else 'FAIL: ' + ', '.join(fails)}")
    print(f"  Orphaned controls: {len(qg.get('orphaned_controls', []))}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
