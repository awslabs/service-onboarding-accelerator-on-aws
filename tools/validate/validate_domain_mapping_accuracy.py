#!/usr/bin/env python3
"""Validate per-objective mapping accuracy against the CCMv4 domain-guidance KB.

The framework-mapping phase maps each CCMv4 objective per-domain using the
guidance in ``data/domain-mapping-guidance/ccmv4.json``. That guidance records,
per objective, what the objective actually requires (``intent``), whether it is
mappable for a platform/infrastructure service (``mappable``), and which
mechanism *classes* may (``allow_mechanisms``) or must never (``deny_mechanisms``)
satisfy it. This validator is the deterministic backstop for that guidance: it
classifies each mapped control into mechanism classes from the control's own
metadata, then flags two mis-mapping shapes.

  1. Denied-class over-claim — a control whose mechanism class is in the
     objective's ``deny_mechanisms`` is mapped to that objective, and the control
     does NOT also satisfy one of the objective's ``allow_mechanisms``. Concrete
     CCMv4 examples the guidance encodes:
       - IVS-07 (Migration to Cloud Environments) is about a secure migration
         *process*, not runtime transfer encryption — a TLS / encryption-in-transit
         control mapped here is a mis-map.
       - LOG-12 (Access Control Logs) is about logging *who accessed what* — a
         misconfiguration-detective control that does not log access events is a
         mis-map.
       - STA-12 (Supply Chain Service Agreement Compliance) is about supply-chain
         *agreements* — an access-control mechanism (e.g. layer-version sharing) is
         a mis-map.

  2. ``default_na`` objective mapped without an override — a generalized version
     of the applicability screen: any objective the guidance marks
     ``mappable == "default_na"`` that is nonetheless ``MAPPED`` without both an
     ``applicability_justification`` and a ``reference_url`` is flagged.

  3. Category-applicability — a row ``MAPPED`` for an objective the
     applicability-matrix marked not-applicable for this service's category.

  4. Coverage-ceiling — a ``MAPPED`` control claiming more coverage than its
     mechanism class can achieve for the objective (per the KB's
     ``coverage_ceilings`` / ``mechanism_class_ceilings`` / ``default_coverage_ceiling``).
     Full is opt-in; a class capped at Partial cannot claim Full Coverage.

  5. Citation-as-gate — a confident ``MAPPED`` row (not ``UNCERTAIN``) with no
     concrete citation (``objective_requirement`` + ``source``). It must instead
     be surfaced as ``UNCERTAIN`` with a ``review_reason`` — we neither silently
     drop nor silently assert an unevidenced mapping. Enforced only when the
     mapping opts into citations (a legacy citation-free mapping is not retro-failed).

The per-service-category overrides in the KB (``by_service_category``) are
applied before checks 1/2/4 when an applicability-matrix resolves the service's
category. An ``UNCERTAIN`` row is advisory (surfaced, never failed) — it is the
review escape hatch, not a violation.

The guidance is framework-specific (CCMv4). Objective ids are matched verbatim
against the guidance, so a framework whose objectives are not in the guidance
simply yields no findings — the validator is a no-op there, never a hard failure.

Advisory by default (warn, exit 0); ``--strict`` exits 2 on any finding so a run
can promote it to a hard gate once the guidance is proven on real runs.

CLI:
    python3 validate_domain_mapping_accuracy.py --slug <slug> [--strict]
    python3 validate_domain_mapping_accuracy.py <map-framework-mapped.json> \
        [--controls <map-controls-generated.json>] [--guidance <ccmv4.json>] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Repo root = three levels up from this file (tools/validate/<this>.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_GUIDANCE = _REPO_ROOT / "data" / "domain-mapping-guidance" / "ccmv4.json"


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def load_guidance(path: str | Path | None = None) -> dict | None:
    """Load the domain-guidance KB. Returns None if absent (validator no-ops)."""
    p = Path(path) if path else _DEFAULT_GUIDANCE
    if not p.exists():
        return None
    return _load_json(p)


def build_objective_index(guidance: dict) -> dict[str, dict]:
    """objective_id -> objective guidance entry (flattened across domains)."""
    index: dict[str, dict] = {}
    for domain in guidance.get("domains", []):
        for obj in domain.get("objectives", []):
            oid = obj.get("objective_id")
            if oid:
                index[oid] = obj
    return index


# --- Coverage-level vocabulary ------------------------------------------------
# Canonical coverage labels, ranked. Legacy values (High/Medium/Low) normalise
# onto the canonical three so archived runs are comparable.
_COVERAGE_RANK = {
    "Full Coverage": 3,
    "Partial Coverage": 2,
    "Supportive": 1,
}
_COVERAGE_ALIAS = {
    "High": "Full Coverage",
    "Medium": "Partial Coverage",
    "Low": "Supportive",
    "Full Coverage": "Full Coverage",
    "Partial Coverage": "Partial Coverage",
    "Supportive": "Supportive",
}


def _normalise_coverage(level: str) -> str | None:
    """Map a control coverage_level onto the canonical three, or None if unknown."""
    return _COVERAGE_ALIAS.get((level or "").strip())


def effective_ceiling(objective: dict, guidance: dict, ctrl_classes: set[str]) -> str | None:
    """Resolve the coverage ceiling for a control mapped to an objective.

    Precedence per mechanism class: the objective's own ``coverage_ceilings``
    override > the KB-level ``mechanism_class_ceilings`` > ``default_coverage_ceiling``.
    A control may satisfy the objective through any of the *allowed* classes it
    matches, so the effective ceiling is the MOST permissive ceiling across the
    control's classes that are in the objective's ``allow_mechanisms`` — the
    control is judged by its strongest legitimate contribution. Returns None when
    no ceiling policy is configured (validator no-ops on ceilings then).
    """
    default = guidance.get("default_coverage_ceiling")
    class_ceilings = guidance.get("mechanism_class_ceilings", {})
    obj_ceilings = objective.get("coverage_ceilings", {})
    allow = set(objective.get("allow_mechanisms", []))

    # Only classes that legitimately satisfy the objective bound its coverage.
    relevant = ctrl_classes & allow if allow else ctrl_classes
    if not relevant:
        return None

    best_rank = 0
    best_label: str | None = None
    for cls in relevant:
        ceil = obj_ceilings.get(cls) or class_ceilings.get(cls) or default
        if ceil and _COVERAGE_RANK.get(ceil, 0) > best_rank:
            best_rank = _COVERAGE_RANK[ceil]
            best_label = ceil
    return best_label


def _control_text(ctrl: dict) -> str:
    """Lowercased blob of a control's keyword-bearing fields for class matching."""
    parts = [
        ctrl.get("name", ""),
        ctrl.get("description", ""),
        " ".join(ctrl.get("framework_keywords", []) or []),
    ]
    return " ".join(parts).lower()


def classify_control(ctrl: dict, mechanism_classes: dict) -> set[str]:
    """Return the set of mechanism-class ids a control belongs to.

    A control matches a class when its ``mechanism`` equals one of the class's
    ``match_mechanisms`` (case-insensitive) OR any of the class's
    ``match_keywords`` appears in the control's text blob. Mechanism matching is
    exact (normalised) — the class vocabulary uses full mechanism names, so a
    short token never matches inside an unrelated word. Keyword matching is
    substring, which is the looser, intentional signal.
    """
    classes: set[str] = set()
    mech = (ctrl.get("mechanism") or "").strip().lower()
    blob = _control_text(ctrl)
    for class_id, spec in mechanism_classes.items():
        match_mechs = {m.strip().lower() for m in spec.get("match_mechanisms", [])}
        if mech and mech in match_mechs:
            classes.add(class_id)
            continue
        for kw in spec.get("match_keywords", []):
            if kw and kw.lower() in blob:
                classes.add(class_id)
                break
    return classes


def _apply_category_overrides(guide: dict, matrix: dict | None) -> dict:
    """Return the objective guidance with any per-service-category override applied.

    When the applicability matrix resolves the service to one or more categories
    and the objective carries a ``by_service_category`` block for a matched
    category, that block's fields (mappable / allow / deny / coverage_ceilings /
    na_reason) shadow the objective-level defaults. If several categories match,
    the most restrictive ``mappable`` wins (default_na > conditional > mappable),
    matching the risk-averse posture. No matrix / no match → the guide unchanged.
    """
    if not matrix:
        return guide
    by_cat = guide.get("by_service_category")
    if not by_cat:
        return guide
    categories = matrix.get("service_categories", []) or []
    matched = [by_cat[c] for c in categories if c in by_cat]
    if not matched:
        return guide

    merged = dict(guide)
    rank = {"default_na": 3, "conditional": 2, "mappable": 1}
    for ov in matched:
        for key in ("allow_mechanisms", "deny_mechanisms", "coverage_ceilings", "na_reason"):
            if key in ov:
                merged[key] = ov[key]
        if "mappable" in ov and rank.get(ov["mappable"], 0) >= rank.get(merged.get("mappable"), 0):
            merged["mappable"] = ov["mappable"]
    return merged


def _has_concrete_citation(entry: dict, cm: dict) -> bool:
    """Whether a mapped-control row carries a concrete citation of its evidence.

    A concrete citation names the specific objective sub-requirement satisfied
    AND a source (Canopy mitigation, reference example, or AWS doc). The citation
    may live on the control-mapping row (preferred) or the objective entry.
    """
    for holder in (cm, entry):
        cit = holder.get("citation")
        if not isinstance(cit, dict):
            continue
        requirement = (cit.get("objective_requirement") or "").strip()
        source = (cit.get("source") or "").strip()
        if requirement and source:
            return True
    return False


def check_accuracy(
    fw_mapped: dict,
    controls_by_id: dict[str, dict] | None,
    guidance: dict | None,
    matrix: dict | None = None,
) -> list[str]:
    """Validate mapping accuracy against the guidance KB. Returns error strings.

    When ``guidance`` is None the validator no-ops (returns []). When
    ``controls_by_id`` is None, the control-dependent checks (denied-class,
    coverage-ceiling, citation) are skipped; the ``default_na``-without-override
    and category-applicability checks still run (they need only the mapping entry
    and the matrix).

    A row with ``status == "UNCERTAIN"`` is the review escape hatch — it is
    advisory (surfaced, not failed), so the FAIL checks skip it. Only ``MAPPED``
    rows are held to the accuracy gates.
    """
    if not guidance:
        return []

    errors: list[str] = []
    obj_index = build_objective_index(guidance)
    mechanism_classes = guidance.get("mechanism_classes", {})
    if not obj_index:
        return errors

    mappings = fw_mapped.get("framework_mapping", [])
    # No objective in this mapping is known to the (CCMv4) guidance → no-op.
    if mappings and not any(m.get("objective_id") in obj_index for m in mappings):
        print(
            "domain-mapping-accuracy: no objective ids match the CCMv4 guidance KB — "
            "guidance is framework-specific, skipping (no findings possible).",
            file=sys.stderr,
        )
        return errors

    matrix_app = (matrix or {}).get("objective_applicability", {})
    uses_citations = _mapping_uses_citations(fw_mapped)

    for entry in mappings:
        oid = entry.get("objective_id", "")
        if entry.get("status") != "MAPPED":
            continue
        base_guide = obj_index.get(oid)
        if not base_guide:
            continue
        guide = _apply_category_overrides(base_guide, matrix)

        # Check 3 — category-applicability: a row MAPPED for an objective the
        # applicability matrix marked not-applicable for this service.
        app = matrix_app.get(oid)
        if app is not None and not app.get("applicable", True):
            reason = app.get("reason", "objective not applicable to this service")
            errors.append(
                f"domain-mapping-accuracy: {oid} is MAPPED but the applicability "
                f"matrix marks it not applicable — {reason} Mark it N/A."
            )

        # Check 2 — default_na objective mapped without the override fields.
        if guide.get("mappable") == "default_na":
            justification = (entry.get("applicability_justification") or "").strip()
            ref = (entry.get("reference_url") or "").strip()
            if not (justification and ref):
                na_reason = guide.get("na_reason", "this objective is N/A by default")
                errors.append(
                    f"domain-mapping-accuracy: {oid} is default-N/A in the CCMv4 "
                    f"guidance ({na_reason}) but is MAPPED without both "
                    f"applicability_justification and reference_url. Mark it N/A or "
                    f"add the override fields with a public AWS doc URL."
                )

        deny = set(guide.get("deny_mechanisms", []))
        allow = set(guide.get("allow_mechanisms", []))
        for cm in entry.get("controls", []):
            cid = cm.get("control_id")
            ctrl = controls_by_id.get(cid) if controls_by_id else None

            # Check 1 — denied-class over-claim (needs control mechanism metadata).
            if ctrl is not None and deny:
                ctrl_classes = classify_control(ctrl, mechanism_classes)
                hit = deny & ctrl_classes
                # A control that also satisfies an allowed class is legitimate
                # (it genuinely meets the objective and merely shares a denied
                # trait); only flag when it matches a denied class and NO allowed
                # class. For a default_na objective allow is empty, so any denied
                # match flags.
                if hit and not (allow & ctrl_classes):
                    denied = ", ".join(sorted(hit))
                    intent = guide.get("intent", "")
                    errors.append(
                        f"domain-mapping-accuracy: {oid} is mapped to {cid} whose "
                        f"mechanism class [{denied}] must not satisfy this objective "
                        f"— {intent} Remove the mapping (mark {oid} N/A) or map only "
                        f"a control whose mechanism genuinely satisfies the objective."
                    )

            # Check 4 — coverage-ceiling: a control claiming more coverage than
            # its mechanism class can achieve for this objective.
            if ctrl is not None:
                ctrl_classes = classify_control(ctrl, mechanism_classes)
                claimed = _normalise_coverage(cm.get("coverage_level", ""))
                ceiling = effective_ceiling(guide, guidance, ctrl_classes)
                if claimed and ceiling and \
                        _COVERAGE_RANK[claimed] > _COVERAGE_RANK.get(ceiling, 0):
                    errors.append(
                        f"domain-mapping-accuracy: {oid} maps {cid} at "
                        f"'{cm.get('coverage_level')}' but its mechanism class caps "
                        f"coverage at '{ceiling}' for this objective. Reduce to "
                        f"'{ceiling}' or lower — most controls partially satisfy an "
                        f"objective, Full is reserved for a class that fully "
                        f"implements the named mechanism."
                    )

            # Check 5 — citation-as-gate: a MAPPED row must carry a concrete
            # citation (sub-requirement + source). Without one it must be
            # surfaced as UNCERTAIN, not asserted as MAPPED. Only enforced when
            # the mapping opts into citations (any row/control carries one, or any
            # row is UNCERTAIN) — a legacy citation-free mapping is not retro-failed.
            # (Status is already MAPPED here; UNCERTAIN rows are skipped at the top
            # of the loop, so they are never subject to this gate.)
            if uses_citations and not _has_concrete_citation(entry, cm):
                errors.append(
                    f"domain-mapping-accuracy: {oid} maps {cid} as a MAPPED row "
                    f"but carries no concrete citation (objective_requirement + "
                    f"source). Add the citation or set status UNCERTAIN with a "
                    f"review_reason."
                )

    return errors


def _mapping_uses_citations(fw_mapped: dict) -> bool:
    """True when this mapping opts into citations (any row/control carries a
    citation, or any row is UNCERTAIN). Legacy mappings with no citation surface at
    all are not retro-failed by the citation gate."""
    for entry in fw_mapped.get("framework_mapping", []):
        if entry.get("status") == "UNCERTAIN" or isinstance(entry.get("citation"), dict):
            return True
        for cm in entry.get("controls", []):
            if isinstance(cm.get("citation"), dict):
                return True
    return False


def check_service(service_root: Path, guidance: dict | None) -> list[str]:
    """Validate a service's map-framework-mapped.json (no-op if absent).

    Also loads the sibling applicability-matrix.json when present so the
    category-applicability and per-category-override checks have their input.
    """
    map_dir = service_root / "04-map"
    mapped_path = map_dir / "map-framework-mapped.json"
    if not mapped_path.exists():
        return []
    fw_mapped = _load_json(mapped_path)
    controls_by_id: dict[str, dict] | None = None
    cg_path = map_dir / "map-controls-generated.json"
    if cg_path.exists():
        cg = _load_json(cg_path)
        controls_by_id = {c["id"]: c for c in cg.get("controls", []) if c.get("id")}
    matrix: dict | None = None
    matrix_path = map_dir / "applicability-matrix.json"
    if matrix_path.exists():
        matrix = _load_json(matrix_path)
    return check_accuracy(fw_mapped, controls_by_id, guidance, matrix)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mapped", nargs="?", help="path to map-framework-mapped.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--controls", help="path to map-controls-generated.json (mechanism lookup)")
    parser.add_argument("--matrix", help="path to applicability-matrix.json (category + N/A screen)")
    parser.add_argument("--guidance", help="path to domain-mapping-guidance KB (default: CCMv4)")
    parser.add_argument("--strict", action="store_true", help="exit 2 on any finding")
    args = parser.parse_args()

    guidance = load_guidance(args.guidance)
    if guidance is None and args.guidance:
        print(f"ERROR: guidance file not found: {args.guidance}", file=sys.stderr)
        sys.exit(1)

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root, guidance)
    elif args.mapped:
        fw_mapped = _load_json(args.mapped)
        controls_by_id = None
        if args.controls:
            cg = _load_json(args.controls)
            controls_by_id = {c["id"]: c for c in cg.get("controls", []) if c.get("id")}
        matrix = _load_json(args.matrix) if args.matrix else None
        errors = check_accuracy(fw_mapped, controls_by_id, guidance, matrix)
    else:
        parser.error("provide a map-framework-mapped.json path OR --slug")

    if guidance is None:
        print(
            "domain-mapping-accuracy: no CCMv4 guidance KB found "
            f"({_DEFAULT_GUIDANCE}) — skipping.",
            file=sys.stderr,
        )

    if errors:
        print(f"DOMAIN MAPPING ACCURACY ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if args.strict:
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
