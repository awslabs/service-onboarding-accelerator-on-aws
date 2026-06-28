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


def check_accuracy(
    fw_mapped: dict,
    controls_by_id: dict[str, dict] | None,
    guidance: dict | None,
) -> list[str]:
    """Validate mapping accuracy against the guidance KB. Returns error strings.

    When ``guidance`` is None the validator no-ops (returns []). When
    ``controls_by_id`` is None, the denied-class check is skipped (it needs each
    control's mechanism/keywords); the ``default_na``-without-override check still
    runs (it needs only the mapping entry).
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

    for entry in mappings:
        oid = entry.get("objective_id", "")
        if entry.get("status") != "MAPPED":
            continue
        guide = obj_index.get(oid)
        if not guide:
            continue

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

        # Check 1 — denied-class over-claim (needs control mechanism metadata).
        deny = set(guide.get("deny_mechanisms", []))
        allow = set(guide.get("allow_mechanisms", []))
        if deny and controls_by_id is not None:
            for cm in entry.get("controls", []):
                cid = cm.get("control_id")
                ctrl = controls_by_id.get(cid)
                if not ctrl:
                    continue
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

    return errors


def check_service(service_root: Path, guidance: dict | None) -> list[str]:
    """Validate a service's map-framework-mapped.json (no-op if absent)."""
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
    return check_accuracy(fw_mapped, controls_by_id, guidance)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mapped", nargs="?", help="path to map-framework-mapped.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--controls", help="path to map-controls-generated.json (mechanism lookup)")
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
        errors = check_accuracy(fw_mapped, controls_by_id, guidance)
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
