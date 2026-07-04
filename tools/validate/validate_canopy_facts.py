#!/usr/bin/env python3
"""
Canopy-factual validator (deterministic).

When a control or preventive decision cites a Canopy mitigation as its intent
source, that citation must be FACTUAL: the cited mitigation `alias` must actually
exist in the provided Canopy export, the control's gated operation must be
consistent with that mitigation's `configurationRequestParameters[]`, and any
mitigation text the citation quotes must appear verbatim in the Canopy export.
This catches a fabricated or drifted Canopy citation — a control that claims
Canopy intent the Canopy file does not support.

It is deterministic (no LLM): pure set membership + normalized text search
against the Canopy file. Runs in BOTH review gates (post-map and post-generate).

Two citation field shapes are accepted (a citation is "canopy" under either):
  - map / framework-mapping rows: `citation.source == "canopy"` +
    `citation.mitigation_alias` (+ optionally a quoted `mitigation_statement`).
  - preventive-plan rows: `citation.type == "canopy"` + `citation.id`.

Three checks per canopy-cited item:
  1. **Alias exists.** The cited alias must match a `mitigations[].alias` (or,
     when the item cites a threat, a `threats[].alias`) in the Canopy export.
  2. **Operation consistency.** When the item names gated operations (a control's
     `actions[]`, or a plan row's `plan_actions[]`), at least one must correspond
     to an operation the cited mitigation actually governs (the
     `configurationRequestParameters[].operation` set). An IAM action
     `prefix:DoThing` maps to the Canopy operation `DoThing` (case-insensitive,
     trailing-wildcard stripped). When the item names no operations, this check
     is skipped (alias existence alone is the assertion).
  3. **Statement is verbatim.** When the citation quotes mitigation text (a
     `mitigation_statement` / `statement` field), that text must appear verbatim
     — normalized for case/whitespace/punctuation — in the cited mitigation's
     `statement`. A citation that quotes text not found in Canopy is a FAIL.
     Citations that quote no text are not subject to this check.

Scope: map-framework-mapped.json rows are checked only when the objective row's
`status == "MAPPED"`. `UNCERTAIN` rows are the honest escape hatch and are
exempt. `assessment_gap`-sourced citations name no Canopy mitigation and are not
Canopy citations, so they are naturally out of scope.

CLI:
    python3 validate_canopy_facts.py --slug <slug> [--strict]
    python3 validate_canopy_facts.py --canopy <file> [--plan <p>] [--mapping <m>] \
        [--fw-mapped <f>] [--strict]
Exit codes: 0 ok (or advisory: violations without --strict), 2 factual violation
under --strict.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from canopy_parse import is_canopy_shape, is_canopy_threats_shape  # type: ignore


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _bare_op(action: str) -> str:
    """`bedrock-agentcore:CreateAgentRuntime` -> `createagentruntime`."""
    a = action.split(":", 1)[1] if ":" in action else action
    return a.strip().lower().rstrip("*")


def _normalize_text(text: str) -> str:
    """Fold case, whitespace, and punctuation for verbatim comparison.

    A legitimate citation should not fail on trivial formatting differences
    (a trailing period, doubled spaces, smart quotes), so we compare on a
    normalized form: lowercased, punctuation stripped, whitespace collapsed.
    """
    lowered = (text or "").lower()
    kept = [ch if (ch.isalnum() or ch.isspace()) else " " for ch in lowered]
    return " ".join("".join(kept).split())


def mitigation_statement(canopy: dict, alias: str) -> str:
    """The Canopy `statement` for a mitigation/threat alias (empty if none)."""
    for m in canopy.get("mitigations", []) or []:
        if isinstance(m, dict) and m.get("alias") == alias:
            return str(m.get("statement") or "")
    for t in canopy.get("threats", []) or []:
        if isinstance(t, dict) and t.get("alias") == alias:
            return str(t.get("statement") or "")
    return ""


def canopy_alias_set(canopy: dict) -> set[str]:
    """All mitigation + threat aliases present in the Canopy export."""
    out: set[str] = set()
    for m in canopy.get("mitigations", []) or []:
        if isinstance(m, dict) and m.get("alias"):
            out.add(m["alias"])
    for t in canopy.get("threats", []) or []:
        if isinstance(t, dict) and t.get("alias"):
            out.add(t["alias"])
    return out


def mitigation_operations(canopy: dict, alias: str) -> set[str]:
    """The set of bare operation names a mitigation/threat governs (lowercased).

    Pulled from `configurationRequestParameters[].operation` (mitigations) and
    `requestParameters[].operation` (threats). Empty set when the alias names a
    mitigation with no operation-scoped parameters (some are resource-level only).
    """
    ops: set[str] = set()
    for m in canopy.get("mitigations", []) or []:
        if not isinstance(m, dict) or m.get("alias") != alias:
            continue
        for cp in m.get("configurationRequestParameters", []) or []:
            if isinstance(cp, dict) and cp.get("operation"):
                ops.add(str(cp["operation"]).lower())
    for t in canopy.get("threats", []) or []:
        if not isinstance(t, dict) or t.get("alias") != alias:
            continue
        for cp in t.get("requestParameters", []) or []:
            if isinstance(cp, dict) and cp.get("operation"):
                ops.add(str(cp["operation"]).lower())
    return ops


def _citation_alias(cit: dict) -> str | None:
    """The cited Canopy alias under either field shape.

    map / framework-mapping rows use `source == "canopy"` + `mitigation_alias`;
    preventive-plan rows use `type == "canopy"` + `id`. Returns None when the
    citation is not a Canopy citation.
    """
    if not isinstance(cit, dict):
        return None
    if cit.get("source") == "canopy":
        # A Canopy-sourced map citation. Alias may be absent (caught downstream).
        return cit.get("mitigation_alias")
    if cit.get("type") == "canopy":
        return cit.get("id")
    return None


def _is_canopy_citation(cit: dict) -> bool:
    return isinstance(cit, dict) and (
        cit.get("source") == "canopy" or cit.get("type") == "canopy"
    )


def _quoted_statement(cit: dict) -> str:
    """Any verbatim mitigation text the citation quotes (empty if none)."""
    for k in ("mitigation_statement", "statement"):
        v = cit.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _canopy_cited_items(
    plan: dict | None, mapping: dict | None, fw_mapped: dict | None
) -> list[dict]:
    """Collect {id, alias, actions[], statement, source} for every canopy-cited item.

    Reads preventive-plan.json decisions, mapping-results.json controls, and
    map-framework-mapped.json control rows (MAPPED objectives only — UNCERTAIN
    rows are the honesty escape hatch and are exempt). Only items whose citation
    is a Canopy citation (either field shape) are returned.
    """
    items: list[dict] = []

    def _maybe_add(obj: dict, action_keys: tuple[str, ...], source: str) -> None:
        cit = obj.get("citation")
        if not _is_canopy_citation(cit):
            return
        actions: list[str] = []
        for k in action_keys:
            v = obj.get(k)
            if isinstance(v, list):
                actions.extend(a for a in v if isinstance(a, str))
        items.append({
            "id": obj.get("control_id") or obj.get("id") or "<unknown>",
            "alias": _citation_alias(cit),
            "actions": actions,
            "statement": _quoted_statement(cit),
            "source": source,
        })

    if isinstance(plan, dict):
        for d in plan.get("decisions", []) or []:
            if isinstance(d, dict):
                _maybe_add(d, ("plan_actions", "actions"), "preventive-plan")
    if isinstance(mapping, dict):
        for c in mapping.get("controls", []) or []:
            if isinstance(c, dict):
                _maybe_add(c, ("actions",), "mapping-results")
    if isinstance(fw_mapped, dict):
        for f in fw_mapped.get("framework_mapping", []) or []:
            if not isinstance(f, dict) or f.get("status") != "MAPPED":
                continue
            oid = f.get("objective_id", "<unknown>")
            for cm in f.get("controls", []) or []:
                if isinstance(cm, dict):
                    _maybe_add(cm, ("actions",), f"framework-mapping {oid}")

    return items


def check(
    canopy: dict,
    plan: dict | None,
    mapping: dict | None,
    fw_mapped: dict | None = None,
) -> list[str]:
    """Return factual-violation error strings for canopy-cited items."""
    errors: list[str] = []
    if not (is_canopy_shape(canopy) or is_canopy_threats_shape(canopy)):
        # Not a Canopy file — nothing authoritative to check against. The caller
        # decides whether that is itself a problem; here we stay quiet.
        return errors

    aliases = canopy_alias_set(canopy)
    items = _canopy_cited_items(plan, mapping, fw_mapped)

    for item in items:
        alias = item["alias"]
        if not alias:
            errors.append(
                f"CANOPY-FACT {item['source']} {item['id']}: citation is canopy-sourced "
                f"but names no mitigation alias. A canopy citation must name the "
                f"mitigation alias it claims intent from."
            )
            continue
        if alias not in aliases:
            errors.append(
                f"CANOPY-FACT {item['source']} {item['id']}: cites canopy alias "
                f"{alias!r} which does not exist in the provided Canopy export — "
                f"fabricated or drifted citation."
            )
            continue
        # Operation consistency — only when the item names operations AND the
        # mitigation governs operations (resource-only mitigations are exempt).
        item_ops = {_bare_op(a) for a in item["actions"] if a}
        gov_ops = mitigation_operations(canopy, alias)
        if item_ops and gov_ops and not (item_ops & gov_ops):
            errors.append(
                f"CANOPY-FACT {item['source']} {item['id']}: gated operation(s) "
                f"{sorted(item_ops)} are not among the operations Canopy mitigation "
                f"{alias!r} governs ({sorted(gov_ops)}) — the citation does not "
                f"support this control's target action."
            )
        # Verbatim provenance — only when the citation quotes mitigation text.
        quoted = item.get("statement", "")
        if quoted:
            source_stmt = mitigation_statement(canopy, alias)
            if _normalize_text(quoted) not in _normalize_text(source_stmt):
                errors.append(
                    f"CANOPY-FACT {item['source']} {item['id']}: cited statement "
                    f"{quoted!r} is not found verbatim in Canopy mitigation "
                    f"{alias!r}'s statement — the citation quotes text the Canopy "
                    f"export does not contain."
                )
    return errors


def find_canopy_file(service_root: Path) -> Path | None:
    """Locate the Canopy export for a run via the intake manifest's input folder.

    Reads 00-intake/intake-manifest.json → inputs.input_folder, scans it for a
    .json that `is_canopy_shape`/`is_canopy_threats_shape` recognizes. Returns
    None when no input folder is recorded or no canopy-shaped file is found.
    """
    manifest = _load_json(service_root / "00-intake" / "intake-manifest.json")
    if not isinstance(manifest, dict):
        return None
    folder = (manifest.get("inputs") or {}).get("input_folder")
    if not folder:
        return None
    fpath = Path(folder)
    if not fpath.is_absolute():
        # input_folder is recorded relative to the run's working dir.
        fpath = Path(os.getcwd()) / fpath
    if not fpath.is_dir():
        return None
    for jf in sorted(fpath.glob("*.json")):
        data = _load_json(jf)
        if isinstance(data, dict) and (is_canopy_shape(data) or is_canopy_threats_shape(data)):
            return jf
    return None


def check_service(service_root: Path) -> list[str]:
    """Run the factual check for a service root. No canopy file / no canopy
    citations → no errors (the check is a no-op for non-Canopy runs)."""
    canopy_path = find_canopy_file(service_root)
    if canopy_path is None:
        return []
    canopy = _load_json(canopy_path)
    if not isinstance(canopy, dict):
        return []
    plan = _load_json(service_root / "05-generate" / "preventive-plan.json")
    mapping = _load_json(service_root / "04-map" / "mapping-results.json")
    fw_mapped = _load_json(service_root / "04-map" / "map-framework-mapped.json")
    return check(canopy, plan if isinstance(plan, dict) else None,
                 mapping if isinstance(mapping, dict) else None,
                 fw_mapped if isinstance(fw_mapped, dict) else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--canopy", help="explicit Canopy export path")
    parser.add_argument("--plan", help="explicit preventive-plan.json path")
    parser.add_argument("--mapping", help="explicit mapping-results.json path")
    parser.add_argument("--fw-mapped", dest="fw_mapped",
                        help="explicit map-framework-mapped.json path")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero (block) on any factual violation; "
                             "without it, violations are advisory (exit 0)")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.canopy:
        canopy = _load_json(Path(args.canopy))
        if not isinstance(canopy, dict):
            print(f"ERROR: {args.canopy} unreadable", file=sys.stderr)
            return 2
        plan = _load_json(Path(args.plan)) if args.plan else None
        mapping = _load_json(Path(args.mapping)) if args.mapping else None
        fw_mapped = _load_json(Path(args.fw_mapped)) if args.fw_mapped else None
        errors = check(canopy, plan if isinstance(plan, dict) else None,
                       mapping if isinstance(mapping, dict) else None,
                       fw_mapped if isinstance(fw_mapped, dict) else None)
    else:
        parser.error("provide --slug OR --canopy")

    if errors:
        label = "FAILED" if args.strict else "advisory"
        print(f"CANOPY-FACTUAL {label} ({len(errors)} violations):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 2 if args.strict else 0
    print("canopy-factual: no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
