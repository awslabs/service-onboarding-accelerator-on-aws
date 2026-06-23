#!/usr/bin/env python3
"""
Canopy-factual validator (deterministic).

When a control or preventive decision cites a Canopy mitigation as its intent
source (`citation.type == "canopy"`), that citation must be FACTUAL: the cited
mitigation `alias` must actually exist in the provided Canopy export, and the
control's gated operation must be consistent with that mitigation's
`configurationRequestParameters[]`. This catches a fabricated or drifted Canopy
citation — a control that claims Canopy intent the Canopy file does not support.

It is deterministic (no LLM): pure set membership against the Canopy file. Runs
in BOTH review gates (post-map and post-generate).

Two checks per canopy-cited item:
  1. **Alias exists.** `citation.id` must match a `mitigations[].alias` (or, when
     the item cites a threat, a `threats[].alias`) in the Canopy export.
  2. **Operation consistency.** When the item names gated operations (a control's
     `actions[]`, or a plan row's `plan_actions[]`), at least one must correspond
     to an operation the cited mitigation actually governs (the
     `configurationRequestParameters[].operation` set). An IAM action
     `prefix:DoThing` maps to the Canopy operation `DoThing` (case-insensitive,
     trailing-wildcard stripped). When the item names no operations, this check
     is skipped (alias existence alone is the assertion).

CLI:
    python3 validate_canopy_facts.py --slug <slug>
    python3 validate_canopy_facts.py --canopy <file> [--plan <p>] [--mapping <m>]
Exit codes: 0 ok (or no canopy citations / no canopy file), 2 factual violation.
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


def _canopy_cited_items(plan: dict | None, mapping: dict | None) -> list[dict]:
    """Collect {id, alias, actions[], source} for every canopy-cited item.

    Reads preventive-plan.json decisions and mapping-results.json controls.
    Only items whose `citation.type == "canopy"` are returned.
    """
    items: list[dict] = []

    def _maybe_add(obj: dict, action_keys: tuple[str, ...], source: str) -> None:
        cit = obj.get("citation")
        if not isinstance(cit, dict) or cit.get("type") != "canopy":
            return
        actions: list[str] = []
        for k in action_keys:
            v = obj.get(k)
            if isinstance(v, list):
                actions.extend(a for a in v if isinstance(a, str))
        items.append({
            "id": obj.get("control_id") or obj.get("id") or "<unknown>",
            "alias": cit.get("id"),
            "actions": actions,
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

    return items


def check(canopy: dict, plan: dict | None, mapping: dict | None) -> list[str]:
    """Return factual-violation error strings for canopy-cited items."""
    errors: list[str] = []
    if not (is_canopy_shape(canopy) or is_canopy_threats_shape(canopy)):
        # Not a Canopy file — nothing authoritative to check against. The caller
        # decides whether that is itself a problem; here we stay quiet.
        return errors

    aliases = canopy_alias_set(canopy)
    items = _canopy_cited_items(plan, mapping)

    for item in items:
        alias = item["alias"]
        if not alias:
            errors.append(
                f"CANOPY-FACT {item['source']} {item['id']}: citation.type==canopy "
                f"but no citation.id (mitigation alias). A canopy citation must name "
                f"the mitigation alias it claims intent from."
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
    return check(canopy, plan if isinstance(plan, dict) else None,
                 mapping if isinstance(mapping, dict) else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--canopy", help="explicit Canopy export path")
    parser.add_argument("--plan", help="explicit preventive-plan.json path")
    parser.add_argument("--mapping", help="explicit mapping-results.json path")
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
        errors = check(canopy, plan if isinstance(plan, dict) else None,
                       mapping if isinstance(mapping, dict) else None)
    else:
        parser.error("provide --slug OR --canopy")

    if errors:
        print(f"CANOPY-FACTUAL FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 2
    print("canopy-factual: no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
