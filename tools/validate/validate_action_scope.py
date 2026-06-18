#!/usr/bin/env python3
"""
Authored-deny action scope-creep check.

Every action a preventive Deny authorizes over must have been reviewed. The
recommender decides which actions a control's policy should gate and records them
on the plan row (`plan_actions[]`); when that is absent it falls back to the
originating mapping control's `actions[]`. An authored Deny statement that lists
an action OUTSIDE that reviewed set is silent scope-creep: the action may be
SAR-bound to the enforcing key (so it is not unsound), but it was never reviewed
as part of the control's intent — exactly the class where a policy quietly denies
more than the mapping described.

This catches, for example, an authored VPC-config Deny over
`[CreateFunction, UpdateFunctionConfiguration]` that also lists
`CreateCapacityProvider` only because the subnet key happens to apply to it.

Statement→control linkage uses the `Sid` suffix the authors emit (e.g.
`DenyLambdaWithoutVpcConfigCtrlOrgPrv002` → `CTRL-ORG-PRV-002`); when a statement
carries no recognizable control suffix, every control listed in the artifact's
`_metadata.controls[]` contributes its reviewed actions (a superset, so the check
stays conservative and does not false-positive on shared statements).

CLI:
    python3 validate_action_scope.py --slug <slug>
    python3 validate_action_scope.py --preventive-dir <dir> --plan <path> --mapping <path>
Exit codes:
    0 — no scope-creep (or no artifacts)
    2 — an authored Deny lists an unreviewed action (with --strict)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


# Sid suffix → control id. The authors suffix each Sid with the control id in
# PascalCase (CtrlOrgPrv002); recover the canonical CTRL-ORG-PRV-002 form.
_SID_CONTROL_RE = re.compile(r"Ctrl(Org|Acc|Res)(Pro|Prv|Det|Cor)(\d{3})")


def control_id_from_sid(sid: str) -> str | None:
    """Recover CTRL-ORG-PRV-NNN from a Sid suffix, or None if absent."""
    m = _SID_CONTROL_RE.search(sid or "")
    if not m:
        return None
    return f"CTRL-{m.group(1).upper()}-{m.group(2).upper()}-{m.group(3)}"


def reviewed_actions_by_control(plan: dict, mapping: dict) -> dict[str, set[str]]:
    """Map control_id → the reviewed action set.

    Prefer the plan decision's `plan_actions[]`; fall back to the mapping
    control's `actions[]`. Returns a dict only for controls that have a reviewed
    set from one of those sources.
    """
    out: dict[str, set[str]] = {}
    mapping_actions: dict[str, set[str]] = {}
    for c in mapping.get("controls", []):
        cid = c.get("id")
        if cid:
            mapping_actions[cid] = {a for a in c.get("actions", []) if isinstance(a, str)}

    for d in plan.get("decisions", []):
        if not isinstance(d, dict):
            continue
        cid = d.get("control_id")
        if not cid:
            continue
        if d.get("plan_actions"):
            out[cid] = {a for a in d["plan_actions"] if isinstance(a, str)}
        elif cid in mapping_actions:
            out[cid] = set(mapping_actions[cid])
    # Controls present in the mapping but not the plan still get their mapping
    # action set (so a statement attributed to them can be checked).
    for cid, acts in mapping_actions.items():
        out.setdefault(cid, acts)
    return out


def _statement_actions(stmt: dict) -> list[str]:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        return [actions]
    return [a for a in actions if isinstance(a, str)]


def assess_artifact_scope(
    path: Path, reviewed: dict[str, set[str]]
) -> list[str]:
    """Return scope-creep errors for one authored artifact."""
    errors: list[str] = []
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return errors
    if not isinstance(data, dict) or "Statement" not in data:
        return errors
    statements = data["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    meta_controls = []
    meta = data.get("_metadata") or {}
    if isinstance(meta, dict):
        meta_controls = [c for c in (meta.get("controls") or []) if isinstance(c, str)]

    for i, stmt in enumerate(statements):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Deny":
            continue
        sid = stmt.get("Sid", "")
        cid = control_id_from_sid(sid)
        if cid and cid in reviewed:
            allowed = reviewed[cid]
        else:
            # No recognizable control suffix → union of every control the
            # artifact declares (a superset; keeps the check conservative).
            allowed = set()
            for mc in meta_controls:
                allowed |= reviewed.get(mc, set())
            if not allowed:
                continue  # nothing to check against — do not guess
        for action in _statement_actions(stmt):
            if action not in allowed:
                errors.append(
                    f"{path.name} Statement[{i}] (Sid {sid!r}): authored Deny "
                    f"lists action {action!r} not in the reviewed action set "
                    f"{sorted(allowed)} for "
                    f"{cid or 'the artifact controls'} — unreviewed scope-creep. "
                    f"Every action a Deny authorizes over must be reviewed; add "
                    f"it to the plan's plan_actions[] (after confirming intent) "
                    f"or remove it from the statement."
                )
    return errors


def assess_preventive_dir_scope(
    preventive_dir: Path, plan: dict, mapping: dict
) -> list[str]:
    """Scope-creep errors across every authored policy artifact."""
    errors: list[str] = []
    if not preventive_dir.exists():
        return errors
    reviewed = reviewed_actions_by_control(plan, mapping)
    for path in sorted(preventive_dir.glob("*.json")):
        if path.name in ("rootcause-report.json", "detective-routing.json"):
            continue
        errors.extend(assess_artifact_scope(path, reviewed))
    return errors


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug")
    parser.add_argument("--preventive-dir")
    parser.add_argument("--plan")
    parser.add_argument("--mapping")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    if args.slug:
        base = Path(os.getcwd()) / ".service-approval" / args.slug
        preventive_dir = Path(args.preventive_dir or base / "05-generate" / "preventive")
        plan_path = args.plan or base / "05-generate" / "preventive-plan.json"
        mapping_path = args.mapping or base / "04-map" / "mapping-results.json"
    else:
        if not (args.preventive_dir and args.plan and args.mapping):
            parser.error("provide --slug OR --preventive-dir, --plan and --mapping")
        preventive_dir = Path(args.preventive_dir)
        plan_path, mapping_path = args.plan, args.mapping

    plan = _load_json(plan_path) if Path(plan_path).exists() else {}
    mapping = _load_json(mapping_path) if Path(mapping_path).exists() else {}
    errors = assess_preventive_dir_scope(preventive_dir, plan, mapping)

    if errors:
        for e in errors:
            print(f"  {e}")
        if args.strict:
            print(
                f"\n{len(errors)} unreviewed authored deny action(s) — "
                f"review and record them or remove them.",
                file=sys.stderr,
            )
            sys.exit(2)
    else:
        print("No authored-deny action scope-creep.")
    sys.exit(0)


if __name__ == "__main__":
    main()
