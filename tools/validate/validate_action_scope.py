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


# Condition keys that legitimately imply a cross-service enforcement action a
# control's mapping actions[] would not list. The canonical case: a control whose
# intent is "cap the execution role passed on create" carries iam:PassedToService
# / iam:AssociatedResourceArn and MUST deny iam:PassRole — an action that is not in
# the (Lambda-only) mapping actions[]. So when a control declares such a key, the
# implied action is part of its reviewed set.
_KEY_IMPLIED_ACTIONS = {
    "iam:passedtoservice": {"iam:PassRole"},
    "iam:associatedresourcearn": {"iam:PassRole"},
    "iam:passedtoservicelist": {"iam:PassRole"},
}


def _norm(action: str) -> str:
    """Case-fold an action for comparison (IAM is case-insensitive on service:op)."""
    return action.strip().lower()


def reviewed_actions_by_control(
    plan: dict, mapping: dict
) -> dict[str, dict]:
    """Map control_id → {actions: set[str], authoritative: bool}.

    `authoritative` is True when the set came from the plan decision's explicit
    `plan_actions[]` (the reviewed contract); False when it fell back to the
    mapping control's `actions[]` (a looser superset that may itself contain
    creep). A non-authoritative mismatch is reported as a WARN, not a hard FAIL,
    so the gate does not block on the known-loose fallback. The reviewed set is
    augmented with any cross-service action implied by the control's declared
    condition keys (e.g. iam:PassRole for an iam:PassedToService control).
    """
    out: dict[str, dict] = {}
    map_by_id: dict[str, dict] = {}
    for c in mapping.get("controls", []):
        cid = c.get("id")
        if cid:
            map_by_id[cid] = c

    def _implied(cid: str) -> set[str]:
        keys = [
            _norm(k) for k in (map_by_id.get(cid, {}).get("condition_keys") or [])
            if isinstance(k, str)
        ]
        implied: set[str] = set()
        for k in keys:
            implied |= _KEY_IMPLIED_ACTIONS.get(k, set())
        return implied

    def _mapping_actions(cid: str) -> set[str]:
        return {a for a in (map_by_id.get(cid, {}).get("actions") or [])
                if isinstance(a, str)}

    for d in plan.get("decisions", []):
        if not isinstance(d, dict):
            continue
        cid = d.get("control_id")
        if not cid:
            continue
        if d.get("plan_actions"):
            actions = {a for a in d["plan_actions"] if isinstance(a, str)}
            out[cid] = {"actions": actions | _implied(cid), "authoritative": True}
        else:
            out[cid] = {"actions": _mapping_actions(cid) | _implied(cid),
                        "authoritative": False}

    for cid in map_by_id:
        out.setdefault(cid, {"actions": _mapping_actions(cid) | _implied(cid),
                             "authoritative": False})
    return out


def _statement_actions(stmt: dict) -> list[str]:
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        return [actions]
    return [a for a in actions if isinstance(a, str)]


def assess_artifact_scope(
    path: Path, reviewed: dict[str, dict]
) -> list[str]:
    """Return scope-creep findings for one authored artifact.

    Each finding is prefixed `FAIL` (authoritative plan_actions contract violated)
    or `WARN` (only the looser mapping fallback was available — the action is not
    in the mapping superset either, but the set is not the reviewed contract).
    """
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

        # A Deny written with NotAction authorizes over the COMPLEMENT of the
        # listed actions — an unbounded surface that cannot be reconciled with a
        # reviewed allowlist. Always flag it.
        if "NotAction" in stmt:
            errors.append(
                f"FAIL {path.name} Statement[{i}] (Sid {sid!r}): Deny uses "
                f"NotAction, which authorizes over every action EXCEPT those "
                f"listed — an unbounded surface that cannot be reviewed against a "
                f"reviewed action set. Rewrite as an explicit Action allowlist."
            )
            continue

        cid = control_id_from_sid(sid)
        if cid and cid in reviewed:
            entry = reviewed[cid]
        else:
            # No recognizable control suffix → union of every control the
            # artifact declares (a superset; keeps the check conservative). The
            # union is authoritative only if every contributing control is.
            actions: set[str] = set()
            auth = bool(meta_controls)
            for mc in meta_controls:
                e = reviewed.get(mc)
                if e:
                    actions |= e["actions"]
                    auth = auth and e["authoritative"]
                else:
                    auth = False
            if not actions:
                continue  # nothing to check against — do not guess
            entry = {"actions": actions, "authoritative": auth}

        allowed_norm = {_norm(a) for a in entry["actions"]}
        prefix = "FAIL" if entry["authoritative"] else "WARN"
        for action in _statement_actions(stmt):
            if _norm(action) not in allowed_norm:
                errors.append(
                    f"{prefix} {path.name} Statement[{i}] (Sid {sid!r}): authored "
                    f"Deny lists action {action!r} not in the reviewed action set "
                    f"{sorted(entry['actions'])} for "
                    f"{cid or 'the artifact controls'} — "
                    + ("unreviewed scope-creep. " if entry["authoritative"]
                       else "not in the mapping action set (no plan_actions[] "
                            "recorded, so this is the looser fallback). ")
                    + "Every action a Deny authorizes over must be reviewed; "
                    "record it in the plan's plan_actions[] (after confirming "
                    "intent) or remove it from the statement."
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
    findings = assess_preventive_dir_scope(preventive_dir, plan, mapping)

    if findings:
        for e in findings:
            print(f"  {e}")
        # Only authoritative-contract violations (FAIL) block under --strict; a
        # WARN means only the looser mapping fallback was available (no
        # plan_actions recorded), so it is surfaced but does not fail the gate.
        fails = [e for e in findings if e.startswith("FAIL")]
        if args.strict and fails:
            print(
                f"\n{len(fails)} authored deny action(s) violate the reviewed "
                f"plan_actions[] contract — review and record them or remove them.",
                file=sys.stderr,
            )
            sys.exit(2)
    else:
        print("No authored-deny action scope-creep.")
    sys.exit(0)


if __name__ == "__main__":
    main()
