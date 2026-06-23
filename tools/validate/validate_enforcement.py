#!/usr/bin/env python3
"""
Per-statement enforcement check for authored preventive artifacts.

The preventability analyzer (validate_preventability.py) answers a *mapping*-time
question: can this control objective be prevented at request time, and with which
key? This module answers the harder *generate*-time question, statement by
statement, over the policy text that was actually authored:

    For each statement in each authored preventive policy, is the enforcing
    condition key EVALUABLE where it was placed, does it apply to the action it
    gates, and is the Resource ARN well-formed?

A statement can name a real condition key that gates the target action and still
be a silent no-op, because correctness depends on *where* the key sits:

  - A request-time-only key (one bound solely to a policy-management action, e.g.
    `lambda:Principal` → AddPermission/RemovePermission) placed inside an ATTACHED
    resource-based policy never fires — the document is not in the evaluation path
    for that request. (The same key in an SCP/identity policy IS evaluable: those
    evaluate the request.)
  - A Resource ARN with the wrong delimiter (`function/*` instead of `function:*`)
    matches nothing — the deny is a no-op.
  - A key whose `applies_to_actions` does not intersect the statement's actions
    gates a different operation than the one denied.

This module reuses the request-time-key derivation from validate_preventability
and the ARN-delimiter logic from validate_pipeline_integrity, so the same
architectural rules back both the mapping-time and generate-time checks. It emits
a per-statement record `{sid, action, resource_arn, enforcing_key, evaluable,
reason}` — the data the root-cause critic writes into rootcause-report.json so a
non-evaluable statement is visible at generation time, not just at the Stop gate.

Policy type is inferred from the artifact filename (scp-policy → scp,
resource-policy → resource-based, permission-boundary → boundary, …). Only
resource-based policies are subject to the request-time-only-key evaluability
rule; the other types evaluate the request and so can use request-time keys.

CLI:
    python3 validate_enforcement.py --slug <slug>
    python3 validate_enforcement.py --preventive-dir <dir> --validated <path>
Exit codes:
    0 — every authored statement is evaluable (or no artifacts)
    2 — at least one statement is not evaluable (with --strict)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_preventability import (  # noqa: E402
    _is_resource_policy_mgmt_action,
    build_condition_key_index,
    normalize_action,
    request_time_only_keys,
)
from validate_pipeline_integrity import (  # noqa: E402
    _arn_delimiter_errors,
    _resource_type_delimiters,
)


# Authored-artifact basename → policy type. The resource-based evaluability
# rules apply to ATTACHED policies (resource-based + KMS key policy, which is
# attached to the key); SCP, identity, boundary and VPCE policies evaluate the
# request itself.
_FILE_POLICY_TYPE = {
    "scp-policy": "scp",
    "rcp-policy": "rcp",
    "iam-policies": "identity",
    "permission-boundary": "boundary",
    "resource-policy": "resource-based",
    "vpce-policy": "vpce",
    "kms-key-policy": "resource-based",  # a key policy is attached to the key
}

# Artifacts that are reports / hand-offs, not policy documents — skip them.
_NON_POLICY_BASENAMES = {"rootcause-report", "detective-routing"}


def policy_type_for_file(filename: str) -> str | None:
    """Infer the policy type from an artifact filename, or None if not a policy.

    Matches on the stem with any numeric split suffix removed (scp-policy-2 →
    scp-policy), so a split SCP file is still typed correctly.
    """
    stem = Path(filename).stem
    if stem in _NON_POLICY_BASENAMES:
        return None
    # Strip a trailing numeric split suffix (`scp-policy-2` → `scp-policy`).
    base = stem
    parts = stem.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        base = parts[0]
    return _FILE_POLICY_TYPE.get(base)


def _statement_condition_keys(stmt: dict) -> list[str]:
    """All condition keys named anywhere in a statement's Condition block."""
    keys: list[str] = []
    cond = stmt.get("Condition") or {}
    if not isinstance(cond, dict):
        return keys
    for kv in cond.values():
        if isinstance(kv, dict):
            keys.extend(kv.keys())
    # De-dup, stable.
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _service_specific_keys(keys: list[str], service_prefix: str) -> list[str]:
    """The non-global condition keys — the ones that carry the control's intent.

    Global keys (`aws:...`) such as aws:PrincipalARN scope WHO the statement
    applies to; a service-specific key (anything not in the `aws:` namespace,
    e.g. `lambda:Principal`, `iam:PassedToService`) is the enforcing gate. A
    statement with only global keys has no service-specific enforcing key.
    """
    return [k for k in keys if not k.startswith("aws:")]


def assess_statement(
    stmt: dict,
    policy_type: str,
    validated: dict,
    delims: dict,
    service_prefix: str,
) -> dict:
    """Return the per-statement enforcement record.

    Keys: sid, action[], resource_arn[], enforcing_key[], evaluable (bool),
    reason. `evaluable` is False when (a) the enforcing key is request-time-only
    and the policy is resource-based, (b) a Resource ARN is malformed, or (c) the
    enforcing key does not apply to any gated action.
    """
    sid = stmt.get("Sid", "")
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    not_resources = stmt.get("NotResource", [])
    if isinstance(not_resources, str):
        not_resources = [not_resources]

    all_keys = _statement_condition_keys(stmt)
    enforcing = _service_specific_keys(all_keys, service_prefix)

    record = {
        "sid": sid,
        "action": list(actions),
        "resource_arn": list(resources),
        "enforcing_key": enforcing,
        "evaluable": True,
        "reason": "",
    }

    # Only Deny statements implement a control's invariant; an Allow floor
    # (boundary baseline, VPCE allow) is not the enforcing gate and is checked
    # for minimality elsewhere. We still validate its ARNs below.
    is_deny = stmt.get("Effect") == "Deny"

    # (b) ARN well-formedness — applies to every statement, Resource AND
    # NotResource (a malformed ARN in either matches nothing).
    for arn in [*resources, *not_resources]:
        err = _arn_delimiter_errors(arn, service_prefix, delims)
        if err:
            record["evaluable"] = False
            record["reason"] = f"malformed resource ARN — {err}"
            return record

    if not is_deny:
        return record

    # (a0) Resource-based policy whose gated actions are ALL policy-management
    # actions → the attached document is never in the evaluation path for those
    # requests, so the deny is a no-op REGARDLESS of which condition key gates it.
    # This is action-driven (not key-driven) so it cannot be masked by a key that
    # merely co-applies to the management action (the key-based check below only
    # fires when EVERY enforcing key is request-time-only, which a co-applying
    # access key would defeat).
    if policy_type == "resource-based" and actions:
        bare = [a for a in actions if isinstance(a, str)]
        if bare and all(_is_resource_policy_mgmt_action(a) for a in bare):
            record["evaluable"] = False
            record["reason"] = (
                "a resource-based policy cannot enforce a deny on a "
                f"policy-management action ({', '.join(bare)}); the attached "
                "document is not in the evaluation path for that request, so the "
                "deny never fires. Route to detective or re-map to an SCP/identity "
                "policy that evaluates the request."
            )
            return record

    # Checks (a) and (c) operate on the SERVICE-SPECIFIC enforcing keys. A Deny
    # may legitimately gate on a global key alone — e.g. a VPCE / data-perimeter
    # org-scoping deny conditioned only on aws:PrincipalOrgID. Global keys are
    # principal-context, always evaluable and not action-bound, so a statement
    # with no service-specific key is not flagged by (a)/(c); the ARN check above
    # and the boundary-minimality check (separate) still apply.
    if not enforcing:
        return record

    # (a) Resource-based policy + request-time-only enforcing key → not evaluable.
    if policy_type == "resource-based":
        rt_only = request_time_only_keys(validated)
        offending = [k for k in enforcing if k in rt_only]
        if offending and all(k in rt_only for k in enforcing):
            record["evaluable"] = False
            record["reason"] = (
                "a resource-based policy cannot evaluate a request-time condition "
                f"key bound to the policy-management action ({', '.join(offending)}); "
                "the attached document is not in the evaluation path for that "
                "request, so the deny never fires."
            )
            return record

    # (c) The enforcing key must apply to at least one gated action.
    bare_actions = {normalize_action(a) for a in actions if isinstance(a, str)}
    ck_index = {
        ck.get("key"): {normalize_action(a) for a in ck.get("applies_to_actions", []) if a}
        for ck in build_condition_key_index(validated)
        if ck.get("key")
    }
    wildcard_stems = {a[:-1] for a in bare_actions if a.endswith("*")}
    concrete = {a for a in bare_actions if not a.endswith("*")}

    def _key_applies(key: str) -> bool:
        applies = ck_index.get(key)
        if applies is None:
            # Key absent from the SAR snapshot — lower-bound rule: do not call it
            # non-applicable (it may be a doc-cited key). Treat as applicable.
            return True
        if not applies:
            return False
        if applies & concrete:
            return True
        return any(any(a.startswith(s) for a in applies) for s in wildcard_stems)

    if not any(_key_applies(k) for k in enforcing):
        record["evaluable"] = False
        record["reason"] = (
            f"the enforcing key(s) {enforcing} do not apply to the gated "
            f"action(s) {sorted(bare_actions)} — the key gates a different "
            "operation than the one denied."
        )
        return record

    return record


def assess_artifact(
    path: Path, validated: dict, delims: dict, service_prefix: str
) -> dict | None:
    """Assess one authored preventive artifact. None if it is not a policy doc."""
    policy_type = policy_type_for_file(path.name)
    if policy_type is None:
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or "Statement" not in data:
        return None
    statements = data["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    records = []
    for stmt in statements:
        if isinstance(stmt, dict):
            records.append(
                assess_statement(stmt, policy_type, validated, delims, service_prefix)
            )
    return {
        "artifact": path.name,
        "policy_type": policy_type,
        "statements": records,
        "all_evaluable": all(r["evaluable"] for r in records),
    }


def assess_preventive_dir(preventive_dir: Path, validated: dict) -> list[dict]:
    """Assess every authored policy artifact under a preventive/ directory."""
    sar_facts: dict = {}
    # validated.json sometimes carries the prefix; otherwise read sar-facts.
    service_prefix = (
        validated.get("capabilities", {}).get("iam", {}).get("service_prefix")
        or validated.get("service_prefix")
        or ""
    )
    delims: dict = {}
    # The sibling 01-assess/sar-facts.json holds the authoritative ARN patterns.
    sar_path = preventive_dir.parent.parent / "01-assess" / "sar-facts.json"
    if sar_path.exists():
        try:
            sar_facts = json.loads(sar_path.read_text())
            delims = _resource_type_delimiters(sar_facts)
            service_prefix = service_prefix or sar_facts.get("service_prefix") or ""
        except (OSError, json.JSONDecodeError):
            pass

    out = []
    if not preventive_dir.exists():
        return out
    for path in sorted(preventive_dir.glob("*.json")):
        result = assess_artifact(path, validated, delims, service_prefix)
        if result is not None:
            out.append(result)
    return out


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--preventive-dir", help="path to 05-generate/preventive/")
    parser.add_argument("--validated", help="path to validated.json")
    parser.add_argument(
        "--strict", action="store_true",
        help="exit 2 if any authored statement is not evaluable",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON records")
    args = parser.parse_args()

    if args.slug:
        base = Path(os.getcwd()) / ".service-approval" / args.slug
        preventive_dir = Path(args.preventive_dir or base / "05-generate" / "preventive")
        validated_path = args.validated or base / "03-validate" / "validated.json"
    else:
        if not (args.preventive_dir and args.validated):
            parser.error("provide --slug OR both --preventive-dir and --validated")
        preventive_dir = Path(args.preventive_dir)
        validated_path = args.validated

    validated = _load_json(validated_path)
    results = assess_preventive_dir(preventive_dir, validated)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for art in results:
            flag = "OK" if art["all_evaluable"] else "FAIL"
            print(f"{flag:6} {art['artifact']} ({art['policy_type']})")
            for r in art["statements"]:
                if not r["evaluable"]:
                    print(f"    NOT EVALUABLE [{r['sid']}]: {r['reason']}")

    if args.strict:
        bad = [a for a in results if not a["all_evaluable"]]
        if bad:
            n = sum(
                1 for a in bad for r in a["statements"] if not r["evaluable"]
            )
            print(
                f"\n{n} authored statement(s) are not evaluable — remove the "
                f"artifact and route the objective to detective.",
                file=sys.stderr,
            )
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
