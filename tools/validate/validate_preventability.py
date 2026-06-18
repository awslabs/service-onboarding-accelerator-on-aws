#!/usr/bin/env python3
"""
Preventability / root-cause check for preventive controls.

A preventive control is only meaningful if a request-time mechanism (SCP / RCP /
IAM policy / permission boundary / resource-based policy / KMS key policy) can
actually enforce its invariant. The enforcement hinges on a **condition key**
that gates the control's target action(s): without a gating key, an SCP that
"denies X unless Y" silently never fires — AWS IAM ignores conditions it cannot
evaluate, so the guardrail is a no-op. Those controls must be routed to a
detective mechanism instead of authoring a non-enforcing policy.

This module answers, per control:

    Is this preventive control PREVENTABLE at request time, and if so, which
    condition key(s) enforce it?

Algorithm (per the root-cause approach):
  1. Identify the control's target action(s) (control.actions[], normalized to
     bare operation names).
  2. Look up the service condition keys (validated.json
     capabilities.iam.condition_keys[]) and find any whose applies_to_actions
     intersects the target actions.
  3. If at least one gating key exists  -> FEASIBLE. The preventive policy MUST
     use one of those keys; we surface them as `enforcing_condition_keys`.
     If none exists                     -> NOT_PREVENTABLE. Route to detective.

The SAR condition-key list is treated as a LOWER BOUND, not a closed set: a
control may declare its own `condition_keys[]` (grounded in a doc citation) that
are not yet in the SAR snapshot. Those are honored — absence from the SAR is not
proof a key does not exist. A control with no target actions at all is treated
as not-preventable (nothing to gate).

Verdicts: "FEASIBLE" | "NOT_PREVENTABLE".

CLI:
    python3 validate_preventability.py --slug <slug>
    python3 validate_preventability.py --mapping <path> --validated <path>
Exit codes:
    0 — ran successfully (verdicts printed; this is an advisory analyzer)
    2 — a control mapped to a request-time mechanism is NOT_PREVENTABLE
        (with --strict); without --strict, always exits 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


# Mechanisms that enforce at AWS IAM request-evaluation time. Only these depend
# on a condition key to function; a NOT_PREVENTABLE verdict for one of these is
# the actionable signal (route to detective). Mechanism strings mirror the
# values map-generate-controls writes into mapping-results.json.controls[].mechanism.
REQUEST_TIME_MECHANISMS = {
    "scp",
    "rcp",
    "iam policy",
    "iam trust policy",
    "iam permission boundary",
    "permission boundary",
    "resource policy",
    "resource-based policy",
    "vpce policy",
    "kms key policy",
}

# Tag-based gating works through global keys (aws:RequestTag/*, aws:TagKeys,
# aws:ResourceTag/*) that are not part of a service's condition_keys[] list but
# DO enforce at request time. A control whose target actions are taggable can be
# prevented via these even with zero service-specific keys.
_GLOBAL_TAG_KEYS = (
    "aws:RequestTag",
    "aws:ResourceTag",
    "aws:TagKeys",
    "aws:PrincipalTag",
)

# Mechanisms whose policy document is ATTACHED TO the resource (a resource-based
# policy). AWS evaluates such a document when a principal tries to *access* the
# resource (invoke, read, …) — it is NOT the authority for the operations that
# *mutate the policy itself*. Those mutations are gated at the request layer by
# the caller's identity policy / SCP.
_RESOURCE_BASED_MECHANISMS = {"resource policy", "resource-based policy"}

# Action-name patterns for operations that MANAGE a resource-based policy or its
# grants (rather than access the resource): grant add/remove and explicit policy
# put/set/delete/get. These follow AWS-wide naming conventions across services
# (Lambda Add/RemovePermission, ECR/S3/SNS Put*Policy, generic *ResourcePolicy),
# so the rule is name-pattern driven, not hardcoded to any one service.
_RESOURCE_POLICY_MGMT_ACTION_RE = re.compile(
    r"(Permission$|ResourcePolicy$|^(Put|Set|Delete|Get)[A-Za-z]*Policy$)"
)


def _is_resource_policy_mgmt_action(action: str) -> bool:
    """True if an action manages a resource-based policy / its grants.

    Such actions are authorized at the request layer (identity policy / SCP),
    not from inside the attached resource policy.
    """
    return bool(_RESOURCE_POLICY_MGMT_ACTION_RE.search(normalize_action(action)))


def request_time_only_keys(validated: dict) -> set[str]:
    """Condition keys that exist only in the request context of a policy-
    management action — and so cannot be evaluated from inside an attached
    resource-based policy document.

    Seeded data-drivenly from validated.json action↔key bindings: a key whose
    `applies_to_actions` are ALL resource-policy-management actions (e.g.
    `lambda:Principal` → bound only to AddPermission/RemovePermission) gates the
    *request to change the policy*, not access through the attached document. A
    Deny placed in the attached document and conditioned on such a key silently
    never fires. No service is hardcoded — membership is derived from the
    snapshot's own bindings.
    """
    out: set[str] = set()
    for ck in build_condition_key_index(validated):
        key = ck.get("key")
        applies = [a for a in ck.get("applies_to_actions", []) if a]
        if not key or not applies:
            continue
        if all(_is_resource_policy_mgmt_action(a) for a in applies):
            out.add(key)
    return out


def normalize_action(action: str) -> str:
    """Strip a service prefix and trailing wildcard from an action string.

    `lambda:CreateFunction` -> `CreateFunction`; `ecs:Create*` -> `Create*`;
    `CreateService` -> `CreateService`.
    """
    a = action.split(":", 1)[1] if ":" in action else action
    return a.strip()


def _controls_request_body_param(control: dict) -> bool:
    """True if any parameters_controlled[] entry names a request-body field.

    Request-body paths name a specific parameter on the call, e.g.
    `$.lambda/CreateFunction.KMSKeyArn`, `$.VpcConfig.SubnetIds`, or
    `$.encryptionKeyArn`. A bare root path (`$.` / `$`) is an endpoint- or
    whole-request-level concern, which a VPCE policy CAN address. We treat any
    path with a named field component (a `.` followed by a non-empty segment)
    as a request-body parameter.
    """
    params = control.get("parameters_controlled") or []
    for p in params:
        if not isinstance(p, str):
            continue
        body = p[2:] if p.startswith("$.") else p.lstrip("$")
        # A named field after stripping the `$.` root → request-body parameter.
        if body and body not in (".", ""):
            return True
    return False


def _bare_actions(actions: list[str]) -> set[str]:
    return {normalize_action(a) for a in actions if isinstance(a, str) and a}


def build_condition_key_index(validated: dict) -> list[dict]:
    """Return the service condition_keys[] entries (with applies_to_actions)."""
    return validated.get("capabilities", {}).get("iam", {}).get("condition_keys", [])


def find_enforcing_keys(
    target_actions: set[str], condition_keys: list[dict]
) -> list[str]:
    """Return condition keys whose applies_to_actions intersect target_actions.

    Matching is on bare operation names. A condition key that lists `*` (applies
    to all) or whose applies_to_actions is empty-but-present is treated as not a
    specific gate (we require a concrete action intersection to claim feasibility).
    Wildcard target actions (`Create*`) match any applies_to action sharing the
    stem.
    """
    if not target_actions:
        return []
    enforcing: list[str] = []
    # Pre-split wildcard targets into stems for prefix matching.
    wildcard_stems = {t[:-1] for t in target_actions if t.endswith("*")}
    concrete = {t for t in target_actions if not t.endswith("*")}

    for ck in condition_keys:
        key = ck.get("key")
        if not key:
            continue
        applies = {normalize_action(a) for a in ck.get("applies_to_actions", []) if a}
        if not applies:
            continue
        # Concrete intersection.
        if applies & concrete:
            enforcing.append(key)
            continue
        # Wildcard stem match (control targets Create*, key applies to CreateX).
        if any(any(a.startswith(stem) for a in applies) for stem in wildcard_stems):
            enforcing.append(key)
    # Stable, de-duplicated.
    seen: set[str] = set()
    out: list[str] = []
    for k in enforcing:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def assess_control(control: dict, validated: dict) -> dict:
    """Return a preventability verdict dict for one control.

    Keys: id, mechanism, verdict ("FEASIBLE"|"NOT_PREVENTABLE"),
    enforcing_condition_keys[], target_actions[], reason, route_to.
    """
    mechanism = (control.get("mechanism") or "").strip()
    target_actions = _bare_actions(control.get("actions", []))
    condition_keys = build_condition_key_index(validated)

    # VPCE-policy scope guard. A VPC-endpoint policy evaluates at the endpoint
    # boundary (Action x Principal x ResourceArn); it cannot see request-body
    # parameters of a Create/Update call (e.g. $.lambda/CreateFunction.SubnetIds).
    # So a VPCE-policy control whose parameters_controlled[] names a request-body
    # field is not preventable by that mechanism — route to detective regardless
    # of whether a condition key happens to exist for the action.
    if "vpce" in mechanism.lower() and _controls_request_body_param(control):
        return {
            "id": control.get("id"),
            "mechanism": mechanism,
            "verdict": "NOT_PREVENTABLE",
            "enforcing_condition_keys": [],
            "target_actions": sorted(target_actions),
            "route_to": "detective",
            "reason": (
                "VPCE policy gates endpoint use, not request-body parameters; it "
                "cannot enforce a parameter on a Create/Update call. Route to a "
                "detective mechanism or re-map to an SCP/IAM-based control."
            ),
        }

    enforcing = find_enforcing_keys(target_actions, condition_keys)

    # Lower-bound rule: honor control-declared condition keys not in the SAR
    # snapshot (they must be grounded in a doc citation upstream). Their presence
    # means the control author found a gating mechanism the snapshot lacks.
    declared = [k for k in control.get("condition_keys", []) if isinstance(k, str) and k]
    declared_non_sar = [
        k for k in declared if k not in {ck.get("key") for ck in condition_keys}
    ]

    # The keys that would be authored into the policy (mirrors the plan's
    # enforcing_condition_keys: the SAR-derived gates, else control-declared keys).
    keys_in_use = enforcing or declared_non_sar

    # Resource-based-policy scope guard. A resource-based policy document is
    # ATTACHED to the resource; AWS consults it when a principal accesses the
    # resource, NOT when a principal calls the operation that *manages the policy
    # itself* (e.g. AddPermission/RemovePermission). So a Deny placed inside the
    # attached document and conditioned on a request-time-only key — one bound
    # solely to those policy-management actions, e.g. lambda:Principal — silently
    # never fires: the document is not in the evaluation path for that request.
    # Route such a control to detective (or re-map to an SCP/identity policy,
    # which DO evaluate the request). Membership of request-time-only keys is
    # derived from validated.json bindings, so no service is hardcoded.
    if mechanism.lower() in _RESOURCE_BASED_MECHANISMS and keys_in_use:
        rt_only = request_time_only_keys(validated)
        if all(k in rt_only for k in keys_in_use):
            return {
                "id": control.get("id"),
                "mechanism": mechanism,
                "verdict": "NOT_PREVENTABLE",
                "enforcing_condition_keys": [],
                "target_actions": sorted(target_actions),
                "route_to": "detective",
                "reason": (
                    "a resource-based policy cannot evaluate a request-time "
                    "condition key bound to the policy-management action "
                    f"({', '.join(sorted(keys_in_use))}); the attached document "
                    "is not in the evaluation path for that request, so the deny "
                    "never fires. Route to a detective mechanism or re-map to an "
                    "SCP/identity policy that evaluates the request."
                ),
            }

    verdict = "FEASIBLE" if keys_in_use else "NOT_PREVENTABLE"
    result = {
        "id": control.get("id"),
        "mechanism": mechanism,
        "verdict": verdict,
        "enforcing_condition_keys": keys_in_use,
        "target_actions": sorted(target_actions),
        "route_to": None,
        "reason": "",
    }
    if verdict == "FEASIBLE":
        result["reason"] = (
            f"{len(result['enforcing_condition_keys'])} condition key(s) gate the "
            f"target action(s); the preventive policy MUST use one of them."
        )
    else:
        result["route_to"] = "detective"
        if not target_actions:
            result["reason"] = (
                "control declares no target actions — nothing to gate at request "
                "time; route to a detective mechanism."
            )
        else:
            result["reason"] = (
                "no condition key gates the target action(s); a request-time deny "
                "would silently never fire. Route to a detective mechanism instead "
                "of authoring a non-enforcing policy."
            )
    return result


def is_request_time_mechanism(mechanism: str) -> bool:
    return (mechanism or "").strip().lower() in REQUEST_TIME_MECHANISMS


def assess_mapping(mapping: dict, validated: dict) -> list[dict]:
    """Assess every PRV control in the mapping. Returns verdict dicts."""
    results = []
    for control in mapping.get("controls", []):
        if (control.get("category") or "").upper() != "PRV":
            continue
        results.append(assess_control(control, validated))
    return results


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--mapping", help="path to mapping-results.json")
    parser.add_argument("--validated", help="path to validated.json")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 2 if any request-time-mechanism control is NOT_PREVENTABLE",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON verdicts")
    args = parser.parse_args()

    if args.slug:
        base = Path(os.getcwd()) / ".service-approval" / args.slug
        mapping_path = args.mapping or base / "04-map" / "mapping-results.json"
        validated_path = args.validated or base / "03-validate" / "validated.json"
    else:
        if not (args.mapping and args.validated):
            parser.error("provide --slug OR both --mapping and --validated")
        mapping_path, validated_path = args.mapping, args.validated

    mapping = _load_json(mapping_path)
    validated = _load_json(validated_path)
    results = assess_mapping(mapping, validated)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['verdict']:16} {r['id']:24} {r['mechanism']}")
            if r["verdict"] == "FEASIBLE":
                print(f"    keys: {', '.join(r['enforcing_condition_keys'])}")
            else:
                print(f"    -> {r['route_to']}: {r['reason']}")

    if args.strict:
        offenders = [
            r
            for r in results
            if r["verdict"] == "NOT_PREVENTABLE"
            and is_request_time_mechanism(r["mechanism"])
        ]
        if offenders:
            print(
                f"\n{len(offenders)} request-time-mechanism control(s) are "
                f"NOT_PREVENTABLE — route them to detective.",
                file=sys.stderr,
            )
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
