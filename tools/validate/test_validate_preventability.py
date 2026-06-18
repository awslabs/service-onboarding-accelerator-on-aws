"""Tests for the preventability / root-cause check.

Covers the two canonical cases:
- A control whose target action is gated by a real condition key -> FEASIBLE,
  and the enforcing key is surfaced (the EBS-CMK / Lambda-code-signing shape).
- A control whose target action has no gating condition key -> NOT_PREVENTABLE,
  routed to detective.
Plus: SAR list treated as a lower bound (control-declared key honored), wildcard
action matching, mechanism classification, and the no-actions edge case.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_preventability import (  # noqa: E402
    assess_control,
    assess_mapping,
    find_enforcing_keys,
    is_request_time_mechanism,
    normalize_action,
    request_time_only_keys,
)


VALIDATED = {
    "service": "lambda",
    "capabilities": {
        "iam": {
            "condition_keys": [
                {
                    "key": "lambda:CodeSigningConfigArn",
                    "applies_to_actions": ["CreateFunction", "PutFunctionCodeSigningConfig"],
                },
                {
                    "key": "lambda:FunctionArn",
                    "applies_to_actions": ["InvokeFunctionUrl", "GetFunctionUrlConfig"],
                },
                # Request-time-only key: bound SOLELY to the policy-management
                # actions (AddPermission/RemovePermission). It gates the request
                # to change the function's resource policy, so it cannot be
                # evaluated from inside the attached resource policy document.
                {
                    "key": "lambda:Principal",
                    "applies_to_actions": ["AddPermission", "RemovePermission"],
                },
                # Genuinely resource-policy-evaluable confused-deputy key: bound
                # to an ACCESS action (InvokeFunction), evaluable in the attached
                # document when a principal invokes the function.
                {
                    "key": "aws:SourceArn",
                    "applies_to_actions": ["InvokeFunction"],
                },
                # A key that CO-APPLIES to AddPermission (a policy-mgmt action)
                # but ALSO to access/config actions, so it is NOT request-time-
                # only. It mirrors the real SAR shape that previously masked the
                # resource-policy guard: a control gated solely on lambda:Principal
                # must still route to detective even though this key co-applies to
                # the same AddPermission action.
                {
                    "key": "lambda:FunctionUrlAuthType",
                    "applies_to_actions": ["AddPermission", "CreateFunctionUrlConfig",
                                           "UpdateFunctionUrlConfig"],
                },
                # KMS key-policy management key, bound solely to PutKeyPolicy
                # (a key-policy-management action) → request-time-only.
                {
                    "key": "kms:GrantConstraintType",
                    "applies_to_actions": ["PutKeyPolicy"],
                },
            ]
        }
    },
}


def test_normalize_action():
    assert normalize_action("lambda:CreateFunction") == "CreateFunction"
    assert normalize_action("ecs:Create*") == "Create*"
    assert normalize_action("CreateService") == "CreateService"


def test_feasible_when_condition_key_gates_action():
    control = {
        "id": "CTRL-ORG-PRV-001",
        "category": "PRV",
        "mechanism": "SCP",
        "actions": ["lambda:CreateFunction"],
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "FEASIBLE"
    assert "lambda:CodeSigningConfigArn" in r["enforcing_condition_keys"]


def test_not_preventable_when_no_gating_key():
    control = {
        "id": "CTRL-ORG-PRV-002",
        "category": "PRV",
        "mechanism": "SCP",
        "actions": ["lambda:DeleteFunction"],  # no condition key applies to this
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert r["route_to"] == "detective"


def test_no_actions_is_not_preventable():
    control = {
        "id": "CTRL-ORG-PRV-003",
        "category": "PRV",
        "mechanism": "SCP",
        "actions": [],
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert "no target actions" in r["reason"]


def test_sar_list_is_lower_bound_control_declared_key_honored():
    """A control may cite a gating key absent from the SAR snapshot."""
    control = {
        "id": "CTRL-ORG-PRV-004",
        "category": "PRV",
        "mechanism": "RCP",
        "actions": ["lambda:DeleteFunction"],
        "condition_keys": ["lambda:SomeNewKeyNotInSar"],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "FEASIBLE"
    assert "lambda:SomeNewKeyNotInSar" in r["enforcing_condition_keys"]


def test_wildcard_action_matches_condition_key():
    control = {
        "id": "CTRL-ORG-PRV-005",
        "category": "PRV",
        "mechanism": "SCP",
        "actions": ["lambda:Create*"],  # should match CreateFunction's key
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "FEASIBLE"
    assert "lambda:CodeSigningConfigArn" in r["enforcing_condition_keys"]


def test_find_enforcing_keys_empty_when_no_targets():
    assert find_enforcing_keys(set(), VALIDATED["capabilities"]["iam"]["condition_keys"]) == []


def test_vpce_policy_on_request_body_param_is_not_preventable():
    """A VPCE-policy control whose parameters_controlled[] names a request-body
    field cannot enforce it (the endpoint policy can't see the request body) —
    route to detective even if a condition key exists for the action."""
    control = {
        "id": "CTRL-RES-PRV-002",
        "category": "PRV",
        "mechanism": "VPCE Policy",
        "actions": ["lambda:CreateFunction"],  # a gating key DOES exist for this
        "parameters_controlled": ["$.lambda/CreateFunction.VpcConfig.SubnetIds"],
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert r["route_to"] == "detective"
    assert "VPCE policy gates endpoint use" in r["reason"]


def test_vpce_policy_at_endpoint_scope_still_assessed_normally():
    """A VPCE-policy control at endpoint scope (root path only) is NOT auto-routed;
    it falls through to the normal condition-key assessment."""
    control = {
        "id": "CTRL-RES-PRV-009",
        "category": "PRV",
        "mechanism": "VPCE Policy",
        "actions": ["lambda:CreateFunction"],
        "parameters_controlled": ["$."],  # endpoint-level concern
        "condition_keys": [],
    }
    r = assess_control(control, VALIDATED)
    # Not short-circuited by the VPCE guard — normal assessment applies.
    assert r["verdict"] == "FEASIBLE"


def test_is_request_time_mechanism():
    assert is_request_time_mechanism("SCP")
    assert is_request_time_mechanism("IAM Permission Boundary")
    assert is_request_time_mechanism("kms key policy")
    assert not is_request_time_mechanism("AWS Config rule")
    assert not is_request_time_mechanism("")


def test_request_time_only_keys_derived_from_bindings():
    """A key bound SOLELY to policy-management actions is request-time-only; a
    key bound to an access action is not (it is evaluable in an attached doc)."""
    rt = request_time_only_keys(VALIDATED)
    assert "lambda:Principal" in rt  # AddPermission/RemovePermission only
    assert "aws:SourceArn" not in rt  # bound to InvokeFunction (an access action)
    assert "lambda:FunctionArn" not in rt  # bound to access/config actions
    assert "lambda:CodeSigningConfigArn" not in rt  # bound to CreateFunction


def test_resource_policy_with_request_time_key_is_not_preventable():
    """A Resource Policy control gated on lambda:Principal (a request-time key
    bound to AddPermission) cannot enforce inside the attached document — the
    document is not in the evaluation path for the AddPermission request, so the
    deny silently never fires. Route to detective rather than ship a no-op."""
    control = {
        "id": "CTRL-RES-PRV-002",
        "category": "PRV",
        "mechanism": "Resource Policy",
        "actions": ["lambda:AddPermission"],
        "parameters_controlled": ["$.Principal"],
        "condition_keys": ["lambda:Principal"],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert r["route_to"] == "detective"
    assert "resource-based policy cannot evaluate a request-time" in r["reason"]
    assert r["enforcing_condition_keys"] == []


def test_resource_policy_with_evaluable_confused_deputy_key_is_feasible():
    """A resource-based policy CAN evaluate a confused-deputy key bound to an
    access action (aws:SourceArn on InvokeFunction) — that stays FEASIBLE."""
    control = {
        "id": "CTRL-RES-PRV-010",
        "category": "PRV",
        "mechanism": "Resource Policy",
        "actions": ["lambda:InvokeFunction"],
        "parameters_controlled": ["$.Principal"],
        "condition_keys": ["aws:SourceArn"],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "FEASIBLE"
    assert "aws:SourceArn" in r["enforcing_condition_keys"]


def test_resource_policy_rt_key_not_masked_by_coapplying_key():
    """Regression: a resource policy gated SOLELY on a request-time-only key
    (lambda:Principal) must route to detective even when the SAR binds ANOTHER
    (non-rt-only) key to the same action. The guard must test the keys the policy
    declares, not the action's full co-applying SAR set — otherwise a single
    co-applying access key (lambda:FunctionUrlAuthType) disables the guard."""
    control = {
        "id": "CTRL-RES-PRV-002",
        "category": "PRV",
        "mechanism": "Resource Policy",
        "actions": ["lambda:AddPermission"],
        "parameters_controlled": ["$.Principal"],
        "condition_keys": ["lambda:Principal"],  # the policy uses only this key
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert r["route_to"] == "detective"


def test_kms_key_policy_with_request_time_key_is_not_preventable():
    """A KMS key policy is resource-based — it cannot evaluate a request-time-only
    key bound to a key-policy-management action (kms:PutKeyPolicy)."""
    control = {
        "id": "CTRL-RES-PRV-020",
        "category": "PRV",
        "mechanism": "KMS Key Policy",
        "actions": ["kms:PutKeyPolicy"],
        "condition_keys": ["kms:GrantConstraintType"],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "NOT_PREVENTABLE"
    assert r["route_to"] == "detective"


def test_scp_with_request_time_key_stays_feasible():
    """The guard is specific to resource-based policies. The SAME lambda:Principal
    key on an SCP (which DOES evaluate the request) stays FEASIBLE — an SCP can
    gate AddPermission at request time."""
    control = {
        "id": "CTRL-ORG-PRV-020",
        "category": "PRV",
        "mechanism": "SCP",
        "actions": ["lambda:AddPermission"],
        "condition_keys": ["lambda:Principal"],
    }
    r = assess_control(control, VALIDATED)
    assert r["verdict"] == "FEASIBLE"
    assert "lambda:Principal" in r["enforcing_condition_keys"]


def test_assess_mapping_only_considers_prv():
    mapping = {
        "controls": [
            {"id": "C1", "category": "DET", "mechanism": "AWS Config rule", "actions": []},
            {
                "id": "C2",
                "category": "PRV",
                "mechanism": "SCP",
                "actions": ["lambda:CreateFunction"],
                "condition_keys": [],
            },
        ]
    }
    results = assess_mapping(mapping, VALIDATED)
    assert [r["id"] for r in results] == ["C2"]
    assert results[0]["verdict"] == "FEASIBLE"
