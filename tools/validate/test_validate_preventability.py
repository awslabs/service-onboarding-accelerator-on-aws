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


def test_is_request_time_mechanism():
    assert is_request_time_mechanism("SCP")
    assert is_request_time_mechanism("IAM Permission Boundary")
    assert is_request_time_mechanism("kms key policy")
    assert not is_request_time_mechanism("AWS Config rule")
    assert not is_request_time_mechanism("")


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
