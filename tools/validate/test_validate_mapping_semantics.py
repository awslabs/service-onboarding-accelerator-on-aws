"""Tests for the deterministic semantic mapping checks (S1/S2/S3)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_mapping_semantics as vms  # noqa: E402


_FRAMEWORK = {"framework_objectives": [{"id": "AIS-01"}, {"id": "DSP-02"}]}
_VALIDATED = {
    "api_surface": {"operations": [
        {"operation": "CreateAgentRuntime", "iam_action": "bedrock-agentcore:CreateAgentRuntime"},
    ]},
    "capabilities": {"iam": {
        "permission_only_actions": [],
        "condition_keys": [{"key": "bedrock-agentcore:EncryptionKeyArn"}],
    }},
}


def test_clean_mapping_passes() -> None:
    mapping = {
        "controls": [
            {"id": "CTRL-ORG-PRV-001",
             "actions": ["bedrock-agentcore:CreateAgentRuntime"],
             "condition_keys": ["bedrock-agentcore:EncryptionKeyArn"]},
        ],
        "framework_mapping": [
            {"objective_id": "AIS-01", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ORG-PRV-001"}]},
        ],
    }
    assert vms.check(mapping, _FRAMEWORK, _VALIDATED) == []


def test_s1_dangling_control_reference_fails() -> None:
    mapping = {
        "controls": [{"id": "CTRL-ORG-PRV-001", "actions": [], "condition_keys": []}],
        "framework_mapping": [
            {"objective_id": "AIS-01", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ORG-PRV-999"}]},
        ],
    }
    errors = vms.check(mapping, _FRAMEWORK, _VALIDATED)
    assert any("SEMANTIC-S1" in e and "CTRL-ORG-PRV-999" in e for e in errors), errors


def test_s2_nonexistent_objective_fails() -> None:
    mapping = {
        "controls": [{"id": "CTRL-ORG-PRV-001", "actions": [], "condition_keys": []}],
        "framework_mapping": [
            {"objective_id": "FAKE-99", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ORG-PRV-001"}]},
        ],
    }
    errors = vms.check(mapping, _FRAMEWORK, _VALIDATED)
    assert any("SEMANTIC-S2" in e and "FAKE-99" in e for e in errors), errors


def test_s3_unverified_action_fails() -> None:
    mapping = {
        "controls": [
            {"id": "CTRL-ORG-PRV-001",
             "actions": ["bedrock-agentcore:DeleteAgentRuntime"],  # not in validated
             "condition_keys": []},
        ],
        "framework_mapping": [],
    }
    errors = vms.check(mapping, _FRAMEWORK, _VALIDATED)
    assert any("SEMANTIC-S3" in e and "DeleteAgentRuntime" in e for e in errors), errors


def test_s3_unverified_condition_key_fails() -> None:
    mapping = {
        "controls": [
            {"id": "CTRL-ORG-PRV-001",
             "actions": ["bedrock-agentcore:CreateAgentRuntime"],
             "condition_keys": ["bedrock-agentcore:MadeUpKey"]},
        ],
        "framework_mapping": [],
    }
    errors = vms.check(mapping, _FRAMEWORK, _VALIDATED)
    assert any("SEMANTIC-S3" in e and "MadeUpKey" in e for e in errors), errors


def test_s3_noops_without_validated() -> None:
    """No validated.json → no verified surface → S3 can't run, stays quiet
    (S1/S2 still apply)."""
    mapping = {
        "controls": [{"id": "CTRL-ORG-PRV-001", "actions": ["x:Y"], "condition_keys": ["z"]}],
        "framework_mapping": [],
    }
    assert vms.check(mapping, _FRAMEWORK, None) == []


def test_s2_noops_without_framework() -> None:
    """No parsed framework → S2 can't run; a mapped objective is not flagged."""
    mapping = {
        "controls": [{"id": "CTRL-ORG-PRV-001", "actions": [], "condition_keys": []}],
        "framework_mapping": [
            {"objective_id": "ANY", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ORG-PRV-001"}]},
        ],
    }
    assert vms.check(mapping, None, _VALIDATED) == []


def test_bare_action_name_matches_verified_surface() -> None:
    """A control listing the bare operation name matches when validated.json
    verified the qualified action."""
    mapping = {
        "controls": [{"id": "CTRL-ORG-PRV-001",
                      "actions": ["CreateAgentRuntime"], "condition_keys": []}],
        "framework_mapping": [],
    }
    assert vms.check(mapping, _FRAMEWORK, _VALIDATED) == []
