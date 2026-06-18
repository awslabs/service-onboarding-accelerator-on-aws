"""Tests for the authored-deny action scope-creep check.

The core case: an authored Deny lists an action (e.g. lambda:CreateCapacityProvider)
that the enforcing key happens to apply to but that was never reviewed as part of
the control's intent. The reviewed set comes from the plan decision's
plan_actions[] (preferred) or the mapping control's actions[] (fallback).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_action_scope import (  # noqa: E402
    assess_preventive_dir_scope,
    control_id_from_sid,
    reviewed_actions_by_control,
)


def control_id_cases():
    return [
        ("DenyLambdaWithoutVpcConfigCtrlOrgPrv002", "CTRL-ORG-PRV-002"),
        ("DenyPassRoleNotToLambdaCtrlAccPrv003", "CTRL-ACC-PRV-003"),
        ("DenyOutsideOrgCtrlResPrv005", "CTRL-RES-PRV-005"),
        ("SomeStatementWithNoControl", None),
    ]


def test_control_id_from_sid():
    for sid, expected in control_id_cases():
        assert control_id_from_sid(sid) == expected


def test_reviewed_actions_prefers_plan_actions():
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002",
         "plan_actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]},
    ]}
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-002",
         "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration",
                     "lambda:CreateCapacityProvider"]},
    ]}
    reviewed = reviewed_actions_by_control(plan, mapping)
    # plan_actions wins — the broader mapping action is NOT in the reviewed set
    assert "lambda:CreateCapacityProvider" not in reviewed["CTRL-ORG-PRV-002"]


def test_reviewed_actions_falls_back_to_mapping():
    plan = {"decisions": [{"control_id": "CTRL-ORG-PRV-002"}]}
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-002", "actions": ["lambda:CreateFunction"]},
    ]}
    reviewed = reviewed_actions_by_control(plan, mapping)
    assert reviewed["CTRL-ORG-PRV-002"] == {"lambda:CreateFunction"}


def _write_scp(prev: Path, sid: str, actions: list[str], controls: list[str]):
    prev.mkdir(parents=True, exist_ok=True)
    (prev / "scp-policy.json").write_text(json.dumps({
        "_metadata": {"controls": controls},
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Deny", "Action": actions, "Resource": "*"}],
    }))


def test_scope_creep_action_flagged(tmp_path):
    prev = tmp_path / "preventive"
    _write_scp(prev, "DenyLambdaWithoutVpcConfigCtrlOrgPrv002",
               ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration",
                "lambda:CreateCapacityProvider"],
               ["CTRL-ORG-PRV-002"])
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002",
         "plan_actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]},
    ]}
    errors = assess_preventive_dir_scope(prev, plan, {"controls": []})
    assert len(errors) == 1
    assert "lambda:CreateCapacityProvider" in errors[0]
    assert "CTRL-ORG-PRV-002" in errors[0]


def test_no_creep_when_all_actions_reviewed(tmp_path):
    prev = tmp_path / "preventive"
    _write_scp(prev, "DenyLambdaWithoutVpcConfigCtrlOrgPrv002",
               ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
               ["CTRL-ORG-PRV-002"])
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002",
         "plan_actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]},
    ]}
    assert assess_preventive_dir_scope(prev, plan, {"controls": []}) == []


def test_cross_service_action_must_be_reviewed(tmp_path):
    """A PassRole control whose mapping actions[] omit iam:PassRole still must
    record it — an authored iam:PassRole Deny is flagged until reviewed."""
    prev = tmp_path / "preventive"
    _write_scp(prev, "DenyPassRoleNotToLambdaCtrlAccPrv003",
               ["iam:PassRole"], ["CTRL-ACC-PRV-003"])
    # mapping omits iam:PassRole; no plan_actions → fallback flags it
    plan = {"decisions": [{"control_id": "CTRL-ACC-PRV-003"}]}
    mapping = {"controls": [
        {"id": "CTRL-ACC-PRV-003",
         "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"]},
    ]}
    errors = assess_preventive_dir_scope(prev, plan, mapping)
    assert len(errors) == 1 and "iam:PassRole" in errors[0]
    # once reviewed (recorded in plan_actions), it passes
    plan["decisions"][0]["plan_actions"] = ["iam:PassRole"]
    assert assess_preventive_dir_scope(prev, plan, mapping) == []


def test_report_artifacts_skipped(tmp_path):
    prev = tmp_path / "preventive"
    prev.mkdir(parents=True)
    (prev / "rootcause-report.json").write_text(json.dumps({
        "Statement": [{"Sid": "x", "Effect": "Deny", "Action": "lambda:Foo"}]
    }))
    assert assess_preventive_dir_scope(prev, {"decisions": []}, {"controls": []}) == []
