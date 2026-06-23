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
    entry = reviewed["CTRL-ORG-PRV-002"]
    # plan_actions wins — the broader mapping action is NOT in the reviewed set,
    # and the set is authoritative (hard FAIL on mismatch).
    assert "lambda:CreateCapacityProvider" not in entry["actions"]
    assert entry["authoritative"] is True


def test_reviewed_actions_falls_back_to_mapping_non_authoritative():
    plan = {"decisions": [{"control_id": "CTRL-ORG-PRV-002"}]}
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-002", "actions": ["lambda:CreateFunction"]},
    ]}
    reviewed = reviewed_actions_by_control(plan, mapping)
    entry = reviewed["CTRL-ORG-PRV-002"]
    assert entry["actions"] == {"lambda:CreateFunction"}
    # fallback to the mapping superset is NOT authoritative → WARN, not FAIL
    assert entry["authoritative"] is False


def test_passrole_implied_by_condition_key():
    """A control declaring iam:PassedToService legitimately denies iam:PassRole;
    the implied action is part of its reviewed set even though the mapping
    actions[] only lists the in-service operations."""
    plan = {"decisions": [{"control_id": "CTRL-ACC-PRV-003"}]}
    mapping = {"controls": [
        {"id": "CTRL-ACC-PRV-003",
         "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
         "condition_keys": ["iam:PassedToService", "iam:AssociatedResourceArn"]},
    ]}
    reviewed = reviewed_actions_by_control(plan, mapping)
    assert "iam:PassRole" in reviewed["CTRL-ACC-PRV-003"]["actions"]


def _write_scp(prev: Path, sid: str, actions: list[str], controls: list[str]):
    prev.mkdir(parents=True, exist_ok=True)
    (prev / "scp-policy.json").write_text(json.dumps({
        "_metadata": {"controls": controls},
        "Version": "2012-10-17",
        "Statement": [{"Sid": sid, "Effect": "Deny", "Action": actions, "Resource": "*"}],
    }))


def test_scope_creep_action_flagged_as_fail(tmp_path):
    """With an authoritative plan_actions contract, creep is a hard FAIL."""
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
    assert errors[0].startswith("FAIL")
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


def test_mapping_fallback_creep_is_warn_not_fail(tmp_path):
    """When no plan_actions is recorded, an action outside the mapping superset is
    a WARN (the fallback set is not the authoritative reviewed contract)."""
    prev = tmp_path / "preventive"
    _write_scp(prev, "DenyExtraCtrlOrgPrv002",
               ["lambda:CreateFunction", "lambda:DeleteFunction"],
               ["CTRL-ORG-PRV-002"])
    plan = {"decisions": [{"control_id": "CTRL-ORG-PRV-002"}]}  # no plan_actions
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-002", "actions": ["lambda:CreateFunction"]},
    ]}
    errors = assess_preventive_dir_scope(prev, plan, mapping)
    assert len(errors) == 1
    assert errors[0].startswith("WARN")
    assert "lambda:DeleteFunction" in errors[0]


def test_passrole_deny_not_false_positive(tmp_path):
    """Regression: a PassRole boundary deny on a control declaring
    iam:PassedToService must NOT be flagged — iam:PassRole is implied by the key,
    so it is part of the reviewed set."""
    prev = tmp_path / "preventive"
    (prev).mkdir(parents=True)
    (prev / "permission-boundary.json").write_text(json.dumps({
        "_metadata": {"controls": ["CTRL-ACC-PRV-003"]},
        "Version": "2012-10-17",
        "Statement": [{"Sid": "DenyPassRoleNotToLambdaCtrlAccPrv003", "Effect": "Deny",
                       "Action": "iam:PassRole", "Resource": "*",
                       "Condition": {"StringNotEqualsIfExists": {"iam:PassedToService": "lambda.amazonaws.com"}}}],
    }))
    plan = {"decisions": [{"control_id": "CTRL-ACC-PRV-003"}]}
    mapping = {"controls": [
        {"id": "CTRL-ACC-PRV-003",
         "actions": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
         "condition_keys": ["iam:PassedToService", "iam:AssociatedResourceArn"]},
    ]}
    assert assess_preventive_dir_scope(prev, plan, mapping) == []


def test_notaction_deny_flagged(tmp_path):
    """A Deny written with NotAction authorizes over the complement — unbounded,
    always flagged."""
    prev = tmp_path / "preventive"
    prev.mkdir(parents=True)
    (prev / "scp-policy.json").write_text(json.dumps({
        "_metadata": {"controls": ["CTRL-ORG-PRV-002"]},
        "Version": "2012-10-17",
        "Statement": [{"Sid": "DenyAllExceptCtrlOrgPrv002", "Effect": "Deny",
                       "NotAction": ["lambda:CreateFunction"], "Resource": "*"}],
    }))
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002", "plan_actions": ["lambda:CreateFunction"]},
    ]}
    errors = assess_preventive_dir_scope(prev, plan, {"controls": []})
    assert len(errors) == 1 and "NotAction" in errors[0]


def test_action_case_insensitive(tmp_path):
    """Action comparison is case-insensitive (IAM is) — a case variant of a
    reviewed action is NOT flagged as creep."""
    prev = tmp_path / "preventive"
    _write_scp(prev, "DenyXCtrlOrgPrv002", ["lambda:createfunction"], ["CTRL-ORG-PRV-002"])
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002", "plan_actions": ["lambda:CreateFunction"]},
    ]}
    assert assess_preventive_dir_scope(prev, plan, {"controls": []}) == []


def test_report_artifacts_skipped(tmp_path):
    prev = tmp_path / "preventive"
    prev.mkdir(parents=True)
    (prev / "rootcause-report.json").write_text(json.dumps({
        "Statement": [{"Sid": "x", "Effect": "Deny", "Action": "lambda:Foo"}]
    }))
    assert assess_preventive_dir_scope(prev, {"decisions": []}, {"controls": []}) == []
