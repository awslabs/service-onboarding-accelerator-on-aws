"""Tests for the per-statement enforcement check (generate-time root-cause).

Covers the two silent-no-op classes the check generalizes:
  - a request-time-only key (lambda:Principal) inside a resource-based policy,
  - a malformed Resource ARN (function/* where the SAR format mandates function:),
plus the policy-type awareness (the same key IS evaluable in an SCP), the
key-applies-to-action check, the global-key-only legitimate deny (VPCE org
perimeter), and filename→policy-type inference.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_enforcement import (  # noqa: E402
    assess_artifact,
    assess_preventive_dir,
    assess_statement,
    policy_type_for_file,
)


VALIDATED = {
    "service": "lambda",
    "capabilities": {
        "iam": {
            "service_prefix": "lambda",
            "condition_keys": [
                {"key": "lambda:Principal",
                 "applies_to_actions": ["AddPermission", "RemovePermission"]},
                {"key": "lambda:FunctionUrlAuthType",
                 "applies_to_actions": ["CreateFunctionUrlConfig", "UpdateFunctionUrlConfig"]},
                {"key": "lambda:SubnetIds",
                 "applies_to_actions": ["CreateFunction", "UpdateFunctionConfiguration"]},
            ],
        }
    },
}

# Delimiter map covering the `function` resource type (colon).
DELIMS = {"function": ":", "layer": ":"}
PREFIX = "lambda"


def _deny(sid, action, resource, cond):
    return {"Sid": sid, "Effect": "Deny", "Action": action,
            "Resource": resource, "Condition": cond}


# ---------- filename → policy type ----------


def test_policy_type_inference():
    assert policy_type_for_file("scp-policy.json") == "scp"
    assert policy_type_for_file("resource-policy.json") == "resource-based"
    assert policy_type_for_file("permission-boundary.json") == "boundary"
    assert policy_type_for_file("vpce-policy.json") == "vpce"
    assert policy_type_for_file("kms-key-policy.json") == "resource-based"
    assert policy_type_for_file("iam-policies.json") == "identity"
    # split SCP keeps its type
    assert policy_type_for_file("scp-policy-2.json") == "scp"
    # reports are not policy docs
    assert policy_type_for_file("rootcause-report.json") is None
    assert policy_type_for_file("detective-routing.json") is None


# ---------- (a) request-time-only key in a resource-based policy ----------


def test_resource_policy_request_time_key_not_evaluable():
    """A resource-based Deny on a policy-management action (AddPermission) is a
    no-op regardless of the gating key — the attached document is not in the
    evaluation path. The action-driven check catches it."""
    stmt = _deny(
        "DenyAddPerm", "lambda:AddPermission", "arn:aws:lambda:*:*:function:*",
        {"StringNotEqualsIfExists": {"lambda:Principal": "123456789012"}},
    )
    r = assess_statement(stmt, "resource-based", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is False
    assert "policy-management action" in r["reason"]
    assert r["enforcing_key"] == ["lambda:Principal"]


def test_resource_policy_mgmt_action_not_masked_by_coapplying_key():
    """Regression: a resource-based Deny on AddPermission gated SOLELY on a
    non-rt-only key that co-applies to AddPermission (lambda:FunctionUrlAuthType)
    must STILL be flagged — the deny is a no-op because AddPermission mutates the
    attached policy, which is not in its own evaluation path. The action-driven
    check is not maskable by a co-applying key."""
    stmt = _deny(
        "DenyAddPerm", "lambda:AddPermission", "arn:aws:lambda:*:*:function:*",
        {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}},
    )
    r = assess_statement(stmt, "resource-based", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is False
    assert "policy-management action" in r["reason"]


def test_notresource_malformed_arn_flagged():
    """A malformed ARN in NotResource is flagged, not just Resource."""
    stmt = {
        "Sid": "DenyOutside", "Effect": "Deny", "Action": "lambda:InvokeFunction",
        "NotResource": "arn:aws:lambda:*:*:function/*",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-x"}},
    }
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is False
    assert "malformed resource ARN" in r["reason"]


def test_same_request_time_key_evaluable_in_scp():
    """The SAME lambda:Principal key in an SCP IS evaluable — an SCP evaluates
    the AddPermission request itself."""
    stmt = _deny(
        "DenyAddPerm", ["lambda:AddPermission", "lambda:RemovePermission"],
        "arn:aws:lambda:*:*:function:*",
        {"StringNotEqualsIfExists": {"lambda:Principal": "123456789012"}},
    )
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is True


# ---------- (b) malformed Resource ARN ----------


def test_malformed_arn_not_evaluable():
    stmt = _deny(
        "DenyUrl", "lambda:CreateFunctionUrlConfig", "arn:aws:lambda:*:*:function/*",
        {"StringNotEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}},
    )
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is False
    assert "malformed resource ARN" in r["reason"]


def test_wellformed_arn_and_applying_key_is_evaluable():
    stmt = _deny(
        "DenyUrl", ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"],
        "arn:aws:lambda:*:*:function:*",
        {"StringNotEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"},
         "ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/admin"}},
    )
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is True
    # the global key is not treated as the enforcing key
    assert r["enforcing_key"] == ["lambda:FunctionUrlAuthType"]


# ---------- (c) key does not apply to the gated action ----------


def test_key_not_applying_to_action_not_evaluable():
    """lambda:SubnetIds applies to CreateFunction, not to DeleteFunction — gating
    DeleteFunction on it denies a different operation than the key controls."""
    stmt = _deny(
        "DenyDelete", "lambda:DeleteFunction", "arn:aws:lambda:*:*:function:*",
        {"Null": {"lambda:SubnetIds": "true"}},
    )
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is False
    assert "do not apply to the gated action" in r["reason"]


# ---------- global-key-only deny is legitimate (no false positive) ----------


def test_global_key_only_deny_is_not_flagged():
    """A VPCE org-perimeter deny conditioned only on aws:PrincipalOrgID is a
    legitimate control — global keys are evaluable and not action-bound."""
    stmt = _deny(
        "DenyOutsideOrg", "lambda:InvokeFunction", "*",
        {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123"},
         "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}},
    )
    r = assess_statement(stmt, "vpce", VALIDATED, DELIMS, PREFIX)
    assert r["evaluable"] is True
    assert r["enforcing_key"] == []  # only global keys present


# ---------- record shape ----------


def test_record_carries_resolved_fields():
    stmt = _deny(
        "S", "lambda:AddPermission", ["arn:aws:lambda:*:*:function:*"],
        {"StringNotEquals": {"lambda:Principal": "x"}},
    )
    r = assess_statement(stmt, "scp", VALIDATED, DELIMS, PREFIX)
    assert r["sid"] == "S"
    assert r["action"] == ["lambda:AddPermission"]
    assert r["resource_arn"] == ["arn:aws:lambda:*:*:function:*"]
    assert "evaluable" in r and "reason" in r


# ---------- artifact / directory level ----------


def test_assess_artifact_skips_non_policy(tmp_path):
    report = tmp_path / "rootcause-report.json"
    report.write_text(json.dumps({"anchored": True}))
    assert assess_artifact(report, VALIDATED, DELIMS, PREFIX) is None


def test_assess_preventive_dir_end_to_end(tmp_path):
    prev = tmp_path / "slug" / "05-generate" / "preventive"
    prev.mkdir(parents=True)
    (tmp_path / "slug" / "01-assess").mkdir(parents=True)
    (tmp_path / "slug" / "01-assess" / "sar-facts.json").write_text(json.dumps({
        "service_prefix": "lambda",
        "resource_types": [
            {"name": "function",
             "arn_pattern": "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}"},
        ],
    }))
    # one good SCP, one bad resource policy
    (prev / "scp-policy.json").write_text(json.dumps({
        "Version": "2012-10-17",
        "Statement": [_deny("Ok", "lambda:AddPermission", "arn:aws:lambda:*:*:function:*",
                            {"StringNotEquals": {"lambda:Principal": "x"}})],
    }))
    (prev / "resource-policy.json").write_text(json.dumps({
        "Version": "2012-10-17",
        "Statement": [_deny("Bad", "lambda:AddPermission", "arn:aws:lambda:*:*:function:*",
                            {"StringNotEquals": {"lambda:Principal": "x"}})],
    }))
    results = assess_preventive_dir(prev, VALIDATED)
    by_name = {a["artifact"]: a for a in results}
    assert by_name["scp-policy.json"]["all_evaluable"] is True
    assert by_name["resource-policy.json"]["all_evaluable"] is False
