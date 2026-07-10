"""Tests for the deterministic control-conflict pre-filter."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detect_control_conflicts as dcc  # noqa: E402
from _schemas import schema_errors  # noqa: E402


def test_deny_vs_allow_candidate_surfaced() -> None:
    statements = [
        {"file": "preventive/scp.json", "sid": "DenyCreate", "effect": "Deny",
         "actions": ["bedrock-agentcore:createagentruntime"], "condition_keys": []},
        {"file": "iac/role.json", "sid": "AllowCreate", "effect": "Allow",
         "actions": ["bedrock-agentcore:createagentruntime"], "condition_keys": []},
    ]
    cands = dcc.find_candidates(statements)
    assert len(cands) == 1
    assert cands[0]["kind"] == "deny_vs_allow"
    assert "bedrock-agentcore:createagentruntime" in cands[0]["shared_actions"]


def test_incompatible_conditions_candidate_surfaced() -> None:
    statements = [
        {"file": "preventive/scp-a.json", "sid": "DenyA", "effect": "Deny",
         "actions": ["s3:putobject"], "condition_keys": ["s3:x-amz-server-side-encryption"]},
        {"file": "preventive/scp-b.json", "sid": "DenyB", "effect": "Deny",
         "actions": ["s3:putobject"], "condition_keys": ["aws:securetransport"]},
    ]
    cands = dcc.find_candidates(statements)
    assert len(cands) == 1
    assert cands[0]["kind"] == "incompatible_conditions"


def test_same_conditions_not_flagged() -> None:
    statements = [
        {"file": "a.json", "sid": "D1", "effect": "Deny",
         "actions": ["s3:putobject"], "condition_keys": ["aws:securetransport"]},
        {"file": "b.json", "sid": "D2", "effect": "Deny",
         "actions": ["s3:putobject"], "condition_keys": ["aws:securetransport"]},
    ]
    assert dcc.find_candidates(statements) == []


def test_no_action_overlap_no_candidate() -> None:
    statements = [
        {"file": "a.json", "sid": "D1", "effect": "Deny",
         "actions": ["s3:putobject"], "condition_keys": []},
        {"file": "b.json", "sid": "A1", "effect": "Allow",
         "actions": ["ec2:runinstances"], "condition_keys": []},
    ]
    assert dcc.find_candidates(statements) == []


def test_glob_action_matches_concrete() -> None:
    """A prefix:* Allow overlaps a concrete Deny under the same prefix."""
    statements = [
        {"file": "deny.json", "sid": "D", "effect": "Deny",
         "actions": ["bedrock-agentcore:deleteagentruntime"], "condition_keys": []},
        {"file": "allow.json", "sid": "A", "effect": "Allow",
         "actions": ["bedrock-agentcore:*"], "condition_keys": []},
    ]
    cands = dcc.find_candidates(statements)
    assert len(cands) == 1
    assert cands[0]["kind"] == "deny_vs_allow"
    assert "bedrock-agentcore:deleteagentruntime" in cands[0]["shared_actions"]


def test_build_prefilter_report_scans_dir(tmp_path: Path) -> None:
    root = tmp_path / ".service-approval" / "svc"
    prev = root / "05-recommended-guidance" / "preventive"
    iac = root / "05-recommended-guidance" / "iac"
    prev.mkdir(parents=True)
    iac.mkdir(parents=True)
    (prev / "scp.json").write_text(json.dumps({
        "Statement": [{"Sid": "DenyCreate", "Effect": "Deny",
                       "Action": "bedrock-agentcore:CreateAgentRuntime", "Resource": "*"}]
    }))
    (iac / "role-policy.json").write_text(json.dumps({
        "Statement": [{"Sid": "AllowCreate", "Effect": "Allow",
                       "Action": "bedrock-agentcore:CreateAgentRuntime", "Resource": "*"}]
    }))
    report = dcc.build_prefilter_report(root)
    assert report["statements_scanned"] == 2
    assert len(report["candidates"]) == 1
    assert report["verdict"] == "PENDING_JUDGE"
    # The prefilter report is schema-valid (pairs empty, candidates populated).
    assert schema_errors(report, "conflict-report") == []


def test_judged_report_validates_against_schema() -> None:
    """A judge-produced report (pairs populated, verdict CONFLICTS_FOUND) is
    schema-valid."""
    report = {
        "_metadata": {"service": "svc", "stage": "judged"},
        "statements_scanned": 2,
        "candidates": [],
        "pairs": [
            {"a": "preventive/scp.json#DenyCreate", "b": "iac/role.json#AllowCreate",
             "kind": "deny_vs_allow",
             "explanation": "the SCP denies a create the IaC role policy grants",
             "severity": "warning"},
        ],
        "verdict": "CONFLICTS_FOUND",
    }
    assert schema_errors(report, "conflict-report") == []
