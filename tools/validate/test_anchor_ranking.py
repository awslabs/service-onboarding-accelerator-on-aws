"""Tests for the deterministic anchor-ranking helper.

Covers mechanism-family resolution, the overlap scoring (condition-key weighted
2x action overlap), deterministic tie-breaking, and the best_anchor None cases
(no family / no overlap). Also a smoke test against the committed real index.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "tools"))

import reference_index as ri  # noqa: E402


EXAMPLES = [
    {"id": "scp-a", "mechanism": "SCP",
     "governed_actions": ["s3:DeleteBucket", "s3:PutBucketPolicy"],
     "condition_keys": ["aws:PrincipalOrgID"]},
    {"id": "scp-b", "mechanism": "SCP",
     "governed_actions": ["ec2:RunInstances"],
     "condition_keys": ["aws:RequestedRegion"]},
    {"id": "rcp-a", "mechanism": "RCP",
     "governed_actions": ["s3:DeleteBucket"],
     "condition_keys": ["aws:PrincipalOrgID"]},
    {"id": "iam-a", "mechanism": "IAM",
     "governed_actions": ["lambda:CreateFunction"],
     "condition_keys": []},
    {"id": "pb-a", "mechanism": "permission-boundary",
     "governed_actions": ["lambda:CreateFunction"],
     "condition_keys": []},
]


@pytest.fixture
def stub_index(monkeypatch):
    monkeypatch.setattr(ri, "examples", lambda *a, **k: EXAMPLES)


def test_mechanism_family():
    assert ri.mechanism_family("SCP") == ["SCP"]
    assert "IAM" in ri.mechanism_family("Resource Policy")
    assert "permission-boundary" in ri.mechanism_family("IAM Permission Boundary")
    # Unknown mechanism falls back to itself.
    assert ri.mechanism_family("SomethingNew") == ["SomethingNew"]


def test_score_example_key_weighted_over_actions():
    ex = {"governed_actions": ["s3:DeleteBucket"], "condition_keys": ["aws:PrincipalOrgID"]}
    # control shares both the action and the key.
    s_both = ri.score_example(ex, ["s3:DeleteBucket"], ["aws:PrincipalOrgID"])
    # control shares only the action.
    s_action = ri.score_example(ex, ["s3:DeleteBucket"], [])
    # control shares only the key.
    s_key = ri.score_example(ex, ["sns:Publish"], ["aws:PrincipalOrgID"])
    assert s_both > s_key > s_action
    # key weighted 2x: key-only (2*1.0) beats action-only (1.0).
    assert s_key == pytest.approx(2.0)
    assert s_action == pytest.approx(1.0)


def test_score_action_match_is_case_and_wildcard_insensitive():
    ex = {"governed_actions": ["s3:DeleteBucket"], "condition_keys": []}
    assert ri.score_example(ex, ["s3:deletebucket"], []) == pytest.approx(1.0)
    assert ri.score_example(ex, ["s3:Delete*"], []) == 0.0  # "delete" != "deletebucket"


def test_rank_anchors_filters_by_family_and_sorts(stub_index):
    ranked = ri.rank_anchors("SCP", ["s3:DeleteBucket"], ["aws:PrincipalOrgID"])
    ids = [r["example"]["id"] for r in ranked]
    assert ids == ["scp-a", "scp-b"]  # scp-a overlaps both; scp-b zero
    assert ranked[0]["score"] > ranked[1]["score"]
    assert ranked[1]["score"] == 0.0


def test_rank_anchors_searches_whole_family(stub_index):
    # "Resource Policy" family is IAM + data-perimeter; iam-a is IAM.
    ranked = ri.rank_anchors("Resource Policy", ["lambda:CreateFunction"], [])
    assert any(r["example"]["id"] == "iam-a" for r in ranked)


def test_best_anchor_returns_top(stub_index):
    best = ri.best_anchor("SCP", ["s3:DeleteBucket"], ["aws:PrincipalOrgID"])
    assert best["id"] == "scp-a"


def test_best_anchor_none_when_no_overlap(stub_index):
    # SCP family exists but nothing overlaps these actions/keys.
    best = ri.best_anchor("SCP", ["dynamodb:GetItem"], ["dynamodb:LeadingKeys"])
    assert best is None


def test_best_anchor_none_when_no_family(stub_index):
    best = ri.best_anchor("NonexistentMechanism", ["s3:DeleteBucket"], [])
    assert best is None


def test_deterministic_tie_break(stub_index):
    # Two zero-score SCP examples — order by id.
    ranked = ri.rank_anchors("SCP", ["nonexistent:Action"], [])
    ids = [r["example"]["id"] for r in ranked]
    assert ids == sorted(ids)


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[2] / "data" / "reference-repos" / "index.yaml").exists(),
    reason="reference index not built",
)
def test_smoke_against_real_index():
    # A leave-org / org-id style SCP control should find an SCP anchor.
    best = ri.best_anchor(
        "SCP",
        ["organizations:LeaveOrganization"],
        ["aws:PrincipalOrgID"],
    )
    # Either a concrete anchor or None — must not raise, and if found must be SCP.
    if best is not None:
        assert best["mechanism"] == "SCP"
