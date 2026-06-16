"""Tests for the preventive-generation scorer (iteration harness).

Lives under tools/validate/ so the canonical `pytest tools/validate/` gate
collects it. Covers the three metrics on synthetic run dirs, the gap-stub
exemption, and the cross-run aggregate (mean + variance).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "validate"))  # noqa
sys.path.insert(0, str(_REPO / "tools" / "validate"))


def _load_scorer():
    spec = importlib.util.spec_from_file_location(
        "score_preventive", _REPO / "tools" / "benchmark" / "score_preventive.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


sp = _load_scorer()

VALIDATED = {
    "service": "lambda",
    "capabilities": {
        "iam": {
            "permission_only_actions": [],
            "condition_keys": [
                {"key": "lambda:CodeSigningConfigArn", "applies_to_actions": ["CreateFunction"]},
            ],
        }
    },
    "api_surface": {"operations": [{"operation": "CreateFunction", "parameters": []}]},
}

MAPPING_FEASIBLE = {
    "controls": [
        {"id": "C1", "category": "PRV", "mechanism": "SCP",
         "actions": ["lambda:CreateFunction"], "condition_keys": []},
    ]
}
MAPPING_NOT_PREVENTABLE = {
    "controls": [
        {"id": "C2", "category": "PRV", "mechanism": "SCP",
         "actions": ["lambda:DeleteFunction"], "condition_keys": []},
    ]
}

KNOWN = {"anchor-1"}


def _write(p: Path, data: dict):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))


def _anchored_scp(action="lambda:CreateFunction"):
    return {
        "_metadata": {"reference": {"example_id": "anchor-1"}},
        "Version": "2012-10-17",
        "Statement": [{"Sid": "S", "Effect": "Deny", "Action": action, "Resource": "*"}],
    }


def test_anchor_rate_all_anchored(tmp_path, monkeypatch):
    rd = tmp_path / "run-01"
    _write(rd / "preventive" / "scp-policy.json", _anchored_scp())
    rate, ok, tot = sp.anchor_rate(rd, KNOWN)
    assert (rate, ok, tot) == (1.0, 1, 1)


def test_anchor_rate_mixed(tmp_path):
    rd = tmp_path / "run-01"
    _write(rd / "preventive" / "good.json", _anchored_scp())
    bad = _anchored_scp()
    del bad["_metadata"]["reference"]
    _write(rd / "preventive" / "bad.json", bad)
    rate, ok, tot = sp.anchor_rate(rd, KNOWN)
    assert ok == 1 and tot == 2 and rate == 0.5


def test_anchor_rate_excludes_gap_stub(tmp_path):
    rd = tmp_path / "run-01"
    _write(rd / "preventive" / "rcp-policy.json",
           {"_metadata": {"rcp_gap": "n/a"}, "Statement": []})
    rate, ok, tot = sp.anchor_rate(rd, KNOWN)
    assert tot == 0 and rate == 1.0  # gap stub not counted


def test_rootcause_pass_rate_feasible():
    rate, ok, tot = sp.rootcause_pass_rate(MAPPING_FEASIBLE, VALIDATED)
    assert (rate, ok, tot) == (1.0, 1, 1)


def test_rootcause_pass_rate_not_preventable():
    rate, ok, tot = sp.rootcause_pass_rate(MAPPING_NOT_PREVENTABLE, VALIDATED)
    assert ok == 0 and tot == 1 and rate == 0.0


def test_action_real_rate(tmp_path):
    rd = tmp_path / "run-01"
    # one real action, one invented
    pol = _anchored_scp()
    pol["Statement"].append(
        {"Sid": "S2", "Effect": "Deny", "Action": "lambda:BogusAction", "Resource": "*"}
    )
    _write(rd / "preventive" / "scp-policy.json", pol)
    rate, real, tot = sp.action_real_rate(rd, VALIDATED)
    assert real == 1 and tot == 2 and rate == 0.5


def test_action_real_rate_ignores_cross_service_and_wildcards(tmp_path):
    rd = tmp_path / "run-01"
    pol = {
        "_metadata": {"reference": {"example_id": "anchor-1"}},
        "Statement": [
            {"Sid": "S", "Effect": "Deny",
             "Action": ["sts:AssumeRole", "lambda:*", "lambda:CreateFunction"],
             "Resource": "*"},
        ],
    }
    _write(rd / "preventive" / "scp-policy.json", pol)
    rate, real, tot = sp.action_real_rate(rd, VALIDATED)
    assert tot == 1 and real == 1 and rate == 1.0  # only lambda:CreateFunction counted


def test_score_run_shape(tmp_path):
    rd = tmp_path / "run-01"
    _write(rd / "preventive" / "scp-policy.json", _anchored_scp())
    s = sp.score_run(rd, VALIDATED, MAPPING_FEASIBLE, KNOWN)
    assert s["anchor_rate"] == 1.0
    assert s["rootcause_pass_rate"] == 1.0
    assert s["action_real_rate"] == 1.0


def test_aggregate_mean_and_variance():
    scores = [
        {"anchor_rate": 1.0, "rootcause_pass_rate": 1.0, "action_real_rate": 0.5},
        {"anchor_rate": 0.0, "rootcause_pass_rate": 1.0, "action_real_rate": 0.5},
    ]
    agg = sp.aggregate(scores)
    assert agg["runs"] == 2
    assert agg["anchor_rate"]["mean"] == 0.5
    assert agg["anchor_rate"]["variance"] == 0.25  # population variance of {1,0}
    assert agg["action_real_rate"]["variance"] == 0.0  # identical → zero variance


def test_aggregate_empty():
    agg = sp.aggregate([])
    assert agg["runs"] == 0
    assert agg["anchor_rate"]["mean"] == 0.0
