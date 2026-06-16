"""Tests for preventive-plan.json schema + anchor-resolution validation.

Covers the recommender gate artifact: a valid plan passes; a bad decision enum,
a GENERATE_* row without an anchor, and a ROUTE_DETECTIVE row without a route are
all rejected by the schema; an anchor that doesn't resolve in the reference index
is rejected by the resolution layer.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tools/ for reference_index

import validate_controls as vc  # noqa: E402
import reference_index  # noqa: E402


def _plan(decisions):
    return {"_metadata": {"service": "lambda"}, "decisions": decisions}


GOOD_SCP = {
    "control_id": "CTRL-ORG-PRV-001",
    "mechanism": "SCP",
    "preventable": True,
    "enforcing_condition_keys": ["lambda:CodeSigningConfigArn"],
    "decision": "GENERATE_SCP",
    "anchor": {"example_id": "anchor-1", "repo": "r", "url": "u"},
    "route_to": None,
    "rationale": "ok",
}
ROUTE = {
    "control_id": "CTRL-ORG-PRV-007",
    "mechanism": "SCP",
    "preventable": False,
    "decision": "ROUTE_DETECTIVE",
    "anchor": None,
    "route_to": "detective",
    "rationale": "no gating key",
}


def test_valid_plan_passes():
    # Anchor "anchor-1" must resolve — stub the index.
    with patch.object(reference_index, "example_ids", lambda *a, **k: {"anchor-1"}):
        errors = vc.check_preventive_plan(_plan([GOOD_SCP, ROUTE]))
    assert errors == [], errors


def test_bad_decision_enum_fails():
    bad = dict(GOOD_SCP, decision="GENERATE_MAGIC")
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors)


def test_generate_without_anchor_fails():
    bad = dict(GOOD_SCP)
    bad["anchor"] = None
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_route_detective_without_route_to_fails():
    bad = dict(ROUTE)
    bad["route_to"] = None
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_bad_control_id_pattern_fails():
    bad = dict(GOOD_SCP, control_id="not-a-control-id")
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_unresolvable_anchor_fails_resolution_layer():
    with patch.object(reference_index, "example_ids", lambda *a, **k: {"different-id"}):
        errors = vc.check_preventive_plan(_plan([GOOD_SCP]))
    assert any("does not resolve" in e for e in errors), errors


def test_missing_metadata_service_fails():
    plan = {"_metadata": {}, "decisions": [GOOD_SCP]}
    errors = vc.check_preventive_plan(plan)
    assert any("SCHEMA" in e for e in errors), errors


def test_dispatcher_routes_preventive_plan(tmp_path):
    """validate_file routes preventive-plan.json to the plan checker."""
    import json
    f = tmp_path / "preventive-plan.json"
    f.write_text(json.dumps(_plan([GOOD_SCP])))
    with patch.object(reference_index, "example_ids", lambda *a, **k: {"anchor-1"}):
        errors = vc.validate_file(str(f))
    assert errors == [], errors
