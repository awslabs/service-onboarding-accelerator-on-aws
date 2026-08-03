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
    "source_control_id": "CTRL-ORG-PRV-001",
    "mechanism": "SCP",
    "preventable": True,
    "enforcing_condition_keys": ["lambda:CodeSigningConfigArn"],
    "decision": "GENERATE_SCP",
    "anchor": {"example_id": "anchor-1", "repo": "r", "url": "u"},
    "citation": {"type": "reference", "id": "anchor-1", "url": "u"},
    "route_to": None,
    "rationale": "ok",
    "applicability": {
        "applies_to": "the resource subset the policy targets",
        "usage_notes": "scope to those resources; do not apply broadly",
    },
}
ROUTE = {
    "control_id": "CTRL-ORG-PRV-007",
    "source_control_id": "CTRL-ORG-PRV-007",
    "mechanism": "SCP",
    "preventable": False,
    "decision": "ROUTE_DETECTIVE",
    "anchor": None,
    "citation": {"type": "service-doc", "url": "https://docs.aws.amazon.com/x.html"},
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


def test_missing_source_control_id_fails_schema():
    """The schema marks source_control_id as required on every decision."""
    bad = {k: v for k, v in GOOD_SCP.items() if k != "source_control_id"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e and "source_control_id" in e for e in errors), errors


def test_missing_citation_fails_schema():
    """The schema marks citation as required on every decision."""
    bad = {k: v for k, v in GOOD_SCP.items() if k != "citation"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e and "citation" in e for e in errors), errors


def test_canopy_citation_without_id_fails():
    """A `citation.type == "canopy"` MUST cite the mitigation alias in `id`."""
    bad = dict(GOOD_SCP)
    bad["citation"] = {"type": "canopy", "url": "https://example/canopy"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_citation_with_neither_id_nor_url_fails():
    """A citation must carry at least one of id or url."""
    bad = dict(GOOD_SCP)
    bad["citation"] = {"type": "reference"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_citation_with_unknown_type_fails():
    """The citation type enum is closed."""
    bad = dict(GOOD_SCP)
    bad["citation"] = {"type": "manual", "id": "x"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_route_decision_still_requires_citation():
    """Citation is required even on ROUTE_DETECTIVE / REFER_TO_REFERENCE rows —
    the customer needs the source pointer regardless of decision type."""
    bad = {k: v for k, v in ROUTE.items() if k != "citation"}
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e and "citation" in e for e in errors), errors


# ---- Canopy anchor resolution + No-MCP web verification -------------------

CANOPY_SCP = {
    "control_id": "CTRL-ORG-PRV-001",
    "source_control_id": "CTRL-ORG-PRV-001",
    "mechanism": "SCP",
    "preventable": True,
    "enforcing_condition_keys": ["aws:ResourceOrgID"],
    "decision": "GENERATE_SCP",
    "anchor": {"source": "canopy", "example_id": "Implementation.X.1"},
    "citation": {
        "type": "canopy",
        "id": "Implementation.X.1",
        "url": "https://docs.aws.amazon.com/x.html",
        "verified_via": "web",
    },
    "route_to": None,
    "rationale": "ok",
    "applicability": {
        "applies_to": "the resource subset the policy targets",
        "usage_notes": "scope to those resources; do not apply broadly",
    },
}


def test_verified_via_web_accepted_no_mcp():
    """No-MCP runs stamp canopy citation urls verified_via=web (rules/web-access)."""
    errors = vc.check_preventive_plan(_plan([CANOPY_SCP]))
    assert not any("SCHEMA" in e for e in errors), errors


def test_verified_via_unknown_value_fails():
    bad = dict(CANOPY_SCP, citation=dict(CANOPY_SCP["citation"], verified_via="carrier-pigeon"))
    errors = vc.check_preventive_plan(_plan([bad]))
    assert any("SCHEMA" in e for e in errors), errors


def test_canopy_anchor_resolves_against_canopy_index(tmp_path):
    """A canopy-sourced anchor resolves its alias against 02-research/canopy-index.json,
    NOT the reference-repo index."""
    import json

    root = tmp_path / "svc"
    (root / "02-research").mkdir(parents=True)
    (root / "05-recommended-guidance").mkdir(parents=True)
    (root / "02-research" / "canopy-index.json").write_text(
        json.dumps(
            {
                "_metadata": {"service": "x"},
                "mitigations": [],
                "implementations": [{"alias": "Implementation.X.1"}],
            }
        )
    )
    f = root / "05-recommended-guidance" / "preventive-plan.json"
    f.write_text(json.dumps(_plan([CANOPY_SCP])))
    # Reference-repo index deliberately does NOT contain the canopy alias.
    with patch.object(reference_index, "example_ids", lambda *a, **k: {"unrelated"}):
        errors = vc.check_preventive_plan(_plan([CANOPY_SCP]), str(f))
    assert errors == [], errors


def test_unresolvable_canopy_anchor_fails(tmp_path):
    import json

    root = tmp_path / "svc"
    (root / "02-research").mkdir(parents=True)
    (root / "05-recommended-guidance").mkdir(parents=True)
    (root / "02-research" / "canopy-index.json").write_text(
        json.dumps({"_metadata": {"service": "x"}, "mitigations": [], "implementations": []})
    )
    f = root / "05-recommended-guidance" / "preventive-plan.json"
    f.write_text(json.dumps(_plan([CANOPY_SCP])))
    errors = vc.check_preventive_plan(_plan([CANOPY_SCP]), str(f))
    assert any("does not resolve in 02-research/canopy-index.json" in e for e in errors), errors
