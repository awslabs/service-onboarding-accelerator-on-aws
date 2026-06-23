"""Tests for the deterministic preventive-plan builder.

Verifies the builder produces a schema-valid plan with the expected decision mix:
a feasible+anchored control → GENERATE_*, a not-preventable control →
ROUTE_DETECTIVE, a feasible-but-unanchored control → REFER_TO_REFERENCE.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "tools"))
sys.path.insert(0, str(_REPO / "tools" / "validate"))

import reference_index as ri  # noqa: E402
from _schemas import schema_errors  # noqa: E402


def _load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_preventive_plan", _REPO / "tools" / "benchmark" / "build_preventive_plan.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


bp = _load_builder()

VALIDATED = {
    "service": "lambda",
    "capabilities": {"iam": {"permission_only_actions": [], "condition_keys": [
        {"key": "lambda:CodeSigningConfigArn", "applies_to_actions": ["CreateFunction"]},
    ]}},
    "api_surface": {"operations": [{"operation": "CreateFunction", "parameters": []}]},
}

MAPPING = {
    "service": "lambda",
    "controls": [
        {"id": "CTRL-ORG-PRV-001", "category": "PRV", "mechanism": "SCP",
         "actions": ["lambda:CreateFunction"], "condition_keys": []},
        {"id": "CTRL-ORG-PRV-003", "category": "PRV", "mechanism": "SCP",
         "actions": ["lambda:DeleteAlias"], "condition_keys": []},  # no gating key
        {"id": "CTRL-RES-DET-009", "category": "DET", "mechanism": "AWS Config rule",
         "actions": [], "condition_keys": []},  # not PRV — ignored
    ],
}

EXAMPLES = [
    {"id": "scp-codesign", "mechanism": "SCP", "repo": "service-control-policy-examples",
     "source_url": "https://github.com/aws-samples/service-control-policy-examples/x",
     "governed_actions": ["lambda:CreateFunction"], "condition_keys": ["lambda:CodeSigningConfigArn"]},
]


def test_plan_decision_mix_and_schema():
    with patch.object(ri, "examples", lambda *a, **k: EXAMPLES), \
         patch.object(ri, "load_index", lambda *a, **k: {"version": 1, "examples": EXAMPLES}):
        plan = bp.build_plan(MAPPING, VALIDATED)

    by_id = {d["control_id"]: d for d in plan["decisions"]}
    # PRV-001: feasible (CodeSigningConfigArn gates CreateFunction) + anchored → GENERATE_SCP
    assert by_id["CTRL-ORG-PRV-001"]["decision"] == "GENERATE_SCP"
    assert by_id["CTRL-ORG-PRV-001"]["anchor"]["example_id"] == "scp-codesign"
    # PRV-003: DeleteAlias has no gating key → ROUTE_DETECTIVE
    assert by_id["CTRL-ORG-PRV-003"]["decision"] == "ROUTE_DETECTIVE"
    assert by_id["CTRL-ORG-PRV-003"]["route_to"] == "detective"
    # DET control ignored
    assert "CTRL-RES-DET-009" not in by_id

    # The produced plan must validate against the committed schema.
    assert schema_errors(plan, "preventive-plan") == []


def test_refer_to_reference_when_no_anchor():
    # Feasible control but no overlapping example → REFER_TO_REFERENCE.
    with patch.object(ri, "examples", lambda *a, **k: []), \
         patch.object(ri, "load_index", lambda *a, **k: {"version": 1, "examples": []}):
        plan = bp.build_plan(
            {"service": "lambda", "controls": [
                {"id": "CTRL-ORG-PRV-001", "category": "PRV", "mechanism": "SCP",
                 "actions": ["lambda:CreateFunction"], "condition_keys": []},
            ]},
            VALIDATED,
        )
    assert plan["decisions"][0]["decision"] == "REFER_TO_REFERENCE"
    assert plan["decisions"][0]["anchor"] is None
    assert schema_errors(plan, "preventive-plan") == []
