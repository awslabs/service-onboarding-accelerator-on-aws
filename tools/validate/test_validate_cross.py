"""Tests for validate_cross.py CHECK-X2 control-coverage.

Focus: the deferred-preventive-control reconciliation. A control the preventive
recommender marked REFER_TO_REFERENCE or ROUTE_DETECTIVE (recorded in
preventive-plan.json) is an intentional non-authoring decision and must NOT be
flagged as an orphan. A preventive control that is simply MISSING (no artifact,
no plan decision) must still be flagged.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_cross import (
    check_boundary_org_prerequisite,
    check_control_coverage,
    _deferred_preventive_controls,
    _org_attaches_permission_boundaries,
)


def _mapping(*control_ids, mechanism="SCP"):
    return {"controls": [{"id": c, "mechanism": mechanism} for c in control_ids]}


def _write_plan(gen_dir: Path, decisions):
    (gen_dir / "preventive-plan.json").write_text(json.dumps(
        {"_metadata": {"service": "lambda"}, "decisions": decisions}
    ))


def _write_anchored_scp(prev_dir: Path, name, control_ids):
    (prev_dir / name).write_text(json.dumps({
        "_metadata": {
            "controls": control_ids,
            "reference": {"example_id": "anchor-1"},
        },
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "lambda:CreateFunction", "Resource": "*"}],
    }))


def _setup(tmp_path):
    gen = tmp_path / "05-generate"
    prev = gen / "preventive"
    prev.mkdir(parents=True)
    return gen, prev


def test_authored_control_is_covered(tmp_path):
    gen, prev = _setup(tmp_path)
    _write_anchored_scp(prev, "scp-policy.json", ["CTRL-ORG-PRV-001"])
    errors = check_control_coverage(str(gen), _mapping("CTRL-ORG-PRV-001"))
    assert errors == []


def test_refer_to_reference_control_not_flagged(tmp_path):
    gen, prev = _setup(tmp_path)
    # No artifact for PRV-002, but the plan records it as REFER_TO_REFERENCE.
    _write_anchored_scp(prev, "scp-policy.json", ["CTRL-ORG-PRV-001"])
    _write_plan(gen, [
        {"control_id": "CTRL-ORG-PRV-001", "mechanism": "SCP", "preventable": True,
         "decision": "GENERATE_SCP", "anchor": {"example_id": "anchor-1"}},
        {"control_id": "CTRL-ORG-PRV-002", "mechanism": "SCP", "preventable": True,
         "decision": "REFER_TO_REFERENCE", "anchor": None},
    ])
    errors = check_control_coverage(str(gen), _mapping("CTRL-ORG-PRV-001", "CTRL-ORG-PRV-002"))
    assert errors == [], errors


def test_route_detective_control_not_flagged(tmp_path):
    gen, prev = _setup(tmp_path)
    _write_anchored_scp(prev, "scp-policy.json", ["CTRL-ORG-PRV-001"])
    _write_plan(gen, [
        {"control_id": "CTRL-ORG-PRV-001", "mechanism": "SCP", "preventable": True,
         "decision": "GENERATE_SCP", "anchor": {"example_id": "anchor-1"}},
        {"control_id": "CTRL-ORG-PRV-003", "mechanism": "SCP", "preventable": False,
         "decision": "ROUTE_DETECTIVE", "anchor": None, "route_to": "detective"},
    ])
    errors = check_control_coverage(str(gen), _mapping("CTRL-ORG-PRV-001", "CTRL-ORG-PRV-003"))
    assert errors == []


def test_missing_control_with_no_plan_decision_still_flagged(tmp_path):
    """A control absent from artifacts AND not deferred in the plan is an orphan."""
    gen, prev = _setup(tmp_path)
    _write_anchored_scp(prev, "scp-policy.json", ["CTRL-ORG-PRV-001"])
    _write_plan(gen, [
        {"control_id": "CTRL-ORG-PRV-001", "mechanism": "SCP", "preventable": True,
         "decision": "GENERATE_SCP", "anchor": {"example_id": "anchor-1"}},
        # CTRL-ORG-PRV-002 has a GENERATE_SCP decision but no artifact was written —
        # that is a real generation gap, not a deferral.
        {"control_id": "CTRL-ORG-PRV-002", "mechanism": "SCP", "preventable": True,
         "decision": "GENERATE_SCP", "anchor": {"example_id": "anchor-1"}},
    ])
    errors = check_control_coverage(str(gen), _mapping("CTRL-ORG-PRV-001", "CTRL-ORG-PRV-002"))
    assert len(errors) == 1 and "CTRL-ORG-PRV-002" in errors[0]


def test_no_plan_preserves_old_behavior(tmp_path):
    """Without preventive-plan.json, an uncovered control is still an orphan."""
    gen, prev = _setup(tmp_path)
    _write_anchored_scp(prev, "scp-policy.json", ["CTRL-ORG-PRV-001"])
    errors = check_control_coverage(str(gen), _mapping("CTRL-ORG-PRV-001", "CTRL-ORG-PRV-099"))
    assert len(errors) == 1 and "CTRL-ORG-PRV-099" in errors[0]


def test_deferred_helper_reads_plan(tmp_path):
    gen, _ = _setup(tmp_path)
    _write_plan(gen, [
        {"control_id": "CTRL-ORG-PRV-002", "decision": "REFER_TO_REFERENCE"},
        {"control_id": "CTRL-ORG-PRV-003", "decision": "ROUTE_DETECTIVE"},
        {"control_id": "CTRL-ORG-PRV-001", "decision": "GENERATE_SCP"},
    ])
    deferred = _deferred_preventive_controls(str(gen))
    assert deferred == {"CTRL-ORG-PRV-002", "CTRL-ORG-PRV-003"}


def test_deferred_helper_empty_without_plan(tmp_path):
    gen, _ = _setup(tmp_path)
    assert _deferred_preventive_controls(str(gen)) == set()


# ---------- X4: permission-boundary org prerequisite ----------


def _write_intake(tmp_path: Path, *, boundaries_attached=None):
    intake = tmp_path / "00-intake"
    intake.mkdir(parents=True, exist_ok=True)
    manifest = {"service": {"name": "lambda"}}
    if boundaries_attached is not None:
        manifest["org_context"] = {"permission_boundaries_attached": boundaries_attached}
    (intake / "intake-manifest.json").write_text(json.dumps(manifest))


def test_boundary_generate_without_optin_flagged(tmp_path):
    """A GENERATE_IAM boundary decision with no recorded org opt-in fails X4."""
    gen, _ = _setup(tmp_path)
    _write_plan(gen, [
        {"control_id": "CTRL-ACC-PRV-001", "mechanism": "IAM Permission Boundary",
         "decision": "GENERATE_IAM"},
    ])
    # no intake org_context → opt-in absent
    errors = check_boundary_org_prerequisite(str(gen))
    assert len(errors) == 1
    assert "X4" in errors[0] and "CTRL-ACC-PRV-001" in errors[0]


def test_boundary_refer_without_optin_passes(tmp_path):
    """The same boundary control as REFER_TO_REFERENCE is the default — no X4."""
    gen, _ = _setup(tmp_path)
    _write_plan(gen, [
        {"control_id": "CTRL-ACC-PRV-001", "mechanism": "IAM Permission Boundary",
         "decision": "REFER_TO_REFERENCE"},
    ])
    assert check_boundary_org_prerequisite(str(gen)) == []


def test_boundary_generate_with_optin_passes(tmp_path):
    """With org_context.permission_boundaries_attached=true, GENERATE_IAM is OK."""
    gen, _ = _setup(tmp_path)
    _write_intake(tmp_path, boundaries_attached=True)
    _write_plan(gen, [
        {"control_id": "CTRL-ACC-PRV-001", "mechanism": "IAM Permission Boundary",
         "decision": "GENERATE_IAM"},
    ])
    assert check_boundary_org_prerequisite(str(gen)) == []


def test_non_boundary_iam_decision_not_affected(tmp_path):
    """A GENERATE_IAM decision for a NON-boundary mechanism (e.g. VPCE / resource
    policy) is not an X4 concern."""
    gen, _ = _setup(tmp_path)
    _write_plan(gen, [
        {"control_id": "CTRL-RES-PRV-001", "mechanism": "VPC Endpoint Policy",
         "decision": "GENERATE_IAM"},
    ])
    assert check_boundary_org_prerequisite(str(gen)) == []


def test_org_optin_helper_defaults_false(tmp_path):
    gen, _ = _setup(tmp_path)
    # no intake manifest at all
    assert _org_attaches_permission_boundaries(str(gen)) is False
    # manifest present but no org_context
    _write_intake(tmp_path, boundaries_attached=None)
    assert _org_attaches_permission_boundaries(str(gen)) is False
    # explicit false
    _write_intake(tmp_path, boundaries_attached=False)
    assert _org_attaches_permission_boundaries(str(gen)) is False
    # explicit true
    _write_intake(tmp_path, boundaries_attached=True)
    assert _org_attaches_permission_boundaries(str(gen)) is True
