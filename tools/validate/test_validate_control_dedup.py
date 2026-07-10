"""Tests for semantic control de-duplication.

Covers the dedup collapse in scripts/map-assemble.py (canonical key, survivor
selection, traceability-field union, framework-mapping remap) and the
validate_control_dedup.py count guard that proves the collapse held.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_control_dedup as vcd  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_assemble():
    spec = importlib.util.spec_from_file_location(
        "map_assemble", REPO_ROOT / "scripts" / "map-assemble.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ma = _load_assemble()


def _ctrl(cid, name, mechanism="SCP", scope="ORG", category="PRV",
          resource_types=None, actions=None, posture="preventative-request",
          mitigation_ids=None):
    return {
        "id": cid,
        "name": name,
        "mechanism": mechanism,
        "scope": scope,
        "category": category,
        "resource_types": resource_types or ["AWS::Lambda::Function"],
        "actions": actions or ["lambda:CreateFunction"],
        "posture": posture,
        "mitigation_ids": mitigation_ids or ["M-Function.0"],
    }


# --- dedup_controls ---------------------------------------------------------

def test_identical_controls_collapse_to_survivor():
    controls = [
        _ctrl("CTRL-ORG-PRV-002", "Require VPC networking on capacity provider via SCP",
              mitigation_ids=["M-CapacityProvider.1"]),
        _ctrl("CTRL-ORG-PRV-001", "Require VPC networking on capacity provider via SCP",
              mitigation_ids=["M-CapacityProvider.0"]),
    ]
    deduped, remap = ma.dedup_controls(controls)
    assert len(deduped) == 1
    # Survivor is the lexicographically smallest id.
    assert deduped[0]["id"] == "CTRL-ORG-PRV-001"
    # Both source ids remap to the survivor.
    assert remap["CTRL-ORG-PRV-001"] == "CTRL-ORG-PRV-001"
    assert remap["CTRL-ORG-PRV-002"] == "CTRL-ORG-PRV-001"
    # mitigation_ids unioned + sorted onto survivor.
    assert deduped[0]["mitigation_ids"] == ["M-CapacityProvider.0", "M-CapacityProvider.1"]


def test_different_actions_stay_distinct():
    controls = [
        _ctrl("CTRL-ORG-PRV-001", "Same name", actions=["lambda:CreateFunction"]),
        _ctrl("CTRL-ORG-PRV-002", "Same name", actions=["lambda:UpdateFunctionCode"]),
    ]
    deduped, _ = ma.dedup_controls(controls)
    assert len(deduped) == 2


def test_different_mechanism_stays_distinct():
    controls = [
        _ctrl("CTRL-ORG-PRV-001", "Same name", mechanism="SCP"),
        _ctrl("CTRL-RES-PRV-001", "Same name", mechanism="Resource Policy", scope="RES"),
    ]
    deduped, _ = ma.dedup_controls(controls)
    assert len(deduped) == 2


def test_name_whitespace_and_case_normalized():
    controls = [
        _ctrl("CTRL-ORG-PRV-001", "Require  VPC Networking"),
        _ctrl("CTRL-ORG-PRV-002", "require vpc networking"),
    ]
    deduped, _ = ma.dedup_controls(controls)
    assert len(deduped) == 1


def test_survivor_list_fields_sorted_even_without_dups():
    controls = [_ctrl("CTRL-ORG-PRV-001", "x", mitigation_ids=["M-b.0", "M-a.0"])]
    deduped, _ = ma.dedup_controls(controls)
    assert deduped[0]["mitigation_ids"] == ["M-a.0", "M-b.0"]


# --- remap_framework_mapping ------------------------------------------------

def test_framework_mapping_references_remapped():
    fw = {
        "framework_mapping": [
            {"objective_id": "IAM-01", "status": "MAPPED", "controls": [
                {"control_id": "CTRL-ORG-PRV-001", "coverage_level": "Partial Coverage", "rationale": "a"},
                {"control_id": "CTRL-ORG-PRV-002", "coverage_level": "Full Coverage", "rationale": "b"},
            ]},
        ],
        "quality_gate_results": {"orphaned_controls": ["CTRL-ORG-PRV-002"]},
    }
    remap = {"CTRL-ORG-PRV-001": "CTRL-ORG-PRV-001", "CTRL-ORG-PRV-002": "CTRL-ORG-PRV-001"}
    ma.remap_framework_mapping(fw, remap)
    ctrls = fw["framework_mapping"][0]["controls"]
    # Both collapsed to one entry, keeping the stronger Full Coverage.
    assert len(ctrls) == 1
    assert ctrls[0]["control_id"] == "CTRL-ORG-PRV-001"
    assert ctrls[0]["coverage_level"] == "Full Coverage"
    # Orphan list deduped after remap.
    assert fw["quality_gate_results"]["orphaned_controls"] == ["CTRL-ORG-PRV-001"]


# --- validate_control_dedup -------------------------------------------------

def test_check_dedup_clean_after_collapse():
    controls = [
        _ctrl("CTRL-ORG-PRV-001", "A"),
        _ctrl("CTRL-ACC-DET-001", "B", mechanism="AWS Config Rule", scope="ACC",
              category="DET", posture="reactive-detective"),
    ]
    deduped, _ = ma.dedup_controls(controls)
    errors, stats = vcd.check_dedup({"controls": deduped})
    assert errors == []
    assert stats["total_controls"] == 2
    assert stats["distinct_controls"] == 2


def test_check_dedup_flags_residual_duplicate():
    # Two undeduped controls sharing a canonical key.
    controls = [
        _ctrl("CTRL-ORG-PRV-001", "Dup"),
        _ctrl("CTRL-ORG-PRV-002", "Dup"),
    ]
    errors, stats = vcd.check_dedup({"controls": controls})
    assert len(errors) == 1 and "canonical identity" in errors[0]
    assert stats["distinct_controls"] == 1
    assert stats["duplicate_groups"] == 1


def test_check_service_absent_file(tmp_path):
    (tmp_path / "04-map").mkdir(parents=True)
    errors, stats = vcd.check_service(tmp_path)
    assert errors == [] and stats["total_controls"] == 0


def test_check_service_reads_results(tmp_path):
    map_dir = tmp_path / "04-map"
    map_dir.mkdir(parents=True)
    (map_dir / "mapping-results.json").write_text(json.dumps(
        {"controls": [_ctrl("CTRL-ORG-PRV-001", "Dup"), _ctrl("CTRL-ORG-PRV-002", "Dup")]}
    ))
    errors, _ = vcd.check_service(tmp_path)
    assert len(errors) == 1


def test_validator_canonical_key_matches_assemble():
    # The validator must use the same key the collapse uses, or it can't guard it.
    c = _ctrl("CTRL-ORG-PRV-001", "X")
    assert vcd.canonical_control_key(c) == ma.canonical_control_key(c)
