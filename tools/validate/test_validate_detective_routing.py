"""Tests for the preventive→detective routing hand-off validator.

Covers: schema validation, the uncovered-routed-objective failure (covered_by
null/empty), the covered-but-missing-file failure, the happy path with an
existing artifact, and the absent-file no-op.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_detective_routing as vdr  # noqa: E402


def _routing(routed):
    return {"_metadata": {"service": "lambda"}, "routed": routed}


def test_schema_rejects_bad_control_id():
    doc = _routing([{"control_id": "bad", "reason": "x"}])
    errors = vdr.check_routing(doc, None)
    assert any("SCHEMA" in e for e in errors)


def test_uncovered_routed_objective_fails():
    doc = _routing([{"control_id": "CTRL-ORG-PRV-007", "reason": "not preventable", "covered_by": None}])
    errors = vdr.check_routing(doc, None)
    assert len(errors) == 1 and "no covered_by" in errors[0]


def test_covered_but_missing_file_fails(tmp_path):
    gen = tmp_path / "05-generate"
    (gen / "detective").mkdir(parents=True)
    doc = _routing([
        {"control_id": "CTRL-ORG-PRV-007", "reason": "r", "covered_by": "config-rules.json"},
    ])
    errors = vdr.check_routing(doc, gen)
    assert len(errors) == 1 and "no such artifact" in errors[0]


def test_covered_with_existing_file_passes(tmp_path):
    gen = tmp_path / "05-generate"
    det = gen / "detective"
    det.mkdir(parents=True)
    (det / "config-rules.json").write_text("{}")
    doc = _routing([
        {"control_id": "CTRL-ORG-PRV-007", "reason": "r", "covered_by": "config-rules.json"},
    ])
    assert vdr.check_routing(doc, gen) == []


def test_covered_by_list_all_present(tmp_path):
    gen = tmp_path / "05-generate"
    det = gen / "detective"
    det.mkdir(parents=True)
    (det / "config-rules.json").write_text("{}")
    (gen / "responsive").mkdir()
    (gen / "responsive" / "ssm-runbook.yaml").write_text("x")
    doc = _routing([
        {"control_id": "CTRL-RES-PRV-003", "reason": "r",
         "covered_by": ["config-rules.json", "ssm-runbook.yaml"]},
    ])
    assert vdr.check_routing(doc, gen) == []


def test_no_coverage_check_when_generate_dir_none():
    # covered_by present but no dir to check against → coverage existence skipped.
    doc = _routing([{"control_id": "CTRL-ORG-PRV-007", "reason": "r", "covered_by": "x.json"}])
    assert vdr.check_routing(doc, None) == []


def test_check_service_absent_file_is_noop(tmp_path):
    # No detective-routing.json → nothing routed → clean.
    (tmp_path / "05-generate").mkdir(parents=True)
    assert vdr.check_service(tmp_path) == []


def test_check_service_reads_routing(tmp_path):
    gen = tmp_path / "05-generate"
    gen.mkdir(parents=True)
    (gen / "detective-routing.json").write_text(json.dumps(
        _routing([{"control_id": "CTRL-ORG-PRV-007", "reason": "r", "covered_by": None}])
    ))
    errors = vdr.check_service(tmp_path)
    assert len(errors) == 1 and "no covered_by" in errors[0]
