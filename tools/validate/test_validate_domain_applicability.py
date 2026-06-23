"""Tests for the domain-applicability validator.

Covers: application-code over-claim (platform-config mechanism → AIS-02/04/05),
N/A-by-default domains (DCS/UEM/BCR/IPY + TVM-10) mapped without override fields,
the override happy path, the DSP-03/04 resource-tag over-claim, the
mechanism-lookup-absent degrade, and the non-CCMv4 no-op.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_domain_applicability as vda  # noqa: E402


def _mapped(mappings):
    return {"framework_mapping": mappings}


def _ctrls(*controls):
    return {c["id"]: c for c in controls}


def _ctrl(cid, mechanism):
    return {"id": cid, "mechanism": mechanism}


# --- Check 1: application-code over-claim -----------------------------------

def test_cfn_guard_to_ais_objective_flagged():
    doc = _mapped([
        {"objective_id": "AIS-02", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ACC-PRO-005"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-ACC-PRO-005", "CloudFormation Guard"))
    errors = vda.check_applicability(doc, controls)
    assert len(errors) == 1 and "application-code" in errors[0]


def test_config_rule_to_ais_objective_flagged():
    doc = _mapped([
        {"objective_id": "AIS-05", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ACC-DET-004"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-ACC-DET-004", "AWS Config Rule"))
    assert len(vda.check_applicability(doc, controls)) == 1


def test_non_platform_mechanism_to_ais_not_flagged():
    # A hypothetical code-testing mechanism is not platform-config → no app-code error.
    doc = _mapped([
        {"objective_id": "AIS-02", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ACC-DET-009"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-ACC-DET-009", "CodeGuru Security Scan"))
    assert vda.check_applicability(doc, controls) == []


def test_app_code_check_skipped_without_mechanism_lookup():
    doc = _mapped([
        {"objective_id": "AIS-02", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ACC-PRO-005"}]},
    ])
    # No controls_by_id → mechanism-dependent check is skipped.
    assert vda.check_applicability(doc, None) == []


# --- Check 2: N/A-by-default domains ----------------------------------------

def test_dcs_mapped_without_override_flagged():
    doc = _mapped([
        {"objective_id": "DCS-05", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ORG-PRO-004"}]},
    ])
    errors = vda.check_applicability(doc, None)
    assert len(errors) == 1 and "N/A-by-default" in errors[0]


def test_ipy_mapped_without_override_flagged():
    doc = _mapped([
        {"objective_id": "IPY-03", "status": "MAPPED", "controls": []},
    ])
    assert len(vda.check_applicability(doc, None)) == 1


def test_tvm10_mapped_without_override_flagged():
    doc = _mapped([
        {"objective_id": "TVM-10", "status": "MAPPED", "controls": []},
    ])
    assert len(vda.check_applicability(doc, None)) == 1


def test_tvm05_mapped_is_allowed():
    # TVM-05 is intentionally mappable (works-with-Inspector) — no finding.
    doc = _mapped([
        {"objective_id": "TVM-05", "status": "MAPPED", "controls": []},
    ])
    assert vda.check_applicability(doc, None) == []


def test_na_by_default_with_override_passes():
    doc = _mapped([
        {"objective_id": "BCR-01", "status": "MAPPED",
         "applicability_justification": "Lambda versions support a recovery procedure.",
         "reference_url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html",
         "controls": []},
    ])
    assert vda.check_applicability(doc, None) == []


def test_na_by_default_partial_override_flagged():
    # justification but no reference_url → still flagged.
    doc = _mapped([
        {"objective_id": "DCS-05", "status": "MAPPED",
         "applicability_justification": "x", "controls": []},
    ])
    assert len(vda.check_applicability(doc, None)) == 1


def test_na_by_default_objective_marked_na_is_clean():
    doc = _mapped([
        {"objective_id": "DCS-05", "status": "N/A", "controls": []},
    ])
    assert vda.check_applicability(doc, None) == []


# --- Check 3: DSP data-classification over-claim ----------------------------

def test_tag_policy_to_dsp03_flagged():
    doc = _mapped([
        {"objective_id": "DSP-03", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ORG-PRO-004"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-ORG-PRO-004", "Tag Policy"))
    errors = vda.check_applicability(doc, controls)
    assert len(errors) == 1 and "data-sensitivity" in errors[0]


def test_encryption_to_dsp03_not_flagged():
    doc = _mapped([
        {"objective_id": "DSP-03", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-RES-PRV-001"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-RES-PRV-001", "KMS Key Policy"))
    assert vda.check_applicability(doc, controls) == []


# --- Framework-agnostic no-op -----------------------------------------------

def test_non_ccmv4_framework_is_noop():
    doc = _mapped([
        {"objective_id": "AC-2", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-ACC-PRO-005"}]},
    ])
    controls = _ctrls(_ctrl("CTRL-ACC-PRO-005", "CloudFormation Guard"))
    assert vda.check_applicability(doc, controls) == []


def test_check_service_absent_file_is_noop(tmp_path):
    (tmp_path / "04-map").mkdir(parents=True)
    assert vda.check_service(tmp_path) == []


def test_check_service_reads_mapping(tmp_path):
    map_dir = tmp_path / "04-map"
    map_dir.mkdir(parents=True)
    (map_dir / "map-framework-mapped.json").write_text(json.dumps(
        _mapped([{"objective_id": "DCS-05", "status": "MAPPED", "controls": []}])
    ))
    errors = vda.check_service(tmp_path)
    assert len(errors) == 1 and "N/A-by-default" in errors[0]


def test_check_service_uses_controls_for_mechanism(tmp_path):
    map_dir = tmp_path / "04-map"
    map_dir.mkdir(parents=True)
    (map_dir / "map-framework-mapped.json").write_text(json.dumps(
        _mapped([{"objective_id": "AIS-02", "status": "MAPPED",
                  "controls": [{"control_id": "CTRL-ACC-PRO-005"}]}])
    ))
    (map_dir / "map-controls-generated.json").write_text(json.dumps(
        {"controls": [{"id": "CTRL-ACC-PRO-005", "mechanism": "CloudFormation Guard"}]}
    ))
    errors = vda.check_service(tmp_path)
    assert len(errors) == 1 and "application-code" in errors[0]
