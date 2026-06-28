"""Tests for the per-objective domain mapping-accuracy validator.

Covers the four anchored mapping decisions as fixtures — IVS-07 (no TLS control),
LOG-12 (access-event logging only), STA-12 (no access-control control), BCR-04
(multi-AZ resilience is clean) — each bad mapping FAILs and each corrected mapping
PASSes, plus the generalized default_na-without-override check, the control
classifier, the override happy path, the mechanism-lookup-absent degrade, and the
non-CCMv4 / absent-guidance no-ops.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_domain_mapping_accuracy as vma  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
GUIDANCE = vma.load_guidance()  # the real CCMv4 KB


def _mapped(mappings):
    return {"framework_mapping": mappings}


def _ctrls(*controls):
    return {c["id"]: c for c in controls}


def _ctrl(cid, mechanism, name="", description="", keywords=None):
    return {
        "id": cid,
        "mechanism": mechanism,
        "name": name,
        "description": description,
        "framework_keywords": keywords or [],
    }


# --- The guidance KB is present and well-formed ------------------------------

def test_guidance_loads():
    assert GUIDANCE is not None, "CCMv4 guidance KB must exist for these tests"
    idx = vma.build_objective_index(GUIDANCE)
    assert len(idx) == 197


# --- Control classifier ------------------------------------------------------

def test_classifier_matches_mechanism_exactly():
    classes = vma.classify_control(
        _ctrl("c", "KMS Key Policy"), GUIDANCE["mechanism_classes"]
    )
    assert "at_rest_encryption" in classes


def test_classifier_matches_keyword_substring():
    classes = vma.classify_control(
        _ctrl("c", "AWS Config Rule", name="Detect functions without TLS source access"),
        GUIDANCE["mechanism_classes"],
    )
    assert "transit_encryption" in classes


def test_classifier_config_rule_is_misconfig_detection():
    classes = vma.classify_control(
        _ctrl("c", "AWS Config Rule", name="Detect drift"),
        GUIDANCE["mechanism_classes"],
    )
    assert "misconfig_detection" in classes


# --- IVS-07 (migration process) must not get a TLS/transit control ----------

def test_ivs07_with_tls_control_fails():
    doc = _mapped([
        {"objective_id": "IVS-07", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard",
                            name="Validate event source mapping TLS source access"))
    errors = vma.check_accuracy(doc, controls, GUIDANCE)
    assert any("IVS-07" in e and "transit_encryption" in e for e in errors)


def test_ivs07_marked_na_is_clean():
    doc = _mapped([{"objective_id": "IVS-07", "status": "N/A", "controls": []}])
    assert vma.check_accuracy(doc, _ctrls(), GUIDANCE) == []


# --- LOG-12 (access logs) maps only to access-event logging ------------------

def test_log12_with_misconfig_control_fails():
    doc = _mapped([
        {"objective_id": "LOG-12", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "AWS Config Rule",
                            name="Detect unauthenticated URL or broad resource policy"))
    errors = vma.check_accuracy(doc, controls, GUIDANCE)
    assert any("LOG-12" in e and "misconfig_detection" in e for e in errors)


def test_log12_with_access_logging_control_passes():
    # A CloudTrail access-event-logging control genuinely satisfies LOG-12 (it is
    # in allow_mechanisms), so even if it tripped a denied keyword it is allowed.
    doc = _mapped([
        {"objective_id": "LOG-12", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudTrail",
                            name="Record function invocation access events"))
    assert vma.check_accuracy(doc, controls, GUIDANCE) == []


# --- STA-12 (supply-chain agreements) must not get the IAM/layer-sharing control

def test_sta12_with_access_control_fails():
    doc = _mapped([
        {"objective_id": "STA-12", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard",
                            name="Validate layer version policy principal scoping",
                            keywords=["access control", "least privilege", "sharing"]))
    errors = vma.check_accuracy(doc, controls, GUIDANCE)
    # STA-12 is default_na AND access_control is denied — at least the deny fires.
    assert any("STA-12" in e and "access_control" in e for e in errors)


# --- BCR-04 (continuity planning) mapped to multi-AZ resilience is clean ------

def test_bcr04_with_resilience_control_passes_accuracy():
    doc = _mapped([
        {"objective_id": "BCR-04", "status": "MAPPED",
         "applicability_justification": "Multi-AZ placement keeps the function "
                                         "available through an AZ disruption.",
         "reference_url": "https://docs.aws.amazon.com/lambda/latest/dg/foundation-networking.html",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard",
                            name="Validate function multi-AZ private subnet placement",
                            keywords=["availability", "high availability"]))
    # BCR-04 is mappable in the guidance, resilience is allowed → no finding.
    assert vma.check_accuracy(doc, controls, GUIDANCE) == []


def test_bcr04_mapped_is_not_default_na_flagged():
    # BCR-04 mapped WITHOUT override must not raise a default_na finding, because
    # the guidance marks BCR-04 mappable (the blanket BCR-N/A is gone).
    doc = _mapped([
        {"objective_id": "BCR-04", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard",
                            name="Validate multi-AZ placement",
                            keywords=["availability"]))
    errors = vma.check_accuracy(doc, controls, GUIDANCE)
    assert not any("default-N/A" in e for e in errors)


# --- Generalized default_na-without-override ---------------------------------

def test_default_na_mapped_without_override_fails():
    # BCR-08 (Backup) is default_na in the guidance.
    doc = _mapped([{"objective_id": "BCR-08", "status": "MAPPED", "controls": []}])
    errors = vma.check_accuracy(doc, None, GUIDANCE)
    assert any("BCR-08" in e and "default-N/A" in e for e in errors)


def test_default_na_with_override_passes():
    doc = _mapped([
        {"objective_id": "BCR-08", "status": "MAPPED",
         "applicability_justification": "Service exposes a documented backup API.",
         "reference_url": "https://docs.aws.amazon.com/example.html",
         "controls": []},
    ])
    assert vma.check_accuracy(doc, None, GUIDANCE) == []


def test_default_na_partial_override_fails():
    doc = _mapped([
        {"objective_id": "BCR-08", "status": "MAPPED",
         "applicability_justification": "x", "controls": []},
    ])
    assert len(vma.check_accuracy(doc, None, GUIDANCE)) == 1


# --- Allowed-class escape hatch ----------------------------------------------

def test_denied_class_with_allowed_class_passes():
    # A control that matches a denied class but ALSO an allowed class is not a
    # mis-map. CEK-09 allows misconfig_detection, denies access_event_logging; a
    # control matching both is legitimate (it genuinely does the posture audit).
    doc = _mapped([
        {"objective_id": "CEK-09", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "AWS Config Rule",
                            name="Audit key usage via CloudTrail and detect non-CMK drift",
                            keywords=["cloudtrail", "drift"]))
    # matches access_event_logging (denied) AND misconfig_detection (allowed) → clean.
    assert vma.check_accuracy(doc, controls, GUIDANCE) == []


# --- Mechanism-lookup-absent degrade -----------------------------------------

def test_denied_class_check_skipped_without_controls():
    doc = _mapped([
        {"objective_id": "LOG-12", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    # No controls_by_id → denied-class check skipped; LOG-12 is conditional (not
    # default_na) so the override check does not fire either → clean.
    assert vma.check_accuracy(doc, None, GUIDANCE) == []


# --- No-op safety nets -------------------------------------------------------

def test_absent_guidance_is_noop():
    doc = _mapped([
        {"objective_id": "IVS-07", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard", name="TLS"))
    assert vma.check_accuracy(doc, controls, None) == []


def test_non_ccmv4_framework_is_noop():
    doc = _mapped([
        {"objective_id": "AC-2", "status": "MAPPED",
         "controls": [{"control_id": "C1"}]},
    ])
    controls = _ctrls(_ctrl("C1", "CloudFormation Guard", name="TLS source access"))
    assert vma.check_accuracy(doc, controls, GUIDANCE) == []


def test_check_service_absent_file_is_noop(tmp_path):
    (tmp_path / "04-map").mkdir(parents=True)
    assert vma.check_service(tmp_path, GUIDANCE) == []


def test_check_service_reads_mapping(tmp_path):
    map_dir = tmp_path / "04-map"
    map_dir.mkdir(parents=True)
    (map_dir / "map-framework-mapped.json").write_text(json.dumps(
        _mapped([{"objective_id": "IVS-07", "status": "MAPPED",
                  "controls": [{"control_id": "C1"}]}])
    ))
    (map_dir / "map-controls-generated.json").write_text(json.dumps(
        {"controls": [{"id": "C1", "mechanism": "CloudFormation Guard",
                       "name": "Validate TLS source access", "framework_keywords": []}]}
    ))
    errors = vma.check_service(tmp_path, GUIDANCE)
    assert any("IVS-07" in e and "transit_encryption" in e for e in errors)
