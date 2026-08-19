"""Tests for scripts/threat_model_trace.py — the deterministic AWS Threat Model traceability resolver.

AWS Threat Model carries MITRE ATT&CK technique IDs on the threat objects; a mitigation's
techniques are recovered by walking mitigation.mappings[THREAT] -> threats[] ->
threat.mappings[FRAMEWORK]. These tests fix-pin that the chain resolves, that a
mitigation with no threat mapping degrades to an empty MITRE list (not a crash),
and that threading onto controls marks AWS Threat Model vs assessment-gap provenance.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "threat_model_trace.py"
FIXTURES = Path(__file__).parent / "fixtures"


def _load_module():
    spec = importlib.util.spec_from_file_location("threat_model_trace", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ct = _load_module()


def _fixture() -> dict:
    with open(FIXTURES / "threat_model_minimal.json") as f:
        return json.load(f)


def test_chain_resolves_mitre_for_mitigation_with_threat() -> None:
    """The CapacityProvider mitigation links to a threat carrying two MITRE
    FRAMEWORK mappings — both techniques resolve, plus the threat alias."""
    index = ct.build_trace_index(_fixture())
    cap = index["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]
    assert cap["alias"] == "Mitigation.LAMBDA.CapacityProvider.1"
    assert cap["mitre_techniques"] == ["T1530", "T1537"]
    assert cap["threat_aliases"] == ["Threat.LAMBDA.CapacityProvider.1"]


def test_mitigation_without_threat_mapping_yields_empty_mitre() -> None:
    """The Function mitigation maps only to an entity + goal (no THREAT) —
    its MITRE list is empty, and this is not a crash."""
    index = ct.build_trace_index(_fixture())
    fn = index["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]
    assert fn["alias"] == "Mitigation.LAMBDA.Function.1"
    assert fn["mitre_techniques"] == []
    assert fn["threat_aliases"] == []


def test_alias_index_keys_by_alias_and_carries_uuid() -> None:
    by_alias = ct.build_alias_index(_fixture())
    rec = by_alias["Mitigation.LAMBDA.CapacityProvider.1"]
    assert rec["mitigation_uuid"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    assert rec["mitre_techniques"] == ["T1530", "T1537"]


def test_thread_onto_threat_model_control() -> None:
    """A control stamped with a real AWS Threat Model alias gains alias/uuid/MITRE and
    trace_source 'threat_model'."""
    threat_model = _fixture()
    ctrl = {
        "id": "CTRL-RES-PRV-001",
        "mitigation_alias": "Mitigation.LAMBDA.CapacityProvider.1",
        "mitigation_ids": ["M-CapacityProvider.0"],
    }
    ct.thread_controls([ctrl], threat_model)
    assert ctrl["trace_source"] == "threat_model"
    assert ctrl["mitigation_uuid"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    assert ctrl["mitre_techniques"] == ["T1530", "T1537"]
    # The verbatim AWS Threat Model statement is threaded so a downstream citation can
    # quote it and be provenance-checked against the export.
    assert ctrl["mitigation_statement"] == (
        "Capacity provider operator role IAM service role should only be "
        "assumable by the Lambda principal."
    )
    # Backward-compat: the M- id list is untouched.
    assert ctrl["mitigation_ids"] == ["M-CapacityProvider.0"]


def test_thread_onto_assessment_gap_control() -> None:
    """A control with no resolvable AWS Threat Model alias degrades to an empty MITRE
    list + trace_source 'assessment_gap' — never an error."""
    threat_model = _fixture()
    ctrl = {"id": "CTRL-ACC-DET-002", "mitigation_ids": ["M-GAP.0"]}
    ct.thread_controls([ctrl], threat_model)
    assert ctrl["trace_source"] == "assessment_gap"
    assert ctrl["mitre_techniques"] == []


def test_no_threat_model_threads_all_as_assessment_gap() -> None:
    """An empty/absent AWS Threat Model (no mitigations) leaves every control marked
    assessment_gap with empty traceability."""
    ctrls = [{"id": "CTRL-ORG-PRV-003"}, {"id": "CTRL-ACC-DET-004"}]
    ct.thread_controls(ctrls, {"mitigations": [], "threats": []})
    assert all(c["trace_source"] == "assessment_gap" for c in ctrls)
    assert all(c["mitre_techniques"] == [] for c in ctrls)


def test_real_lambda_threat_model_all_mitigations_resolve() -> None:
    """On the real Lambda AWS Threat Model input, every mitigation resolves to >=1 MITRE
    technique — the traceability the final mapping cites."""
    lambda_threat_model = REPO / "runs" / "with-threat-model" / "input" / "lambda-threat-model.json"
    if not lambda_threat_model.exists():
        return  # repo checkout without the local run fixture; not a failure
    threat_model = json.loads(lambda_threat_model.read_text())
    index = ct.build_trace_index(threat_model)
    assert len(index) == len(threat_model["mitigations"])
    with_mitre = [r for r in index.values() if r["mitre_techniques"]]
    assert len(with_mitre) == len(index), "every Lambda mitigation should resolve MITRE"
