"""Custom coverage depends on source evidence, never on CCM wording scores."""
import copy
import json

import pytest

from framework_review import document_review_errors, DIRECT_EVIDENCE_METHOD
from validate_state import check_framework_mapped
from test_threat_model_integrity import script

CID = "CTRL-ACC-DET-001"


def fixture():
    control = {"id": CID, "scope": "ACC", "category": "DET", "mechanism": "CloudTrail",
               "trace_source": "threat_model",
               "mitigation_references": [{"alias": "Mitigation.EXAMPLE.1", "uuid": "source-uuid"}]}
    document = {
        "_metadata": {"framework_mapping_method": DIRECT_EVIDENCE_METHOD},
        "framework_mapping": [{
            "objective_id": "CUSTOM-LOG-1", "status": "MAPPED",
            "reason": "Service access records support the event collection requirement.",
            "anchor": {"anchor_score": 0.01, "status": "uncertain"},
            "controls": [{"control_id": CID, "rationale": "Records access events.",
                          "citation": {"source": "threat_model",
                                       "objective_requirement": "collect access events",
                                       "mitigation_alias": "Mitigation.EXAMPLE.1",
                                       "mitigation_uuid": "source-uuid"}}],
        }],
    }
    return document, [control]


def test_weak_ccm_match_does_not_block_direct_model_evidence():
    document, controls = fixture()
    assert document_review_errors(document, controls) == []


def test_strong_ccm_match_does_not_replace_source_evidence():
    document, controls = fixture()
    document["framework_mapping"][0]["anchor"] = {"anchor_score": 1, "status": "anchored"}
    del document["framework_mapping"][0]["controls"][0]["citation"]
    assert any("citation" in e for e in document_review_errors(document, controls))


@pytest.mark.parametrize("change", ["wrong_uuid", "wrong_alias", "downgraded_source", "blank_requirement"])
def test_model_citation_cannot_be_fabricated_or_downgraded(change):
    document, controls = fixture()
    citation = document["framework_mapping"][0]["controls"][0]["citation"]
    if change == "wrong_uuid": citation["mitigation_uuid"] = "different"
    if change == "wrong_alias": citation["mitigation_alias"] = "Mitigation.EXAMPLE.2"
    if change == "downgraded_source":
        citation.update(source="aws_doc", reference_url="https://docs.aws.amazon.com/example/")
    if change == "blank_requirement": citation["objective_requirement"] = " "
    assert document_review_errors(document, controls)


def test_supplemental_control_is_distinct_and_requires_documentation():
    document, controls = fixture()
    controls[0] = {"id": CID, "trace_source": "assessment_gap"}
    citation = document["framework_mapping"][0]["controls"][0]["citation"]
    citation.clear()
    citation.update(source="assessment_gap", objective_requirement="collect access events")
    assert document_review_errors(document, controls)
    citation["reference_url"] = "https://docs.aws.amazon.com/example/"
    assert not document_review_errors(document, controls)
    citation["source"] = "ccmv4"
    assert document_review_errors(document, controls)


def test_uncertainty_and_not_applicable_remain_valid_evidence_decisions():
    document, controls = fixture()
    row = document["framework_mapping"][0]
    row.update(status="UNCERTAIN", review_reason="The recorded event content is not verified.")
    row["controls"][0].pop("citation")
    assert not document_review_errors(document, controls)
    row.update(status="N/A", controls=[], reason="Enterprise board duties are outside service configuration.")
    document["unmapped_control_reviews"] = [{
        "control_id": CID, "status": "no_framework_match",
        "rationale": "The control records service events; this framework only covers board duties.",
        "reviewed_objective_ids": ["CUSTOM-LOG-1"],
    }]
    assert not document_review_errors(document, controls)


def test_new_custom_run_requires_the_evidence_contract_marker(tmp_path):
    document, controls = fixture()
    (tmp_path / "map-controls-generated.json").write_text(json.dumps({"controls": controls}))
    (tmp_path / "custom_to_ccmv4_anchor.json").write_text(json.dumps({"purpose": "advisory_guidance_lookup"}))
    document.pop("_metadata")
    assert any("framework_mapping_method" in e for e in check_framework_mapped(document, str(tmp_path)))


def test_assembly_retains_evidence_gate_and_legacy_artifacts_are_unchanged():
    document, controls = fixture()
    assembly = script("map-assemble")
    result = assembly.assemble_mapping_results(
        controls, [], {"framework": {"name": "Customer"}}, document, {}, "example", {})
    assert result["_metadata"]["framework_mapping_method"] == DIRECT_EVIDENCE_METHOD
    assert not document_review_errors(result, controls)
    legacy = copy.deepcopy(document)
    legacy.pop("_metadata")
    legacy["framework_mapping"][0]["controls"][0].pop("citation")
    assert not document_review_errors(legacy, controls)
