"""Rule 7 must agree at merge, intermediate state, assembly, and Stop."""
import copy
import json

import pytest

from framework_review import document_review_errors
from validate_state import check_framework_mapped, check_mapping_results
from validate_pipeline_integrity import check_mapping_state
from test_merge_domain_mappings import mdm
from test_threat_model_integrity import script

CID = "CTRL-ACC-PRV-001"


def document():
    return {
        "framework_mapping": [{"objective_id": "IAM-01", "status": "N/A", "controls": []}],
        "controls": [{"id": CID}],
    }


def review():
    return {"control_id": CID, "status": "no_framework_match",
            "rationale": "This control detects capacity exhaustion; IAM-01 concerns identity policy.",
            "reviewed_objective_ids": ["IAM-01"]}


def test_same_contract_at_every_gate(tmp_path):
    data = document()
    (tmp_path / 'map-controls-generated.json').write_text(json.dumps({'controls': data['controls']}))
    for accepted in (False, True):
        data['unmapped_control_reviews'] = [review()] if accepted else []
        errors = document_review_errors(data, data['controls'])
        quality, failures = mdm.run_quality_gates(data['framework_mapping'], {CID}, data['unmapped_control_reviews'])
        assert bool(errors) is not accepted
        assert quality['rule_7_orphan_review'] == ('PASS' if accepted else 'FAIL')
        assert bool([e for e in failures if 'Rule7' in e]) is not accepted
        assert bool([e for e in check_framework_mapped(data, str(tmp_path)) if 'Rule7' in e]) is not accepted
        assert bool([e for e in check_mapping_results(data) if 'Rule7' in e]) is not accepted
        (tmp_path / 'map-framework-mapped.json').write_text(json.dumps(data))
        assert bool([e for e in check_mapping_state(tmp_path) if 'Rule7' in e]) is not accepted


@pytest.mark.parametrize('change', ['blank', 'unknown_control', 'unknown_objective', 'duplicate', 'mapped', 'wrong_status', 'not_array'])
def test_invalid_reviews_cannot_bypass_gate(change):
    data = document()
    r = review()
    data['unmapped_control_reviews'] = [r]
    if change == 'blank': r['rationale'] = '  '
    elif change == 'unknown_control': r['control_id'] = 'CTRL-ACC-PRV-999'
    elif change == 'unknown_objective': r['reviewed_objective_ids'] = ['FAKE-99']
    elif change == 'duplicate': data['unmapped_control_reviews'].append(copy.deepcopy(r))
    elif change == 'mapped':
        data['framework_mapping'][0].update(status='MAPPED', controls=[{'control_id': CID}])
    elif change == 'wrong_status': r['status'] = 'unresolved'
    elif change == 'not_array': data['unmapped_control_reviews'] = {}
    assert document_review_errors(data, data['controls'])


def test_uncertain_candidate_is_accounted_without_claiming_coverage():
    data = document()
    data['framework_mapping'][0].update(status='UNCERTAIN', controls=[{'control_id': CID}])
    assert not document_review_errors(data, data['controls'])
    summary = mdm.build_coverage_summary(data['framework_mapping'], [{'id': 'IAM-01'}])
    assert summary['mapped'] == 0 and summary['uncertain'] == 1


def test_dedup_removes_obsolete_review_when_survivor_has_mapping():
    assembly = script('map-assemble')
    data = document()
    data['unmapped_control_reviews'] = [review()]
    survivor = 'CTRL-ACC-PRV-002'
    data['framework_mapping'][0].update(status='MAPPED', controls=[{'control_id': survivor}])
    assembly.remap_framework_mapping(data, {CID: survivor})
    assert data['unmapped_control_reviews'] == []
