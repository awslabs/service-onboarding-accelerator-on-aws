"""Tests for the AWS Threat Model threat-model JSON shape detector and parser.

AWS Threat Model exports use a top-level `mitigations[]` and `threats[]` array. The
earlier research-mitigations parser only walked `entities[].mitigations[]`,
so AWS Threat Model mitigations were silently dropped. These tests fix-pin the
detector and the per-mitigation field carry-through.
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_model_parse import (
    is_threat_model_shape,
    is_threat_model_threats_shape,
    parse_threat_model_mitigations,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture() -> dict:
    with open(FIXTURES / "threat_model_minimal.json") as f:
        return json.load(f)


def test_threat_model_shape_detector_matches_top_level_mitigations() -> None:
    """The AWS Threat Model fixture has top-level mitigations[] and entity entries
    without a mitigations sub-key — the detector must say yes."""
    data = _load_fixture()
    assert is_threat_model_shape(data) is True


def test_threat_model_shape_detector_rejects_entity_nested() -> None:
    """An entity-nested doc (legacy shape) must NOT be classified as AWS Threat Model
    even when a top-level mitigations[] is also present — the legacy parser
    already handles that path."""
    data = {
        "entities": [
            {"id": "e1", "mitigations": [{"id": "M-1", "statement": "x"}]}
        ],
        "mitigations": [{"id": "top-1"}],
    }
    assert is_threat_model_shape(data) is False


def test_threat_model_shape_detector_rejects_empty() -> None:
    """No mitigations, no entities -> not AWS Threat Model."""
    assert is_threat_model_shape({}) is False
    assert is_threat_model_shape({"mitigations": [], "entities": []}) is False


def test_threat_model_threats_detector_matches_attack_surface_use() -> None:
    """research-attack-surface SKILL.md uses an independent detector that
    only requires both arrays to be non-empty."""
    data = _load_fixture()
    assert is_threat_model_threats_shape(data) is True


def test_threat_model_threats_detector_rejects_threats_only() -> None:
    """Without a top-level mitigations[], the file is not an AWS Threat Model export
    in the sense that research-attack-surface needs (it could be a plain
    MITRE export). Detector must say no."""
    data = {"threats": [{"id": "t1"}], "mitigations": []}
    assert is_threat_model_threats_shape(data) is False


def test_parse_threat_model_ingests_top_level_mitigations() -> None:
    """The top-level mitigations[] (2 entries in the fixture) must be
    ingested — none should be silently dropped."""
    data = _load_fixture()
    mits = parse_threat_model_mitigations(data)
    assert len(mits) == 2
    aliases = {m["alias"] for m in mits}
    assert aliases == {
        "Mitigation.LAMBDA.Function.1",
        "Mitigation.LAMBDA.CapacityProvider.1",
    }


def test_parse_threat_model_carries_alias_and_statement() -> None:
    """Each mitigation must carry the source `alias` and the FULL
    `statement` text — no truncation, no summary."""
    mits = parse_threat_model_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    fn = by_alias["Mitigation.LAMBDA.Function.1"]
    assert fn["statement"] == (
        "Functions should be encrypted with a customer-managed KMS key."
    )
    assert fn["alias"] == "Mitigation.LAMBDA.Function.1"


def test_parse_threat_model_flattens_configuration_request_parameters() -> None:
    """request_parameters[] is the flat list of every
    configurationRequestParameters[].paths[].path. The Function mitigation
    has 2 paths under one operation -> 2 flat paths."""
    mits = parse_threat_model_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    fn = by_alias["Mitigation.LAMBDA.Function.1"]
    assert fn["request_parameters"] == ["$.FunctionName", "$.KMSKeyArn"]
    # The original nested structure must also be retained
    assert fn["configuration_request_parameters"][0]["service"] == "lambda"
    assert fn["configuration_request_parameters"][0]["operation"] == "CreateFunction"


def test_parse_threat_model_recovers_resource_type_via_entity_mapping() -> None:
    """resource_type for each mitigation must be recovered by following
    mappings[type=="ENTITY"].id -> entities[].id -> entityType."""
    mits = parse_threat_model_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    assert (
        by_alias["Mitigation.LAMBDA.Function.1"]["resource_type"]
        == "AWS::Lambda::Function"
    )
    assert (
        by_alias["Mitigation.LAMBDA.CapacityProvider.1"]["resource_type"]
        == "AWS::Lambda::CapacityProvider"
    )


def test_parse_threat_model_returns_empty_on_non_threat_model_shape() -> None:
    """Calling parse_threat_model_mitigations on a non-AWS Threat Model doc yields []."""
    legacy = {
        "entities": [
            {"id": "e1", "mitigations": [{"id": "M-1", "statement": "x"}]}
        ]
    }
    assert parse_threat_model_mitigations(legacy) == []


def test_published_entity_identifiers_preserve_all_cfn_types():
    data = _load_fixture()
    entity = data['entities'][0]
    entity['entityType'] = 'RESOURCE'
    entity['identifiers'] = {'cfnResourceTypes': ['AWS::Example::First', 'AWS::Example::Second', 'AWS::Example::First']}
    mit = data['mitigations'][0]
    mit['mappings'] = [{'type': 'ENTITY', 'id': entity['id']}]
    normalized = parse_threat_model_mitigations(data)[0]
    assert normalized['resource_types'] == ['AWS::Example::First', 'AWS::Example::Second']
    assert normalized['resource_type'] == 'AWS::Example::First'


def test_semantic_entity_label_is_not_invented_as_cfn_type():
    data = _load_fixture()
    for entity in data['entities']:
        entity['entityType'] = 'RESOURCE'
        entity.pop('resource_type', None)
    assert all(m['resource_type'] == '' for m in parse_threat_model_mitigations(data))
