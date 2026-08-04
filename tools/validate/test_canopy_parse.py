"""Tests for the Canopy threat-model JSON shape detector and parser.

Canopy exports use a top-level `mitigations[]` and `threats[]` array. The
earlier research-mitigations parser only walked `entities[].mitigations[]`,
so Canopy mitigations were silently dropped. These tests fix-pin the
detector and the per-mitigation field carry-through.
"""

from __future__ import annotations

import json
from pathlib import Path

from canopy_parse import (
    is_canopy_shape,
    is_canopy_threats_shape,
    parse_canopy_mitigations,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture() -> dict:
    with open(FIXTURES / "canopy_minimal.json") as f:
        return json.load(f)


def test_canopy_shape_detector_matches_top_level_mitigations() -> None:
    """The Canopy fixture has top-level mitigations[] and entity entries
    without a mitigations sub-key — the detector must say yes."""
    data = _load_fixture()
    assert is_canopy_shape(data) is True


def test_canopy_shape_detector_rejects_entity_nested() -> None:
    """An entity-nested doc (legacy shape) must NOT be classified as Canopy
    even when a top-level mitigations[] is also present — the legacy parser
    already handles that path."""
    data = {
        "entities": [
            {"id": "e1", "mitigations": [{"id": "M-1", "statement": "x"}]}
        ],
        "mitigations": [{"id": "top-1"}],
    }
    assert is_canopy_shape(data) is False


def test_canopy_shape_detector_rejects_empty() -> None:
    """No mitigations, no entities -> not Canopy."""
    assert is_canopy_shape({}) is False
    assert is_canopy_shape({"mitigations": [], "entities": []}) is False


def test_canopy_threats_detector_matches_attack_surface_use() -> None:
    """research-attack-surface SKILL.md uses an independent detector that
    only requires both arrays to be non-empty."""
    data = _load_fixture()
    assert is_canopy_threats_shape(data) is True


def test_canopy_threats_detector_rejects_threats_only() -> None:
    """Without a top-level mitigations[], the file is not a Canopy export
    in the sense that research-attack-surface needs (it could be a plain
    MITRE export). Detector must say no."""
    data = {"threats": [{"id": "t1"}], "mitigations": []}
    assert is_canopy_threats_shape(data) is False


def test_parse_canopy_ingests_top_level_mitigations() -> None:
    """The top-level mitigations[] (2 entries in the fixture) must be
    ingested — none should be silently dropped."""
    data = _load_fixture()
    mits = parse_canopy_mitigations(data)
    assert len(mits) == 2
    aliases = {m["alias"] for m in mits}
    assert aliases == {
        "Mitigation.LAMBDA.Function.1",
        "Mitigation.LAMBDA.CapacityProvider.1",
    }


def test_parse_canopy_carries_alias_and_statement() -> None:
    """Each mitigation must carry the source `alias` and the FULL
    `statement` text — no truncation, no summary."""
    mits = parse_canopy_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    fn = by_alias["Mitigation.LAMBDA.Function.1"]
    assert fn["statement"] == (
        "Functions should be encrypted with a customer-managed KMS key."
    )
    assert fn["alias"] == "Mitigation.LAMBDA.Function.1"


def test_parse_canopy_flattens_configuration_request_parameters() -> None:
    """request_parameters[] is the flat list of every
    configurationRequestParameters[].paths[].path. The Function mitigation
    has 2 paths under one operation -> 2 flat paths."""
    mits = parse_canopy_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    fn = by_alias["Mitigation.LAMBDA.Function.1"]
    assert fn["request_parameters"] == ["$.FunctionName", "$.KMSKeyArn"]
    # The original nested structure must also be retained
    assert fn["configuration_request_parameters"][0]["service"] == "lambda"
    assert fn["configuration_request_parameters"][0]["operation"] == "CreateFunction"


def test_parse_canopy_recovers_resource_type_via_entity_mapping() -> None:
    """resource_type for each mitigation must be recovered by following
    mappings[type=="ENTITY"].id -> entities[].id -> entityType."""
    mits = parse_canopy_mitigations(_load_fixture())
    by_alias = {m["alias"]: m for m in mits}
    assert (
        by_alias["Mitigation.LAMBDA.Function.1"]["resource_type"]
        == "AWS::Lambda::Function"
    )
    assert (
        by_alias["Mitigation.LAMBDA.CapacityProvider.1"]["resource_type"]
        == "AWS::Lambda::CapacityProvider"
    )


def test_parse_canopy_returns_empty_on_non_canopy_shape() -> None:
    """Calling parse_canopy_mitigations on a non-Canopy doc yields []."""
    legacy = {
        "entities": [
            {"id": "e1", "mitigations": [{"id": "M-1", "statement": "x"}]}
        ]
    }
    assert parse_canopy_mitigations(legacy) == []
