"""Tests for the Canopy threat-model JSON shape detector and parser.

Canopy exports use a top-level `mitigations[]` and `threats[]` array. The
earlier research-mitigations parser only walked `entities[].mitigations[]`,
so Canopy mitigations were silently dropped. These tests fix-pin the
detector and the per-mitigation field carry-through.
"""

from __future__ import annotations

import json
from pathlib import Path

from _schemas import schema_errors
from canopy_parse import (
    build_canopy_index,
    canopy_index_aliases,
    is_canopy_shape,
    is_canopy_threats_shape,
    parse_canopy_implementations,
    parse_canopy_mitigation_index,
    parse_canopy_mitigations,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture() -> dict:
    with open(FIXTURES / "canopy_minimal.json") as f:
        return json.load(f)


def _load_dsql_fixture() -> dict:
    with open(FIXTURES / "canopy_dsql_minimal.json") as f:
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


# ---------------------------------------------------------------------------
# parse_canopy_implementations — the newer DSQL-shaped implementations[] array
# ---------------------------------------------------------------------------


def test_parse_implementations_ingests_all_entries() -> None:
    """Every top-level implementations[] entry is normalized (7 in fixture)."""
    impls = parse_canopy_implementations(_load_dsql_fixture())
    assert len(impls) == 7
    aliases = {i["alias"] for i in impls}
    assert "Implementation.DSQL.1" in aliases
    assert "Implementation.DSQL.Cluster.6" in aliases


def test_parse_implementations_maps_mechanism_vocab() -> None:
    """implementationType maps to the pipeline mechanism vocabulary, including
    the wildcard RESOURCE_POLICY form."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    assert by_alias["Implementation.DSQL.1"]["mechanism"] == "Resource Policy"
    assert by_alias["Implementation.DSQL.2"]["mechanism"] == "SCP"
    assert by_alias["Implementation.DSQL.Stream.3"]["mechanism"] == "RCP"
    assert by_alias["Implementation.DSQL.Cluster.7"]["mechanism"] == "Declarative Policy"
    assert by_alias["Implementation.DSQL.Cluster.2"]["mechanism"] == "CFN Hook"
    assert by_alias["Implementation.DSQL.Cluster.3"]["mechanism"] == "CloudTrail"
    assert by_alias["Implementation.DSQL.Cluster.6"]["mechanism"] == "Config Rule"


def test_parse_implementations_flattens_authorization_policy() -> None:
    """A PREVENTIVE authorization_policy exposes flat actions/resources/keys."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    impl = by_alias["Implementation.DSQL.1"]
    assert impl["behavior"] == "PREVENTIVE"
    assert impl["actions"] == ["dsql:*"]
    assert impl["resources"] == ["*"]
    assert impl["condition_keys"] == ["aws:PrincipalIsAWSService", "aws:ResourceOrgID"]
    assert impl["governed_resource_type"] == "AWS::EC2::VPCEndpoint"


def test_parse_implementations_extracts_reference_links() -> None:
    """REFERENCE (and DATA_PERIMETER) context links are surfaced as public
    doc URLs."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    links = by_alias["Implementation.DSQL.1"]["reference_links"]
    assert len(links) == 1
    assert links[0]["href"].startswith(
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_data-perimeters.html"
    )
    assert links[0]["title"] == "Establishing a resource perimeter"
    # DATA_PERIMETER context also carries links (detective CloudTrail impl).
    ct_links = by_alias["Implementation.DSQL.Cluster.3"]["reference_links"]
    assert any("API_PutClusterPolicy" in link["href"] for link in ct_links)


def test_parse_implementations_config_rule_operations() -> None:
    """A DETECTIVE Config rule exposes its governed_api_operations."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    impl = by_alias["Implementation.DSQL.Cluster.6"]
    assert impl["behavior"] == "DETECTIVE"
    assert impl["config_rule_type"] == "PERIODIC"
    ops = impl["governed_api_operations"]
    assert ops[0]["service"] == "dsql"
    assert ops[0]["operation"] == "ListClusters"


def test_parse_implementations_cloudtrail_and_hook_and_declarative() -> None:
    """CloudTrail monitored_operations, CFN hook governed_resource_properties,
    and declarative governed_attributes/policy_type are each parsed."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    ct = by_alias["Implementation.DSQL.Cluster.3"]
    assert {op["operation"] for op in ct["monitored_operations"]} == {
        "CreateCluster",
        "PutClusterPolicy",
    }
    hook = by_alias["Implementation.DSQL.Cluster.2"]
    assert hook["behavior"] == "PROACTIVE"
    assert hook["governed_resource_properties"][0]["resource_type"] == "AWS::DSQL::Cluster"
    decl = by_alias["Implementation.DSQL.Cluster.7"]
    assert decl["policy_type"] == "BACKUP_POLICY"
    assert decl["governed_attributes"][0]["path"].startswith("$.plans")


def test_parse_implementations_carries_mitigation_and_entity_mappings() -> None:
    """mappings[] split into mitigation_ids[] and entity_ids[]."""
    by_alias = {i["alias"]: i for i in parse_canopy_implementations(_load_dsql_fixture())}
    impl = by_alias["Implementation.DSQL.1"]
    assert impl["mitigation_ids"] == ["6df5a224-53bf-5499-8fd8-ceb0e14e4928"]
    hook = by_alias["Implementation.DSQL.Cluster.2"]
    assert "0fb25b34-6aaa-58a3-b621-4e468552d6de" in hook["entity_ids"]


def test_parse_implementations_empty_on_missing_array() -> None:
    """A doc with no implementations[] (older Canopy, non-Canopy) yields []."""
    assert parse_canopy_implementations(_load_fixture()) == []
    assert parse_canopy_implementations({}) == []


# ---------------------------------------------------------------------------
# parse_canopy_mitigation_index — pull a mitigation's cited doc link
# ---------------------------------------------------------------------------


def test_mitigation_index_keys_by_id() -> None:
    """The index is keyed by mitigation id (UUID) so an implementation's
    mitigation_ids[] resolve directly."""
    idx = parse_canopy_mitigation_index(_load_dsql_fixture())
    assert "6df5a224-53bf-5499-8fd8-ceb0e14e4928" in idx
    entry = idx["6df5a224-53bf-5499-8fd8-ceb0e14e4928"]
    assert entry["alias"] == "Mitigation.DSQL.1"
    assert entry["statement"].startswith("Aurora DSQL service API calls")


def test_mitigation_index_carries_reference_links() -> None:
    """A mitigation's REFERENCE context links are indexed so a control mapped to
    it can cite the mitigation's public doc URL."""
    idx = parse_canopy_mitigation_index(_load_dsql_fixture())
    links = idx["6df5a224-53bf-5499-8fd8-ceb0e14e4928"]["reference_links"]
    assert any("data-perimeters" in link["href"] for link in links)


def test_mitigation_index_empty_on_non_canopy() -> None:
    """A non-Canopy doc yields an empty index."""
    legacy = {"entities": [{"id": "e1", "mitigations": [{"id": "M-1"}]}]}
    assert parse_canopy_mitigation_index(legacy) == {}


# ---------------------------------------------------------------------------
# build_canopy_index — the persisted canopy-index.json payload
# ---------------------------------------------------------------------------


def test_build_canopy_index_conforms_to_schema() -> None:
    """The assembled index validates against schemas/canopy-index.schema.json."""
    index = build_canopy_index(_load_dsql_fixture(), service="dsql")
    assert schema_errors(index, "canopy-index") == []
    assert index["_metadata"]["service"] == "dsql"
    assert len(index["implementations"]) == 7
    assert len(index["mitigations"]) == 1


def test_canopy_index_aliases_union() -> None:
    """canopy_index_aliases returns the union of mitigation + implementation
    aliases — the set a canopy citation resolves against."""
    index = build_canopy_index(_load_dsql_fixture(), service="dsql")
    aliases = canopy_index_aliases(index)
    assert "Mitigation.DSQL.1" in aliases
    assert "Implementation.DSQL.1" in aliases
    assert "Implementation.DSQL.Cluster.6" in aliases
    assert "not-a-real-alias" not in aliases
