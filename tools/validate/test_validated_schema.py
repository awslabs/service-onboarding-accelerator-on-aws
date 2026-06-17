"""Tests for schemas/validated.schema.json.

The validate skill writes top-level fields that downstream skills
(map-generate-controls, map-assemble, generate-*) read directly.
The schema is `additionalProperties: false`, so any field the SKILL
mandates but the schema omits would silently bounce through the
validator and break downstream consumers.

These tests pin the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from _schemas import schema_errors

SCHEMA_NAME = "validated"
SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "validated.schema.json"
)


def _minimal_validated_doc(**overrides) -> dict:
    """Build a minimal validated.json that satisfies the required-keys
    constraint plus any overrides the test wants to set."""
    doc = {
        "schema_version": "3.0",
        "service": "test-service",
        "assets": [{"name": "asset-1"}],
        "capabilities": {},
        "api_surface": {},
        "existing_mitigations": [],
    }
    doc.update(overrides)
    return doc


def test_minimal_doc_validates() -> None:
    """The minimal required-keys doc must pass the schema."""
    doc = _minimal_validated_doc()
    assert schema_errors(doc, SCHEMA_NAME) == []


def test_top_level_scp_expressible_is_allowed() -> None:
    """The validate SKILL mandates `scp_expressible` at the root. The
    schema must accept it."""
    doc = _minimal_validated_doc(scp_expressible=True)
    assert schema_errors(doc, SCHEMA_NAME) == []
    doc2 = _minimal_validated_doc(scp_expressible=False)
    assert schema_errors(doc2, SCHEMA_NAME) == []


def test_top_level_rcp_expressible_is_allowed() -> None:
    doc = _minimal_validated_doc(rcp_expressible=False)
    assert schema_errors(doc, SCHEMA_NAME) == []


def test_top_level_attack_surface_is_allowed() -> None:
    """research-attack-surface populates an `attack_surface` block that
    flows through validate. The schema must accept it at the root."""
    doc = _minimal_validated_doc(
        attack_surface={
            "applicable_techniques": [],
            "stride_to_attack_bridge": [],
            "tactic_coverage_summary": {},
            "customer_stride_profile": {},
        }
    )
    assert schema_errors(doc, SCHEMA_NAME) == []


def test_top_level_unverified_count_and_items_are_allowed() -> None:
    doc = _minimal_validated_doc(unverified_count=0, unverified_items=[])
    assert schema_errors(doc, SCHEMA_NAME) == []


def test_top_level_enrichment_opportunities_allowed() -> None:
    doc = _minimal_validated_doc(enrichment_opportunities=[])
    assert schema_errors(doc, SCHEMA_NAME) == []


def test_unknown_root_key_still_rejected() -> None:
    """The schema is additionalProperties:false — an unknown key must
    still fail. (Sanity-pin so a future loosening of the schema doesn't
    silently weaken the contract.)"""
    doc = _minimal_validated_doc(some_typo_field="x")
    errs = schema_errors(doc, SCHEMA_NAME)
    assert errs, "additionalProperties:false must reject unknown keys"


def test_skill_mandated_root_fields_are_in_schema() -> None:
    """Direct schema-shape pin: read the schema JSON and assert the
    top-level fields the validate SKILL writes are explicitly listed.
    Catches accidental regressions where someone removes a property
    block but tests still pass because the example doc happened not to
    set it."""
    with open(SCHEMA_PATH) as f:
        schema = json.load(f)
    props = schema.get("properties", {})
    required_in_validate_skill = {
        "scp_expressible",
        "rcp_expressible",
        "attack_surface",
        "unverified_count",
        "unverified_items",
        "enrichment_opportunities",
    }
    missing = required_in_validate_skill - props.keys()
    assert not missing, (
        f"validated.schema.json missing top-level properties the validate "
        f"SKILL mandates: {sorted(missing)}"
    )
