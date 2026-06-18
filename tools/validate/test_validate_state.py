"""Unit tests for validate_state.py helpers.

Currently covers:
- `_load_botocore_iam_aliases` — CHECK-S9 alias-table loader (iter-14 Class E).
- CHECK-S9 cross-reference: SAR action names in `condition_keys[].applies_to_actions`
  that match a botocore operation via the alias table must NOT produce a
  CRITICAL error.

Add new tests here when extending state-level validation.
"""
from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch

from validate_state import (
    _load_botocore_iam_aliases,
    check_research_merged,
)


# ------------------------------------------------------------------
# _load_botocore_iam_aliases
# ------------------------------------------------------------------


def test_load_aliases_returns_empty_for_unknown_service() -> None:
    fwd, rev = _load_botocore_iam_aliases("this-service-has-no-aliases")
    assert fwd == {}
    assert rev == {}


def test_load_aliases_athena_has_cancel_alias() -> None:
    """The shipped alias file registers Athena's StopQueryExecution↔CancelQueryExecution."""
    fwd, rev = _load_botocore_iam_aliases("athena")
    assert fwd.get("StopQueryExecution") == "CancelQueryExecution"
    assert rev.get("CancelQueryExecution") == "StopQueryExecution"


def test_load_aliases_case_insensitive_service() -> None:
    fwd, _ = _load_botocore_iam_aliases("Athena")
    assert fwd.get("StopQueryExecution") == "CancelQueryExecution"


def test_load_aliases_missing_file_returns_empty(tmp_path, monkeypatch) -> None:
    """If the alias file doesn't exist, fall back silently — validator uses
    strict comparison. Not a safety error."""
    import validate_state as vs
    monkeypatch.setattr(vs, "_BOTOCORE_IAM_ALIAS_PATH", str(tmp_path / "does-not-exist.json"))
    fwd, rev = vs._load_botocore_iam_aliases("athena")
    assert fwd == {}
    assert rev == {}


def test_load_aliases_malformed_json_returns_empty(tmp_path, monkeypatch) -> None:
    import validate_state as vs
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    monkeypatch.setattr(vs, "_BOTOCORE_IAM_ALIAS_PATH", str(bad))
    fwd, rev = vs._load_botocore_iam_aliases("athena")
    assert fwd == {}
    assert rev == {}


# ------------------------------------------------------------------
# CHECK-S9 cross-reference with alias table (Class E end-to-end)
# ------------------------------------------------------------------


def _minimal_research(service: str, ops: list[dict], ck: list[dict]) -> dict:
    """Build a minimal research.json structure satisfying everything CHECK-S9
    looks at except the cross-reference we're exercising."""
    return {
        "phase": "research",
        "schema_version": "3.0",
        "service": service,
        "doc_sources": [{"url": "https://example.invalid"}],
        "resources": [{"type": "AWS::Example::Thing"}],
        "assets": [
            {
                "name": "thing",
                "cfn_type": "AWS::Example::Thing",
                "data_classification": "Customer data",
                "entry_points": ["api"],
            }
        ],
        "capabilities": {
            "iam": {
                "condition_keys": ck,
                "permission_only_actions": [],
            },
            "encryption": {},
            "network": {},
            "logging": {"cloudtrail": {"data_events": {"supported": False}}},
            "organization_policies": {},
        },
        "api_surface": {"operations": ops},
        "existing_mitigations": [],
    }


def test_check_s9_flags_unknown_action_without_alias() -> None:
    """Baseline: a condition-key action not in operations and not aliased
    still raises CRITICAL."""
    data = _minimal_research(
        service="some-service",
        ops=[{"operation": "DoThing", "parameters": []}],
        ck=[{"key": "svc:thing", "applies_to_actions": ["NonExistentAction"]}],
    )
    errors = check_research_merged(data)
    critical = [e for e in errors if "CHECK-S9 CRITICAL" in e]
    assert len(critical) == 1
    assert "NonExistentAction" in critical[0]


def test_check_s9_accepts_sar_name_when_botocore_alias_exists() -> None:
    """The real Athena case: condition_keys.applies_to_actions uses
    CancelQueryExecution (SAR), api_surface has StopQueryExecution (botocore).
    With the alias table, this must NOT produce CRITICAL."""
    data = _minimal_research(
        service="athena",
        ops=[
            {"operation": "StopQueryExecution", "parameters": []},
            {"operation": "StartQueryExecution", "parameters": []},
        ],
        ck=[
            {
                "key": "athena:WorkgroupAdmin",
                "applies_to_actions": ["CancelQueryExecution", "StartQueryExecution"],
            }
        ],
    )
    errors = check_research_merged(data)
    critical = [e for e in errors if "CHECK-S9 CRITICAL" in e]
    assert critical == [], (
        f"Alias table should have bridged CancelQueryExecution→StopQueryExecution, "
        f"but CHECK-S9 still fired: {critical}"
    )


def test_check_s9_alias_scoped_to_service() -> None:
    """Athena's alias must NOT apply to other services — if lambda's
    condition_keys reference CancelQueryExecution, that's a real error."""
    data = _minimal_research(
        service="lambda",
        ops=[{"operation": "StopQueryExecution", "parameters": []}],
        ck=[
            {"key": "lambda:Something", "applies_to_actions": ["CancelQueryExecution"]}
        ],
    )
    errors = check_research_merged(data)
    critical = [e for e in errors if "CHECK-S9 CRITICAL" in e]
    assert len(critical) == 1
    assert "CancelQueryExecution" in critical[0]


def test_check_s9_alias_also_works_reverse_direction() -> None:
    """If a service's permission_only_actions contains the SAR name and
    condition_keys references the botocore name, the alias must bridge
    reverse."""
    data = _minimal_research(
        service="athena",
        ops=[],
        ck=[{"key": "athena:X", "applies_to_actions": ["StopQueryExecution"]}],
    )
    data["capabilities"]["iam"]["permission_only_actions"] = ["CancelQueryExecution"]
    errors = check_research_merged(data)
    critical = [e for e in errors if "CHECK-S9 CRITICAL" in e]
    assert critical == []


def test_check_s9_accepts_wildcard_star_as_applies_to_actions() -> None:
    """SAR uses the literal '*' string as shorthand for 'applies to every
    action' (e.g., DynamoDB's aws:ResourceTag/${TagKey}). CHECK-S9 must
    pass '*' through as a universal match, not flag it as missing from
    operations/permission_only_actions. Regression for iter-18/10 signal
    F-G2 surfaced during DynamoDB Phase 1 regression."""
    data = _minimal_research(
        service="dynamodb",
        ops=[{"operation": "GetItem", "parameters": []}],
        ck=[{"key": "aws:ResourceTag/${TagKey}", "applies_to_actions": ["*"]}],
    )
    errors = check_research_merged(data)
    critical = [e for e in errors if "CHECK-S9 CRITICAL" in e]
    assert critical == [], (
        "CHECK-S9 must treat '*' as a wildcard pass-through, not flag it as "
        f"a missing action. Got: {critical}"
    )


# ------------------------------------------------------------------
# CHECK-S11 — Control-ID format enum (iter-14 Class C)
# ------------------------------------------------------------------


from validate_state import check_controls_generated  # noqa: E402
from _schemas import schema_errors  # noqa: E402


def _minimal_control(cid: str, scope: str = "ORG", category: str = "PRV") -> dict:
    """Build a control dict that passes every schema constraint EXCEPT the
    ID-format pattern. Used to isolate ID-format behaviour per-test."""
    return {
        "id": cid,
        "name": "test",
        "scope": scope,
        "category": category,
        "mechanism": "SCP",
        "description": "test",
        "actions": ["test:Action"],
        "mitigation_ids": ["M-Example.0"],
        "security_rationale": "Illustrative rationale.",
        "framework_keywords": ["encryption", "access-control"],
        "parameters_controlled": ["$.name"],
        "condition_keys": [],
        "resource_types": [],
    }


def _ctrl_gen_doc(controls: list[dict]) -> dict:
    return {
        "schema_version": "1.0",
        "service": "test",
        "controls": controls,
        "control_summary": {"total_controls": len(controls)},
    }


def _id_format_errors(doc: dict) -> list[str]:
    """Return only schema errors that fire on the controls[*].id pattern."""
    return [
        e for e in schema_errors(doc, "map-controls-generated")
        if "controls." in e and ".id:" in e and "does not match" in e
    ]


def test_schema_id_pattern_accepts_canonical_format() -> None:
    """Schema pattern on controls[].id accepts canonical CTRL-<SCOPE>-<CAT>-NNN."""
    for cid in ["CTRL-ORG-PRV-001", "CTRL-ACC-DET-012", "CTRL-RES-PRO-099", "CTRL-ORG-COR-123"]:
        doc = _ctrl_gen_doc([_minimal_control(cid, scope=cid.split("-")[1], category=cid.split("-")[2])])
        assert _id_format_errors(doc) == [], f"expected accept: {cid}"


def test_schema_id_pattern_rejects_service_prefixed_ids() -> None:
    """Service-prefixed IDs (iter-14 LLM drift) fail the schema pattern."""
    for cid in ["S3-RES-PRO-01", "ATH-ORG-PRV-01", "LAMBDA-ACC-DET-03", "AGC-ORG-PRV-01"]:
        # Use scope/category consistent with the id suffix so we test the
        # pattern in isolation, not the mismatch rule.
        doc = _ctrl_gen_doc([_minimal_control(cid, scope="RES", category="PRO")])
        assert len(_id_format_errors(doc)) == 1, f"expected reject: {cid}"


def test_schema_id_pattern_rejects_malformed() -> None:
    """Other malformed shapes fail the schema pattern."""
    for cid in [
        "CTRL-org-prv-001",         # lowercase scope/category
        "CTRL-ORG-PRV-01",          # two-digit sequence
        "CTRL-ORG-PRV-0001",        # four-digit sequence
        "CTRL-XYZ-PRV-001",         # unknown scope
        "CTRL-ORG-XYZ-001",         # unknown category
        "ctrl-ORG-PRV-001",         # lowercase prefix
        "CTRL_ORG_PRV_001",         # underscore separator
        "CTRL-ORG-PRV-001-extra",   # trailing content
    ]:
        doc = _ctrl_gen_doc([_minimal_control(cid)])
        assert _id_format_errors(doc), f"expected reject: {cid}"


def test_check_s11_rejects_service_prefixed_id(tmp_path) -> None:
    """check_controls_generated surfaces the schema pattern violation.
    We assert on the structured path `controls.0.id` so the test is
    decoupled from any specific error-message string format."""
    doc = _ctrl_gen_doc([_minimal_control("S3-RES-PRO-01", scope="RES", category="PRO")])
    errors = check_controls_generated(doc, str(tmp_path))
    # Look for a schema error on controls.0.id.
    path_errors = [e for e in errors if "controls.0.id" in e]
    assert len(path_errors) >= 1, f"no controls.0.id error emitted; errors={errors}"


def test_check_s11_accepts_canonical_id(tmp_path) -> None:
    doc = _ctrl_gen_doc([_minimal_control("CTRL-ORG-PRV-001")])
    errors = check_controls_generated(doc, str(tmp_path))
    id_errors = [e for e in errors if "controls.0.id" in e]
    assert id_errors == []


def test_check_s11_still_catches_scope_category_mismatch(tmp_path) -> None:
    """After accepting canonical format, the per-control scope/category
    mismatch check (ID says one thing, fields say another) still fires."""
    doc = _ctrl_gen_doc([_minimal_control("CTRL-ORG-PRV-001", scope="ACC", category="PRV")])
    errors = check_controls_generated(doc, str(tmp_path))
    mismatch = [e for e in errors if "scope/category mismatch" in e]
    assert len(mismatch) == 1


# ------------------------------------------------------------------
# map-framework-mapped coverage_level enum.
# Accepts both new values (Full Coverage, Partial Coverage, Supportive)
# and legacy values (High, Medium, Low) for backward compatibility.
# ------------------------------------------------------------------


def _minimal_mapped_doc(coverage_level: str, field_name: str = "coverage_level") -> dict:
    """Build a minimal map-framework-mapped.json that passes every schema
    constraint except (potentially) the coverage_level enum."""
    ctrl = {
        "control_id": "CTRL-ORG-PRV-001",
        field_name: coverage_level,
        "rationale": "test rationale",
    }
    return {
        "schema_version": "1.0",
        "service": "test",
        "framework_mapping": [
            {
                "objective_id": "TEST-01",
                "domain": "TEST",
                "title": "Test objective",
                "status": "MAPPED",
                "coverage": "Fully Covered",
                "reason": "test",
                "controls": [ctrl],
            }
        ],
    }


def test_coverage_level_accepts_new_values() -> None:
    """The new enum must accept all three user-friendly values."""
    for value in ["Full Coverage", "Partial Coverage", "Supportive"]:
        doc = _minimal_mapped_doc(value, "coverage_level")
        errs = [e for e in schema_errors(doc, "map-framework-mapped") if "coverage_level" in e]
        assert errs == [], f"New value {value!r} must validate; got: {errs}"


def test_confidence_field_no_longer_in_schema() -> None:
    """The deprecated `confidence` enum was removed from the schema. The schema
    intentionally does not define a `confidence` property anywhere on a control
    entry — coverage_level is the only ranked field."""
    import json
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / "map-framework-mapped.schema.json"
    )
    with open(schema_path) as f:
        schema = json.load(f)
    ctrl_props = (
        schema["$defs"]["mapping"]["properties"]["controls"]["items"]["properties"]
    )
    assert "confidence" not in ctrl_props, (
        "confidence property must be absent from map-framework-mapped.schema.json "
        "(LLM confidence scoring was removed)"
    )
    assert "coverage_level" in ctrl_props, "coverage_level remains the canonical field"


def _walk_schema_property_names(node):
    """Yield every JSON-Schema `properties` key name reachable from `node`.

    Walks `properties`, `$defs`/`definitions`, `items`, and the composition
    keywords (`allOf`/`anyOf`/`oneOf`) so a `confidence` property nested at any
    depth — under a control item, a mapping row, or a sub-definition — is found.
    """
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            for name in props:
                yield name
        for key, child in node.items():
            yield from _walk_schema_property_names(child)
    elif isinstance(node, list):
        for child in node:
            yield from _walk_schema_property_names(child)


def test_no_pipeline_schema_defines_confidence_property() -> None:
    """LLM confidence scoring is permanently locked out. No pipeline schema
    under schemas/ may define a `confidence` (or `run_confidence`) property at
    any nesting depth — coverage_level is the only ranked field the pipeline
    emits, and it is a deterministic catalog cross-check, not an LLM score."""
    import json
    from pathlib import Path

    schemas_dir = Path(__file__).resolve().parents[2] / "schemas"
    offenders: list[str] = []
    for schema_path in sorted(schemas_dir.glob("*.json")):
        with open(schema_path) as f:
            schema = json.load(f)
        names = set(_walk_schema_property_names(schema))
        for banned in ("confidence", "run_confidence"):
            if banned in names:
                offenders.append(f"{schema_path.name}:{banned}")
    assert not offenders, (
        "confidence scoring was permanently removed; these schemas re-introduced "
        f"a confidence property: {offenders}"
    )


def test_mapping_results_schema_has_no_confidence() -> None:
    """`mapping-results.schema.json` specifically must define neither
    `confidence` nor `run_confidence` (the deprecated CANOPY-PARITY §4.10
    feature put both there — it is descoped)."""
    import json
    from pathlib import Path

    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / "mapping-results.schema.json"
    )
    with open(schema_path) as f:
        schema = json.load(f)
    names = set(_walk_schema_property_names(schema))
    assert "confidence" not in names, (
        "mapping-results.schema.json must not define a `confidence` property"
    )
    assert "run_confidence" not in names, (
        "mapping-results.schema.json must not define a `run_confidence` property"
    )
