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


# ------------------------------------------------------------------
# CHECK-S11 — Control-ID format enum (iter-14 Class C)
# ------------------------------------------------------------------


from validate_state import check_controls_generated, _CONTROL_ID_RE  # noqa: E402


def _minimal_control(cid: str, scope: str = "ORG", category: str = "PRV") -> dict:
    """Build a control dict that passes every CHECK-S11 rule EXCEPT the
    ID-format check. Use this to isolate ID-format behaviour per-test."""
    return {
        "id": cid,
        "scope": scope,
        "category": category,
        "mechanism": "SCP",
        "mitigation_ids": ["M-Example.0"],
        "security_rationale": "Illustrative rationale.",
        "framework_keywords": ["encryption", "access-control"],
    }


def _ctrl_gen_doc(controls: list[dict]) -> dict:
    return {
        "schema_version": "1.0",
        "controls": controls,
        "control_summary": {"total_controls": len(controls)},
    }


def test_control_id_regex_accepts_canonical_format() -> None:
    for cid in ["CTRL-ORG-PRV-001", "CTRL-ACC-DET-012", "CTRL-RES-PRO-099", "CTRL-ORG-COR-123"]:
        assert _CONTROL_ID_RE.match(cid), f"expected match: {cid}"


def test_control_id_regex_rejects_service_prefixed_ids() -> None:
    """Service-prefixed IDs (iter-14 LLM drift) must fail the regex."""
    for cid in ["S3-RES-PRO-01", "ATH-ORG-PRV-01", "LAMBDA-ACC-DET-03", "AGC-ORG-PRV-01"]:
        assert not _CONTROL_ID_RE.match(cid), f"expected reject: {cid}"


def test_control_id_regex_rejects_malformed() -> None:
    """Other malformed shapes must also fail."""
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
        assert not _CONTROL_ID_RE.match(cid), f"expected reject: {cid}"


def test_check_s11_flags_service_prefixed_id(tmp_path) -> None:
    """CHECK-S11 must reject a service-prefixed control ID with a message
    that names the regex and points to _metadata.service."""
    doc = _ctrl_gen_doc([_minimal_control("S3-RES-PRO-01", scope="RES", category="PRO")])
    errors = check_controls_generated(doc, str(tmp_path))
    id_errors = [e for e in errors if "invalid format" in e]
    assert len(id_errors) == 1
    assert "S3-RES-PRO-01" in id_errors[0]
    assert "^CTRL-" in id_errors[0]  # regex cited for the reader
    assert "_metadata.service" in id_errors[0]  # rationale cited


def test_check_s11_accepts_canonical_id(tmp_path) -> None:
    doc = _ctrl_gen_doc([_minimal_control("CTRL-ORG-PRV-001")])
    errors = check_controls_generated(doc, str(tmp_path))
    id_errors = [e for e in errors if "invalid format" in e]
    assert id_errors == []


def test_check_s11_still_catches_scope_category_mismatch(tmp_path) -> None:
    """After accepting canonical format, the per-control scope/category
    mismatch check (ID says one thing, fields say another) still fires."""
    doc = _ctrl_gen_doc([_minimal_control("CTRL-ORG-PRV-001", scope="ACC", category="PRV")])
    errors = check_controls_generated(doc, str(tmp_path))
    mismatch = [e for e in errors if "scope/category mismatch" in e]
    assert len(mismatch) == 1
