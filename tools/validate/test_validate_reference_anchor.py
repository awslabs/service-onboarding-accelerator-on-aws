"""Tests for the reference-anchor enforcement validator (P8).

Covers:
- An anchored artifact (reference resolves to a real index id) passes.
- An un-anchored policy artifact hard-fails.
- A reference to a non-existent example id fails.
- Gap/skip stubs and documentation files are exempt.
- The integrity-hook wrapper picks up violations across a service tree.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_reference_anchor as vra  # noqa: E402


KNOWN = {"real-anchor-id", "another-id"}


def _write(p: Path, data: dict) -> str:
    p.write_text(json.dumps(data))
    return str(p)


def test_anchored_artifact_passes(tmp_path):
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {
                "posture": "preventative-request",
                "reference": {"example_id": "real-anchor-id", "repo": "r", "url": "u"},
            },
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_unanchored_policy_fails(tmp_path):
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {"posture": "preventative-request"},
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    errors = vra.check_artifact(path, KNOWN)
    assert len(errors) == 1 and "P8" in errors[0] and "no _metadata.reference" in errors[0]


def test_unresolvable_anchor_fails(tmp_path):
    path = _write(
        tmp_path / "rcp-policy.json",
        {
            "_metadata": {
                "reference": {"example_id": "ghost-id-not-in-index"},
            },
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    errors = vra.check_artifact(path, KNOWN)
    assert len(errors) == 1 and "does not resolve" in errors[0]


def test_no_metadata_fails(tmp_path):
    path = _write(
        tmp_path / "scp-policy.json",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*"}]},
    )
    errors = vra.check_artifact(path, KNOWN)
    assert len(errors) == 1 and "no _metadata" in errors[0]


def test_not_applicable_stub_exempt(tmp_path):
    path = _write(
        tmp_path / "resource-policy.json",
        {"_metadata": {"status": "NOT_APPLICABLE"}, "Statement": []},
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_gap_note_with_empty_body_exempt(tmp_path):
    path = _write(
        tmp_path / "rcp-policy.json",
        {"_metadata": {"rcp_gap": "service is not RCP-expressible"}, "Statement": []},
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_gap_note_with_policy_body_still_requires_anchor(tmp_path):
    """A *_gap note does NOT exempt a file that actually emits a policy."""
    path = _write(
        tmp_path / "rcp-policy.json",
        {
            "_metadata": {"rcp_gap": "note"},
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    errors = vra.check_artifact(path, KNOWN)
    assert len(errors) == 1


def test_documentation_file_exempt(tmp_path):
    path = _write(
        tmp_path / "compensating-controls-documentation.json",
        {"_metadata": {}, "controls": []},
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_rootcause_report_exempt(tmp_path):
    """The root-cause critic's report is a findings document, not a policy."""
    path = _write(
        tmp_path / "rootcause-report.json",
        {"_metadata": {"service": "lambda"}, "anchored": True, "enforcing": True},
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_non_json_skipped(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("not json")
    assert vra.check_artifact(str(p), KNOWN) == []


def test_check_service_scans_preventive_dir(tmp_path, monkeypatch):
    prev = tmp_path / "05-generate" / "preventive"
    prev.mkdir(parents=True)
    _write(
        prev / "good.json",
        {"_metadata": {"reference": {"example_id": "real-anchor-id"}},
         "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]},
    )
    _write(
        prev / "bad.json",
        {"_metadata": {}, "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]},
    )
    # Stub the index to our KNOWN set so the test is hermetic.
    monkeypatch.setattr(vra, "_known_ids", lambda: KNOWN)
    errors = vra.check_service(tmp_path)
    assert len(errors) == 1 and "bad.json" in errors[0]


def test_integrity_wrapper_surfaces_violations(tmp_path, monkeypatch):
    """validate_pipeline_integrity.check_reference_anchors delegates to vra."""
    import validate_pipeline_integrity as vpi

    prev = tmp_path / "05-generate" / "preventive"
    prev.mkdir(parents=True)
    _write(
        prev / "bad.json",
        {"_metadata": {}, "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]},
    )
    monkeypatch.setattr(vra, "_known_ids", lambda: KNOWN)
    errors = vpi.check_reference_anchors(tmp_path)
    assert len(errors) == 1 and "P8" in errors[0]


# ---------------------------------------------------------------------------
# ITEM E: not_anchored escape hatch + source_control_id orphan check.
# ---------------------------------------------------------------------------


def test_not_anchored_without_statement_fails(tmp_path):
    """A REFER/pointer artifact with no _metadata.reference, no Statement
    body, and no explicit not_anchored declaration must hard-fail — silent
    un-anchored artifacts are forbidden."""
    path = _write(
        tmp_path / "scp-policy.json",
        {"_metadata": {"posture": "preventative-request"}, "Statement": []},
    )
    errors = vra.check_artifact(path, KNOWN)
    assert len(errors) == 1
    assert "P8" in errors[0] and "not_anchored" in errors[0]


def test_not_anchored_with_statement_passes(tmp_path):
    """A REFER/pointer artifact that explicitly declares not_anchored with
    a reason and ships no Statement body passes the gate."""
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {
                "posture": "preventative-request",
                "not_anchored": True,
                "not_anchored_reason": "no reference example overlaps "
                                      "this control's actions/keys; pointing at "
                                      "the closest reference family instead",
            },
            "Statement": [],
        },
    )
    assert vra.check_artifact(path, KNOWN) == []


def test_not_anchored_with_authored_policy_fails(tmp_path):
    """The not_anchored escape hatch is only valid for REFER/pointer files;
    an authored policy with not_anchored: true must hard-fail."""
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {
                "not_anchored": True,
                "not_anchored_reason": "claiming we couldn't anchor",
            },
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    errors = vra.check_artifact(path, KNOWN)
    assert any("ships enforcing policy" in e for e in errors), errors


def test_not_anchored_without_reason_fails(tmp_path):
    """not_anchored: true without not_anchored_reason fails — the reason is
    required so reviewers can audit the gap."""
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {"not_anchored": True},
            "Statement": [],
        },
    )
    errors = vra.check_artifact(path, KNOWN)
    assert any("not_anchored_reason" in e for e in errors), errors


def test_orphan_source_control_id_fails(tmp_path):
    """An artifact whose source_control_id is not in mapping-results.json is
    an orphan — fail."""
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {
                "reference": {"example_id": "real-anchor-id"},
                "source_control_id": "CTRL-ORG-PRV-999",
            },
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    mapping_ids = {"CTRL-ORG-PRV-001"}  # 999 not present
    errors = vra.check_artifact(path, KNOWN, mapping_ids)
    assert any("orphan" in e for e in errors), errors


def test_source_control_id_present_in_mapping_passes(tmp_path):
    """An artifact whose source_control_id IS in mapping-results.json passes."""
    path = _write(
        tmp_path / "scp-policy.json",
        {
            "_metadata": {
                "reference": {"example_id": "real-anchor-id"},
                "source_control_id": "CTRL-ORG-PRV-001",
            },
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    mapping_ids = {"CTRL-ORG-PRV-001"}
    assert vra.check_artifact(path, KNOWN, mapping_ids) == []


def test_check_service_loads_mapping_for_orphan_check(tmp_path):
    """check_service reads mapping-results.json to build the orphan-check set."""
    map_dir = tmp_path / "04-map"
    map_dir.mkdir(parents=True)
    (map_dir / "mapping-results.json").write_text(
        json.dumps({"controls": [{"id": "CTRL-ORG-PRV-001", "category": "PRV"}]})
    )
    prev = tmp_path / "05-generate" / "preventive"
    prev.mkdir(parents=True)
    _write(
        prev / "orphan.json",
        {
            "_metadata": {
                "reference": {"example_id": "real-anchor-id"},
                "source_control_id": "CTRL-ORG-PRV-999",
            },
            "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
        },
    )
    # Stub the index so the anchor resolves; orphan check is what we want to fire.
    import unittest.mock as mock

    with mock.patch.object(vra, "_known_ids", lambda: {"real-anchor-id"}):
        errors = vra.check_service(tmp_path)
    assert any("orphan" in e and "CTRL-ORG-PRV-999" in e for e in errors), errors
