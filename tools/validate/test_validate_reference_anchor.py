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
