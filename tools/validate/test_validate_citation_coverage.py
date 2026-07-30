"""Tests for validate_citation_coverage.py — the detective/proactive/responsive
citation gate."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import validate_citation_coverage as vcc


def _write(p: Path, obj: dict) -> str:
    p.write_text(json.dumps(obj))
    return str(p)


# A doc anchor that satisfies the shape rules.
_GOOD_DOC = {
    "type": "aws_doc",
    "title": "AWS Config Managed Rules — efs-encrypted-check",
    "url": "https://docs.aws.amazon.com/config/latest/developerguide/efs-encrypted-check.html",
    "verified_via": "mcp",
}


def test_missing_metadata_fails(tmp_path):
    f = _write(tmp_path / "config-rules.json", {"rules": []})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("no _metadata block" in e for e in errors)


def test_neither_reference_nor_citation_fails(tmp_path):
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"posture": "reactive-detective"}})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("neither a _metadata.reference" in e for e in errors)


def test_valid_doc_anchor_passes(tmp_path):
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": _GOOD_DOC}})
    assert vcc.check_artifact(f, known_ids=set()) == []


def test_checkov_policy_index_url_passes(tmp_path):
    """Checkov/OPA doc anchor to the checkov.io policy-index URL is accepted."""
    citation = {
        "type": "aws_doc",
        "title": "Checkov CloudFormation Policy Index — CKV_AWS_18",
        "url": "https://www.checkov.io/5.Policy%20Index/cloudformation.html",
        "verified_via": "mcp",
    }
    f = _write(tmp_path / "checkov-config.json", {"_metadata": {"citation": citation}})
    assert vcc.check_artifact(f, known_ids=set()) == []


def test_doc_anchor_bad_url_fails(tmp_path):
    bad = dict(_GOOD_DOC, url="https://example.com/made-up")
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": bad}})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("not a" in e and "AWS documentation URL" in e for e in errors)


def test_doc_anchor_not_mcp_verified_fails(tmp_path):
    bad = dict(_GOOD_DOC, verified_via="memory")
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": bad}})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("verified_via must be 'mcp'" in e for e in errors)


def test_repo_anchor_resolves(tmp_path):
    ref = {"example_id": "efs-encryption-check", "repo": "aws-config-custom-policy-rule-samples",
           "url": "https://github.com/aws-samples/aws-config-custom-policy-rule-samples/blob/sha/efs_encryption_check.guard"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"reference": ref}})
    assert vcc.check_artifact(f, known_ids={"efs-encryption-check"}) == []


def test_repo_anchor_unresolved_fails(tmp_path):
    ref = {"example_id": "not-a-real-id", "repo": "x", "url": "https://github.com/x"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"reference": ref}})
    errors = vcc.check_artifact(f, known_ids={"efs-encryption-check"})
    assert any("does not resolve" in e for e in errors)


def test_cfn_hooks_two_part_both_must_resolve(tmp_path):
    """CFN Hooks carries repo anchor + doc anchor; both must resolve."""
    ref = {"example_id": "efs-encryption-check", "repo": "aws-config-custom-policy-rule-samples",
           "url": "https://github.com/aws-samples/x/blob/sha/y.guard"}
    obj = {"_metadata": {"reference": ref, "citation": _GOOD_DOC}}
    f = _write(tmp_path / "cfn-hooks-policy.json", obj)
    assert vcc.check_artifact(f, known_ids={"efs-encryption-check"}) == []
    # Break the doc half — the whole artifact must now fail.
    obj["_metadata"]["citation"] = dict(_GOOD_DOC, verified_via="guess")
    f2 = _write(tmp_path / "cfn-hooks-policy2.json", obj)
    assert vcc.check_artifact(f2, known_ids={"efs-encryption-check"}) != []


def test_gap_stub_exempt(tmp_path):
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"status": "NOT_APPLICABLE"}})
    assert vcc.check_artifact(f, known_ids=set()) == []


def test_doc_only_basename_exempt(tmp_path):
    f = _write(tmp_path / "compensating-controls-documentation.json", {"foo": "bar"})
    assert vcc.check_artifact(f, known_ids=set()) == []


def test_non_json_ignored(tmp_path):
    p = tmp_path / "cfn-guard-rules.guard"
    p.write_text("rule x { ... }")
    assert vcc.check_artifact(str(p), known_ids=set()) == []


def test_proactive_manifest_entries_validated(tmp_path):
    ref = {"example_id": "efs-encryption-check", "repo": "aws-config-custom-policy-rule-samples",
           "url": "https://github.com/aws-samples/x/blob/sha/y.guard"}
    manifest = {
        "_metadata": {"service": "lambda"},
        "artifacts": [
            {"artifact": "cfn-guard-rules.guard", "reference": ref},
            {"artifact": "checkov-config.yaml", "citation": _GOOD_DOC},
        ],
    }
    f = _write(tmp_path / "citations.json", manifest)
    assert vcc.check_artifact(f, known_ids={"efs-encryption-check"}) == []


def test_proactive_manifest_unresolved_entry_fails(tmp_path):
    manifest = {"artifacts": [{"artifact": "cfn-guard-rules.guard",
                               "reference": {"example_id": "nope", "repo": "x", "url": "https://x"}}]}
    f = _write(tmp_path / "citations.json", manifest)
    errors = vcc.check_artifact(f, known_ids={"efs-encryption-check"})
    assert any("cfn-guard-rules.guard" in e and "does not resolve" in e for e in errors)


def test_proactive_manifest_empty_fails(tmp_path):
    f = _write(tmp_path / "citations.json", {"artifacts": []})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("has no" in e and "artifacts[]" in e for e in errors)


def test_check_service_walks_all_families(tmp_path):
    root = tmp_path / ".service-approval" / "svc"
    guidance = root / "05-recommended-guidance"
    for fam in ("detective", "proactive", "responsive"):
        (guidance / fam).mkdir(parents=True)
    # A good detective + an uncited proactive.
    _write(guidance / "detective" / "config-rules.json", {"_metadata": {"citation": _GOOD_DOC}})
    _write(guidance / "proactive" / "cfn-guard-rules.json", {"_metadata": {"posture": "preventative-proactive"}})
    errors = vcc.check_service(root)
    assert any("cfn-guard-rules.json" in e for e in errors)
    assert not any("config-rules.json" in e for e in errors)
