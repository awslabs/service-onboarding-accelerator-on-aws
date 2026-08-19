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


def test_doc_anchor_web_verified_passes(tmp_path):
    """No-MCP mode: a doc anchor stamped verified_via='web' is accepted."""
    web = dict(_GOOD_DOC, verified_via="web")
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": web}})
    assert vcc.check_artifact(f, known_ids=set()) == []


# No-MCP mode widens the WebFetch allowlist (aws.amazon.com blogs, boto3/awscli
# refs, AWS-owned GitHub repos) for *discovery and reading*, but artifact
# *citations* stay narrow: docs.aws.amazon.com (+ the Checkov policy-index host).
# A fact found on a blog or SDK reference must be re-confirmed on the
# authoritative doc page before it is cited. These cases lock that in — the
# fetch-only hosts are NOT accepted as citation URLs.
@pytest.mark.parametrize(
    "url",
    [
        "https://aws.amazon.com/blogs/security/some-post/",
        "https://aws.amazon.com/aurora-dsql/faqs/",
        "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dsql.html",
        "https://awscli.amazonaws.com/v2/documentation/api/latest/reference/dsql/index.html",
        "https://github.com/aws-samples/aws-config-custom-policy-rule-samples/blob/main/x.guard",
    ],
)
def test_fetch_only_hosts_not_citable(tmp_path, url):
    """Hosts fetchable-in-discovery but off the citation allowlist are rejected."""
    bad = dict(_GOOD_DOC, url=url)
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": bad}})
    errors = vcc.check_artifact(f, known_ids=set())
    assert any("not a" in e and "AWS documentation URL" in e for e in errors)


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


# --- AWS Threat Model citation anchor -------------------------------------------------

_THREAT_MODEL_ALIASES = {"Implementation.DSQL.Cluster.6", "Mitigation.DSQL.1"}


def test_threat_model_citation_resolvable_passes(tmp_path):
    """A threat_model citation whose alias resolves in the index passes."""
    citation = {"type": "threat_model", "id": "Implementation.DSQL.Cluster.6"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    assert vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES) == []


def test_threat_model_citation_with_verified_url_passes(tmp_path):
    """A threat_model citation carrying an MCP-verified AWS doc URL passes."""
    citation = {
        "type": "threat_model",
        "id": "Implementation.DSQL.Cluster.6",
        "url": "https://docs.aws.amazon.com/aurora-dsql/latest/APIReference/API_PutClusterPolicy.html",
        "verified_via": "mcp",
    }
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    assert vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES) == []


def test_threat_model_citation_web_verified_url_passes(tmp_path):
    """No-MCP mode: a threat_model citation URL stamped verified_via='web' passes."""
    citation = {
        "type": "threat_model",
        "id": "Implementation.DSQL.Cluster.6",
        "url": "https://docs.aws.amazon.com/aurora-dsql/latest/APIReference/API_PutClusterPolicy.html",
        "verified_via": "web",
    }
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    assert vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES) == []


def test_threat_model_citation_unresolvable_alias_fails(tmp_path):
    """An alias not in the ingested index is a hard fail."""
    citation = {"type": "threat_model", "id": "Implementation.NOPE.1"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    errors = vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES)
    assert any("does not resolve" in e for e in errors)


def test_threat_model_citation_no_index_fails(tmp_path):
    """A threat_model citation with no threat-model-index available cannot be resolved."""
    citation = {"type": "threat_model", "id": "Implementation.DSQL.Cluster.6"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    errors = vcc.check_artifact(f, known_ids=set(), threat_model_aliases=None)
    assert any("no threat-model-index.json" in e for e in errors)


def test_threat_model_citation_malformed_url_fails(tmp_path):
    """A threat_model citation URL that isn't a well-formed AWS doc URL fails."""
    citation = {
        "type": "threat_model",
        "id": "Implementation.DSQL.Cluster.6",
        "url": "https://example.com/made-up",
        "verified_via": "mcp",
    }
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    errors = vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES)
    assert any("not a" in e and "AWS documentation URL" in e for e in errors)


def test_threat_model_citation_url_not_mcp_verified_fails(tmp_path):
    """A threat_model citation with a URL but verified_via != mcp fails."""
    citation = {
        "type": "threat_model",
        "id": "Implementation.DSQL.Cluster.6",
        "url": "https://docs.aws.amazon.com/aurora-dsql/latest/APIReference/API_PutClusterPolicy.html",
    }
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    errors = vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES)
    assert any("verified_via is not 'mcp'" in e for e in errors)


def test_threat_model_citation_missing_id_fails(tmp_path):
    """A threat_model citation with no id fails."""
    citation = {"type": "threat_model"}
    f = _write(tmp_path / "config-rules.json", {"_metadata": {"citation": citation}})
    errors = vcc.check_artifact(f, known_ids=set(), threat_model_aliases=_THREAT_MODEL_ALIASES)
    assert any("carries no id" in e for e in errors)


def test_check_service_resolves_threat_model_from_index(tmp_path):
    """check_service loads threat-model-index.json and resolves threat_model citations."""
    root = tmp_path / ".service-approval" / "dsql"
    (root / "02-research").mkdir(parents=True)
    (root / "05-recommended-guidance" / "detective").mkdir(parents=True)
    index = {
        "_metadata": {"service": "dsql"},
        "mitigations": [{"id": "m1", "alias": "Mitigation.DSQL.1"}],
        "implementations": [
            {"id": "i1", "alias": "Implementation.DSQL.Cluster.6",
             "behavior": "DETECTIVE", "mechanism": "Config Rule"}
        ],
    }
    (root / "02-research" / "threat-model-index.json").write_text(json.dumps(index))
    _write(
        root / "05-recommended-guidance" / "detective" / "config-rules.json",
        {"_metadata": {"citation": {"type": "threat_model", "id": "Implementation.DSQL.Cluster.6"}}},
    )
    assert vcc.check_service(root) == []
    # A bogus alias fails.
    _write(
        root / "05-recommended-guidance" / "detective" / "other.json",
        {"_metadata": {"citation": {"type": "threat_model", "id": "Implementation.BOGUS"}}},
    )
    assert any("does not resolve" in e for e in vcc.check_service(root))


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
