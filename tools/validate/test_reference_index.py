"""Tests for the reference-repo anchor index.

Covers:
- The committed data/reference-repos/index.yaml is well-formed: every example
  carries a source URL, a recognized mechanism, and at least one governed action
  or condition key.
- The tools.reference_index loader returns the expected lookups.
- Share-alike-licensed repos are recorded facts-only (no vendored body).
- The build tool's harvest/slugify helpers behave on synthetic policies.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TOOLS = _REPO_ROOT / "tools"
sys.path.insert(0, str(_TOOLS))

import reference_index  # type: ignore  # noqa: E402


def _load_builder():
    """Import build_reference_index.py by path (it lives under tools/post-process)."""
    spec = importlib.util.spec_from_file_location(
        "build_reference_index",
        _TOOLS / "post-process" / "build_reference_index.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


INDEX_FILE = _REPO_ROOT / "data" / "reference-repos" / "index.yaml"

index_built = pytest.mark.skipif(
    not INDEX_FILE.exists(),
    reason="reference index not built (run build_reference_index.py)",
)


# ---------------------------------------------------------------------------
# Committed-index integrity
# ---------------------------------------------------------------------------
@index_built
def test_index_loads():
    idx = reference_index.load_index()
    assert idx.get("version") == 1
    assert idx.get("repos"), "index has no repos block"
    assert idx.get("examples"), "index has no examples"


@index_built
def test_every_example_has_source_mechanism_and_action_or_key():
    for e in reference_index.examples():
        assert e.get("id"), f"example missing id: {e}"
        assert e.get("source_url", "").startswith("https://"), (
            f"{e['id']}: source_url must be an https URL"
        )
        assert e.get("mechanism") in reference_index.ALLOWED_MECHANISMS, (
            f"{e['id']}: mechanism {e.get('mechanism')!r} not allowed"
        )
        has_anchor = bool(e.get("governed_actions")) or bool(e.get("condition_keys"))
        assert has_anchor, (
            f"{e['id']}: must carry at least one governed action or condition key"
        )


@index_built
def test_example_ids_are_unique():
    ids = [e["id"] for e in reference_index.examples()]
    assert len(ids) == len(set(ids)), "duplicate example ids in index"


@index_built
def test_repos_have_pinned_commit_and_license():
    for r in reference_index.load_index()["repos"]:
        assert r.get("commit") and r["commit"] != "unknown", (
            f"{r['slug']}: repo entry must carry a pinned commit"
        )
        assert r.get("license"), f"{r['slug']}: repo entry must record a license"
        assert r.get("url", "").startswith("https://github.com/")


@index_built
def test_vendored_bodies_resolve_and_facts_only_have_none():
    for e in reference_index.examples():
        repo = next(
            r for r in reference_index.load_index()["repos"] if r["slug"] == e["repo"]
        )
        if repo["vendor_bodies"]:
            sp = e.get("source_path")
            assert sp, f"{e['id']}: vendored repo entry must carry source_path"
            assert (_REPO_ROOT / sp).exists(), f"{e['id']}: source_path {sp} missing"
        else:
            # Share-alike license: facts-only, no vendored body.
            assert e.get("source_path") is None, (
                f"{e['id']}: share-alike repo entry must not vendor a body"
            )


@index_built
def test_loader_lookups():
    ids = reference_index.example_ids()
    assert ids
    some_id = next(iter(ids))
    assert reference_index.get_example(some_id) is not None
    assert reference_index.get_example("does-not-exist-xyz") is None
    scps = reference_index.examples_for_mechanism("SCP")
    assert all(e["mechanism"] == "SCP" for e in scps)


@index_built
def test_loader_raises_when_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        reference_index.load_index(tmp_path / "nope.yaml")


# ---------------------------------------------------------------------------
# Builder helpers (no clones needed)
# ---------------------------------------------------------------------------
def test_harvest_actions_and_keys():
    builder = _load_builder()
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["s3:DeleteBucket", "s3:PutBucketPolicy"],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {"aws:PrincipalOrgID": "o-123"},
                    "Bool": {"aws:SecureTransport": "false"},
                },
            }
        ],
    }
    actions, keys = builder.harvest_actions_and_keys(policy)
    assert actions == ["s3:DeleteBucket", "s3:PutBucketPolicy"]
    assert keys == ["aws:PrincipalOrgID", "aws:SecureTransport"]


def test_harvest_ignores_condition_values_as_actions():
    builder = _load_builder()
    # A bare Allow * Deny * with conditions only — no real actions but keys exist.
    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "*", "Resource": "*",
             "Condition": {"StringEquals": {"aws:SourceAccount": "123"}}}
        ]
    }
    actions, keys = builder.harvest_actions_and_keys(policy)
    assert actions == []  # "*" is not a prefixed action
    assert keys == ["aws:SourceAccount"]


def test_slugify():
    builder = _load_builder()
    assert builder.slugify("Deny-Leave Org!") == "deny-leave-org"
    assert builder.slugify("S3/Foo_Bar") == "s3-foo-bar"


def test_mechanism_for_directory_hint():
    builder = _load_builder()
    p = Path("resource_control_policies/identity_perimeter_rcp.json")
    assert builder.mechanism_for(p, "data-perimeter") == "RCP"
    p2 = Path("vpc_endpoint_policies/s3_endpoint_policy.json")
    assert builder.mechanism_for(p2, "data-perimeter") == "VPCE"
    p3 = Path("some/other/file.json")
    assert builder.mechanism_for(p3, "SCP") == "SCP"
