"""Tests for validate_config_support.py — the Config-supportability gate."""
from __future__ import annotations

import json
from pathlib import Path

import validate_config_support as vcs


_SUPPORTED = {"AWS::Lambda::Function", "AWS::EFS::FileSystem", "AWS::DSQL::Cluster"}


def _write(p: Path, obj: dict) -> str:
    p.write_text(json.dumps(obj))
    return str(p)


def test_data_file_loads_and_has_dsql():
    """The shipped data file loads and includes the doc-confirmed DSQL cluster
    type (SDK enum lags the doc for just-launched services)."""
    types = vcs.load_supported_types()
    assert "AWS::Lambda::Function" in types
    assert "AWS::DSQL::Cluster" in types  # doc addition
    assert len(types) > 400


def test_is_config_supported():
    assert vcs.is_config_supported("AWS::Lambda::Function", _SUPPORTED)
    assert not vcs.is_config_supported("AWS::Lambda::CapacityProvider", _SUPPORTED)


def test_supported_rule_passes(tmp_path):
    art = {
        "_metadata": {"posture": "reactive-detective"},
        "rules": [
            {"rule_name": "lambda-encrypted", "resource_type": "AWS::Lambda::Function"}
        ],
    }
    results = vcs.check_artifact(_write(tmp_path / "config-rules.json", art), _SUPPORTED)
    assert len(results) == 1
    assert results[0]["status"] == "SUPPORTED"


def test_unsupported_rule_flagged(tmp_path):
    art = {
        "rules": [
            {"rule_name": "cp-check", "resource_type": "AWS::Lambda::CapacityProvider"}
        ]
    }
    results = vcs.check_artifact(_write(tmp_path / "config-rules.json", art), _SUPPORTED)
    assert results[0]["status"] == "UNSUPPORTED"


def test_rule_without_resource_type_not_gated(tmp_path):
    """A periodic rule with no resource_type has no CI type to gate — skipped."""
    art = {"rules": [{"rule_name": "periodic-check", "source_type": "AWS_MANAGED"}]}
    results = vcs.check_artifact(_write(tmp_path / "config-rules.json", art), _SUPPORTED)
    assert results == []


def test_non_config_rule_file_ignored(tmp_path):
    art = {"rules": [{"rule_name": "x", "resource_type": "AWS::Nope::Thing"}]}
    # eventbridge-rules.json is not a Config-rule artifact.
    results = vcs.check_artifact(_write(tmp_path / "eventbridge-rules.json", art), _SUPPORTED)
    assert results == []


def test_gap_stub_skipped(tmp_path):
    art = {"_metadata": {"status": "NOT_APPLICABLE"},
           "rules": [{"rule_name": "x", "resource_type": "AWS::Nope::Thing"}]}
    results = vcs.check_artifact(_write(tmp_path / "config-rules.json", art), _SUPPORTED)
    assert results == []


def test_check_service_no_rules_is_noop_pass(tmp_path):
    """A service with no Config rules yields no results (a clean pass)."""
    root = tmp_path / ".service-approval" / "svc"
    (root / "05-recommended-guidance" / "detective").mkdir(parents=True)
    assert vcs.check_service(root, _SUPPORTED) == []


def test_check_service_walks_config_files(tmp_path):
    root = tmp_path / ".service-approval" / "svc"
    det = root / "05-recommended-guidance" / "detective"
    det.mkdir(parents=True)
    _write(det / "config-rules.json", {"rules": [
        {"rule_name": "ok", "resource_type": "AWS::Lambda::Function"},
        {"rule_name": "bad", "resource_type": "AWS::Lambda::CapacityProvider"},
    ]})
    results = vcs.check_service(root, _SUPPORTED)
    statuses = {r["rule_name"]: r["status"] for r in results}
    assert statuses == {"ok": "SUPPORTED", "bad": "UNSUPPORTED"}


def test_dsql_cluster_is_supported_live_case(tmp_path):
    """The DSQL live case: AWS::DSQL::Cluster IS Config-supported per the doc, so a
    Config rule for it passes the gate."""
    types = vcs.load_supported_types()
    art = {"rules": [{"rule_name": "dsql-cluster-check", "resource_type": "AWS::DSQL::Cluster"}]}
    results = vcs.check_artifact(_write(tmp_path / "config-rules.json", art), types)
    assert results[0]["status"] == "SUPPORTED"
