"""Lint/schema tests for the CCMv4 domain mapping-guidance KB.

Guards the structural invariants the dispatcher and both validators rely on:
all 17 CCMv4 domains present, every objective has intent + mappable, enums valid,
allow/deny reference real mechanism classes and are disjoint, default_na carries
an na_reason, and the four anchored mapping decisions (IVS-07, LOG-12, STA-12,
BCR-04) are encoded.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
KB_PATH = REPO / "data" / "domain-mapping-guidance" / "ccmv4.json"
SCHEMA_PATH = REPO / "schemas" / "domain-mapping-guidance.schema.json"

# Canonical CCMv4 domains (the 17 the parsed framework produces).
CCMV4_DOMAINS = {"A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS",
                 "IAM", "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM"}
VALID_MAPPABLE = {"mappable", "default_na", "conditional"}


@pytest.fixture(scope="module")
def kb():
    return json.loads(KB_PATH.read_text())


@pytest.fixture(scope="module")
def objectives(kb):
    return [o for d in kb["domains"] for o in d["objectives"]]


def test_kb_exists_and_parses(kb):
    assert kb["framework"] == "CCMv4"
    assert kb["mechanism_classes"]
    assert kb["domains"]


def test_validates_against_schema(kb):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.validate(kb, schema)


def test_all_17_domains_present(kb):
    ids = {d["domain_id"] for d in kb["domains"]}
    assert ids == CCMV4_DOMAINS


def test_every_objective_has_intent_and_mappable(objectives):
    for o in objectives:
        assert o.get("objective_id"), o
        assert o.get("intent", "").strip(), o["objective_id"]
        assert o.get("mappable") in VALID_MAPPABLE, o["objective_id"]


def test_mechanism_class_refs_resolve(kb, objectives):
    classes = set(kb["mechanism_classes"])
    for o in objectives:
        for c in o.get("allow_mechanisms", []) + o.get("deny_mechanisms", []):
            assert c in classes, f"{o['objective_id']}: unknown class {c}"


def test_allow_and_deny_disjoint(objectives):
    for o in objectives:
        overlap = set(o.get("allow_mechanisms", [])) & set(o.get("deny_mechanisms", []))
        assert not overlap, f"{o['objective_id']}: allow/deny overlap {overlap}"


def test_default_na_objectives_have_na_reason(objectives):
    for o in objectives:
        if o["mappable"] == "default_na":
            assert o.get("na_reason", "").strip(), o["objective_id"]


def test_mappable_objectives_have_allow_mechanisms(objectives):
    # A mappable/conditional objective must say which classes satisfy it.
    for o in objectives:
        if o["mappable"] in ("mappable", "conditional"):
            assert o.get("allow_mechanisms"), \
                f"{o['objective_id']} is {o['mappable']} but has no allow_mechanisms"


def test_mechanism_classes_have_descriptions(kb):
    for cid, spec in kb["mechanism_classes"].items():
        assert spec.get("description", "").strip(), cid


def test_objective_count_matches_ccmv4(objectives):
    # CCMv4 has 197 control objectives.
    assert len(objectives) == 197


# --- The four anchored mapping decisions -------------------------------------

def _by_id(objectives):
    return {o["objective_id"]: o for o in objectives}


def test_ivs07_anchor(objectives):
    o = _by_id(objectives)["IVS-07"]
    assert o["mappable"] == "default_na"
    assert "transit_encryption" in o["deny_mechanisms"]


def test_log12_anchor(objectives):
    o = _by_id(objectives)["LOG-12"]
    assert o["allow_mechanisms"] == ["access_event_logging"]
    assert "misconfig_detection" in o["deny_mechanisms"]


def test_sta12_anchor(objectives):
    o = _by_id(objectives)["STA-12"]
    assert o["mappable"] == "default_na"
    assert "access_control" in o["deny_mechanisms"]


def test_bcr04_anchor(objectives):
    o = _by_id(objectives)["BCR-04"]
    assert o["mappable"] == "mappable"
    assert "resilience" in o["allow_mechanisms"]


def test_bcr_backup_dr_stay_default_na(objectives):
    # The granular split: only BCR-04 is mappable; backup/DR objectives stay N/A.
    by_id = _by_id(objectives)
    for oid in ("BCR-01", "BCR-08", "BCR-09", "BCR-11"):
        assert by_id[oid]["mappable"] == "default_na", oid
