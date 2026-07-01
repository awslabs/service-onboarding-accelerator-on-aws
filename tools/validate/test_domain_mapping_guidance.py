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


# --- Coverage-ceiling policy (Full is opt-in) --------------------------------

VALID_COVERAGE = {"Full Coverage", "Partial Coverage", "Supportive"}


def test_default_ceiling_is_partial(kb):
    assert kb.get("default_coverage_ceiling") == "Partial Coverage"


def test_mechanism_class_ceilings_reference_real_classes(kb):
    classes = set(kb["mechanism_classes"])
    ceilings = kb.get("mechanism_class_ceilings", {})
    assert ceilings, "mechanism_class_ceilings must be present"
    for cls, level in ceilings.items():
        assert cls in classes, f"ceiling for unknown class {cls}"
        assert level in VALID_COVERAGE, f"{cls}: bad coverage {level}"


def test_per_objective_ceilings_reference_real_classes(kb, objectives):
    classes = set(kb["mechanism_classes"])
    for o in objectives:
        for cls, level in o.get("coverage_ceilings", {}).items():
            assert cls in classes, f"{o['objective_id']}: ceiling for unknown class {cls}"
            assert level in VALID_COVERAGE, f"{o['objective_id']}: bad coverage {level}"


def test_cek_encryption_objectives_capped_at_partial(objectives):
    """CEK-03/CEK-08 cannot be Full from CMK-existence/TLS-presence alone."""
    by_id = _by_id(objectives)
    for oid in ("CEK-03", "CEK-08"):
        ceil = by_id[oid].get("coverage_ceilings", {})
        assert ceil.get("at_rest_encryption") == "Partial Coverage", oid


# --- supply_chain class + code-signing home ----------------------------------

def test_supply_chain_class_exists(kb):
    assert "supply_chain" in kb["mechanism_classes"]


def test_dsp10_denies_supply_chain(objectives):
    """Code-signing (code integrity) must not satisfy data-in-transit protection."""
    o = _by_id(objectives)["DSP-10"]
    assert "supply_chain" in o["deny_mechanisms"]


def test_dsp01_denies_encryption(objectives):
    """A technical encryption control must never map to the data-security policy objective."""
    o = _by_id(objectives)["DSP-01"]
    assert o["mappable"] == "default_na"
    assert "at_rest_encryption" in o["deny_mechanisms"]
    assert "transit_encryption" in o["deny_mechanisms"]


def test_code_signing_has_a_home(objectives):
    """Code-signing routes to a change-integrity objective, not DSP-10."""
    o = _by_id(objectives)["CCC-04"]
    assert "supply_chain" in o["allow_mechanisms"]


# --- Log-protection trio: log creation != log protection ---------------------

def test_log_protection_denies_log_creation(objectives):
    by_id = _by_id(objectives)
    for oid in ("LOG-02", "LOG-09", "IAM-12"):
        o = by_id[oid]
        assert "access_event_logging" in o["deny_mechanisms"], oid
        assert "access_event_logging" not in o["allow_mechanisms"], oid


def test_log_protection_allows_encryption_at_rest_capped(objectives):
    """Encrypting the log store at rest is a legitimate log-protection facet, but
    only one facet — allow it capped at Partial so it cannot false-FAIL nor
    over-claim Full."""
    by_id = _by_id(objectives)
    for oid in ("LOG-02", "LOG-09", "IAM-12"):
        o = by_id[oid]
        assert "at_rest_encryption" in o["allow_mechanisms"], oid
        assert o.get("coverage_ceilings", {}).get("at_rest_encryption") == "Partial Coverage", oid


def test_monitoring_objectives_cap_log_recording_at_partial(objectives):
    """Recording events (access_event_logging) is not monitoring/alerting/response;
    LOG-03/05/13 cap it at Partial so a record-only control cannot claim Full."""
    by_id = _by_id(objectives)
    for oid in ("LOG-03", "LOG-05", "LOG-13"):
        o = by_id[oid]
        assert o.get("coverage_ceilings", {}).get("access_event_logging") == "Partial Coverage", oid


def test_cek10_key_generation_caps_at_rest_encryption(objectives):
    """Encrypting data with a CMK does not prove how the key was generated;
    CEK-10 caps the at_rest_encryption path at Partial."""
    o = _by_id(objectives)["CEK-10"]
    assert o.get("coverage_ceilings", {}).get("at_rest_encryption") == "Partial Coverage"


def test_log_protection_serverless_category_na(objectives):
    """A serverless-compute service owns no log store to protect."""
    by_id = _by_id(objectives)
    for oid in ("LOG-02", "LOG-09"):
        cat = by_id[oid].get("by_service_category", {})
        assert cat.get("serverless_compute", {}).get("mappable") == "default_na", oid


def test_by_service_category_shapes_valid(kb, objectives):
    classes = set(kb["mechanism_classes"])
    valid_mappable = {"mappable", "default_na", "conditional"}
    for o in objectives:
        for catname, ov in o.get("by_service_category", {}).items():
            if "mappable" in ov:
                assert ov["mappable"] in valid_mappable, (o["objective_id"], catname)
            for cls in ov.get("allow_mechanisms", []) + ov.get("deny_mechanisms", []):
                assert cls in classes, f"{o['objective_id']}/{catname}: unknown class {cls}"
