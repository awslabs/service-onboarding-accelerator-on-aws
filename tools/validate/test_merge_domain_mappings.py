"""Tests for scripts/merge-domain-mappings.py — the deterministic per-domain merge.

Covers: 17 partials → a schema-valid merged file, canonical domain ordering,
by_domain coverage arithmetic, cross-domain spray (Rule 2/3) detection, rationale
(Rule 5) / Full-Coverage (Rule 6) gates, orphan (Rule 7) detection, completeness
(missing/duplicate/extra objective), and bare-list vs object partial shapes.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "merge-domain-mappings.py"
SCHEMA = json.loads((REPO / "schemas" / "map-framework-mapped.schema.json").read_text())


def _load_module():
    spec = importlib.util.spec_from_file_location("merge_domain_mappings", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mdm = _load_module()


def _entry(oid, domain, status="MAPPED", controls=None):
    e = {"objective_id": oid, "domain": domain, "title": oid,
         "status": status, "coverage": "N/A" if status == "N/A" else "Partially Covered",
         "reason": "r", "controls": controls or []}
    return e


def _ctrl(cid, level="Partial Coverage", rationale="because mechanism X gates action Y"):
    return {"control_id": cid, "coverage_level": level, "rationale": rationale}


def _parsed(objectives):
    return {"framework": {"name": "CSA CCMv4", "version": "4.0"},
            "framework_objectives": objectives}


# --- prefix + partial-shape helpers ------------------------------------------

def test_domain_prefix():
    assert mdm._domain_prefix("A&A-01") == "A&A"
    assert mdm._domain_prefix("BCR-04") == "BCR"
    assert mdm._domain_prefix("") == ""


def test_partial_entries_accepts_list_and_object():
    e = [_entry("IAM-01", "Identity & Access Management")]
    assert mdm._partial_entries(e) == e
    assert mdm._partial_entries({"framework_mapping": e}) == e


def test_partial_entries_rejects_garbage():
    with pytest.raises(ValueError):
        mdm._partial_entries("not a partial")


# --- collect + order ---------------------------------------------------------

def test_collect_buckets_by_objective_prefix(tmp_path):
    # Filename is sanitised (A_A) but bucketing keys off objective_id (A&A).
    (tmp_path / "A_A.json").write_text(json.dumps(
        {"framework_mapping": [_entry("A&A-01", "Audit & Assurance", status="N/A")]}
    ))
    by = mdm.collect_partials(tmp_path)
    assert "A&A" in by and len(by["A&A"]) == 1


def test_order_entries_canonical_order():
    by = {
        "LOG": [_entry("LOG-01", "Logging and Monitoring", status="N/A")],
        "A&A": [_entry("A&A-01", "Audit & Assurance", status="N/A")],
        "IAM": [_entry("IAM-01", "Identity & Access Management", status="N/A")],
    }
    ordered = mdm.order_entries(by, ["LOG", "A&A", "IAM"])
    prefixes = [mdm._domain_prefix(e["objective_id"]) for e in ordered]
    # Canonical order: A&A < IAM < LOG regardless of input/parsed order.
    assert prefixes == ["A&A", "IAM", "LOG"]


def test_order_entries_within_domain_sorted_by_id():
    by = {"IAM": [
        _entry("IAM-03", "Identity & Access Management", status="N/A"),
        _entry("IAM-01", "Identity & Access Management", status="N/A"),
        _entry("IAM-02", "Identity & Access Management", status="N/A"),
    ]}
    ordered = mdm.order_entries(by, ["IAM"])
    assert [e["objective_id"] for e in ordered] == ["IAM-01", "IAM-02", "IAM-03"]


# --- coverage summary arithmetic ---------------------------------------------

def test_by_domain_arithmetic():
    mappings = [
        _entry("IAM-01", "Identity & Access Management", controls=[_ctrl("CTRL-ACC-PRV-001")]),
        _entry("IAM-02", "Identity & Access Management", status="N/A"),
        _entry("BCR-08", "Business Continuity Management and Operational Resilience", status="N/A"),
    ]
    parsed_objs = [{"id": "IAM-01"}, {"id": "IAM-02"}, {"id": "BCR-08"}]
    summary = mdm.build_coverage_summary(mappings, parsed_objs)
    assert summary["total_objectives"] == 3
    assert summary["mapped"] == 1
    assert summary["not_applicable"] == 2
    assert summary["by_domain"]["IAM"] == {
        "total": 2, "mapped": 1, "not_applicable": 1, "uncertain": 0,
        "coverage_percentage": 50.0
    }
    assert summary["by_domain"]["BCR"]["coverage_percentage"] == 0.0


def test_uncertain_excluded_from_coverage():
    """UNCERTAIN counts separately: not mapped, not N/A, and out of coverage %."""
    mappings = [
        _entry("IAM-01", "Identity & Access Management", controls=[_ctrl("CTRL-ACC-PRV-001")]),
        _entry("IAM-02", "Identity & Access Management", status="UNCERTAIN"),
        _entry("IAM-03", "Identity & Access Management", status="N/A"),
    ]
    parsed_objs = [{"id": "IAM-01"}, {"id": "IAM-02"}, {"id": "IAM-03"}]
    summary = mdm.build_coverage_summary(mappings, parsed_objs)
    assert summary["mapped"] == 1
    assert summary["not_applicable"] == 1
    assert summary["uncertain"] == 1
    iam = summary["by_domain"]["IAM"]
    assert iam == {"total": 3, "mapped": 1, "not_applicable": 1, "uncertain": 1,
                   "coverage_percentage": round(1 / 3 * 100, 1)}


# --- quality gates -----------------------------------------------------------

def test_rule2_spray_three_in_a_row_fails():
    same = [_ctrl("CTRL-ACC-PRV-001")]
    mappings = [
        _entry("BCR-01", "B", controls=same),
        _entry("BCR-02", "B", controls=same),
        _entry("BCR-03", "B", controls=same),
    ]
    results, failures = mdm.run_quality_gates(mappings, None)
    assert results["rule_2_no_spray"] == "FAIL"
    assert any("Rule2" in f for f in failures)


def test_rule2_two_in_a_row_passes():
    same = [_ctrl("CTRL-ACC-PRV-001")]
    mappings = [_entry("BCR-01", "B", controls=same), _entry("BCR-02", "B", controls=same)]
    results, _ = mdm.run_quality_gates(mappings, None)
    assert results["rule_2_no_spray"] == "PASS"


def test_rule3_over_15_objectives_fails():
    mappings = [
        _entry(f"IAM-{i:02d}", "I", controls=[_ctrl("CTRL-ACC-PRV-001")])
        for i in range(1, 18)
    ]
    results, _ = mdm.run_quality_gates(mappings, None)
    assert results["rule_3_max_15_per_control"] == "FAIL"


def test_rule5_missing_rationale_fails():
    mappings = [_entry("IAM-01", "I", controls=[
        {"control_id": "CTRL-ACC-PRV-001", "coverage_level": "Partial Coverage"}
    ])]
    results, _ = mdm.run_quality_gates(mappings, None)
    assert results["rule_5_rationale_present"] == "FAIL"


def test_rule6_over_5_full_coverage_fails():
    ctrls = [_ctrl(f"CTRL-ACC-PRV-{i:03d}", level="Full Coverage") for i in range(1, 7)]
    mappings = [_entry("IAM-01", "I", controls=ctrls)]
    results, _ = mdm.run_quality_gates(mappings, None)
    assert results["rule_6_max_5_full_per_objective"] == "FAIL"


def test_rule7_orphan_detection():
    mappings = [_entry("IAM-01", "I", controls=[_ctrl("CTRL-ACC-PRV-001")])]
    all_ids = {"CTRL-ACC-PRV-001", "CTRL-ACC-DET-099"}
    results, _ = mdm.run_quality_gates(mappings, all_ids)
    assert results["rule_7_orphan_review"] == "FAIL"
    assert results["orphaned_controls"] == ["CTRL-ACC-DET-099"]


# --- completeness ------------------------------------------------------------

def test_completeness_missing_objective():
    mappings = [_entry("IAM-01", "I", status="N/A")]
    parsed = [{"id": "IAM-01"}, {"id": "IAM-02"}]
    errors = mdm.check_completeness(mappings, parsed)
    assert any("missing" in e for e in errors)


def test_completeness_duplicate_objective():
    mappings = [_entry("IAM-01", "I", status="N/A"), _entry("IAM-01", "I", status="N/A")]
    parsed = [{"id": "IAM-01"}]
    errors = mdm.check_completeness(mappings, parsed)
    assert any("duplicate" in e for e in errors)


def test_completeness_extra_objective():
    mappings = [_entry("IAM-01", "I", status="N/A"), _entry("ZZZ-99", "Z", status="N/A")]
    parsed = [{"id": "IAM-01"}]
    errors = mdm.check_completeness(mappings, parsed)
    assert any("unexpected" in e for e in errors)


def test_completeness_clean():
    mappings = [_entry("IAM-01", "I", status="N/A")]
    parsed = [{"id": "IAM-01"}]
    assert mdm.check_completeness(mappings, parsed) == []


# --- end-to-end: 17 partials -> schema-valid merged file ---------------------

def test_merge_17_partials_schema_valid(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    domains = {
        "A&A": "Audit & Assurance", "AIS": "Application & Interface Security",
        "BCR": "Business Continuity Management and Operational Resilience",
        "CCC": "Change Control and Configuration Management",
        "CEK": "Cryptography, Encryption & Key Management",
        "DCS": "Datacenter Security", "DSP": "Data Security and Privacy Lifecycle Management",
        "GRC": "Governance, Risk and Compliance", "HRS": "Human Resources",
        "IAM": "Identity & Access Management", "IPY": "Interoperability & Portability",
        "IVS": "Infrastructure & Virtualization Security", "LOG": "Logging and Monitoring",
        "SEF": "Security Incident Management", "STA": "Supply Chain Management",
        "TVM": "Threat & Vulnerability Management", "UEM": "Universal Endpoint Management",
    }
    domains_dir = tmp_path / "_domains"
    domains_dir.mkdir()
    parsed_objs = []
    for prefix, name in domains.items():
        entries = []
        for i in (1, 2):
            oid = f"{prefix}-{i:02d}"
            parsed_objs.append({"id": oid, "domain": name})
            # First objective MAPPED with a control, second N/A.
            if i == 1:
                entries.append(_entry(oid, name, controls=[_ctrl("CTRL-ACC-PRV-001")]))
            else:
                entries.append(_entry(oid, name, status="N/A"))
        safe = prefix.replace("&", "_")
        (domains_dir / f"{safe}.json").write_text(json.dumps({"framework_mapping": entries}))

    parsed_path = tmp_path / "parsed.json"
    parsed_path.write_text(json.dumps(_parsed(parsed_objs)))
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(json.dumps({"controls": [{"id": "CTRL-ACC-PRV-001"}]}))

    by = mdm.collect_partials(domains_dir)
    merged = mdm.merge(by, _parsed(parsed_objs),
                       json.loads(controls_path.read_text())["controls"])

    jsonschema.validate(merged, SCHEMA)
    assert len(merged["framework_mapping"]) == 34
    assert merged["framework_coverage_summary"]["total_objectives"] == 34
    assert merged["framework_coverage_summary"]["mapped"] == 17
    assert merged["framework_coverage_summary"]["not_applicable"] == 17
    assert len(merged["framework_coverage_summary"]["by_domain"]) == 17
    # Canonical ordering: first entry is A&A-01.
    assert merged["framework_mapping"][0]["objective_id"] == "A&A-01"
    # Completeness holds.
    assert mdm.check_completeness(merged["framework_mapping"], parsed_objs) == []
