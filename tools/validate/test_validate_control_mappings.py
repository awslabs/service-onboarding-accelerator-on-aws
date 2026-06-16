"""Tests for the Control Catalog mapping cross-check.

Covers:
- A known-good objective (bridges to a NIST control present in the catalog) ->
  CATALOG_SUPPORTED.
- An objective that bridges to NIST but whose NIST controls are absent from the
  catalog -> LOW_CONFIDENCE (the "mapping doesn't make sense" signal).
- An objective with no CCM->NIST bridge -> NO_BRIDGE (reported, not failed).
- Snapshot absent -> SKIPPED (no authoritative source; not penalized).
- The CCM->NIST bridge builder and NIST family normalization.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_control_mappings import (  # noqa: E402
    assess_mappings,
    build_ccm_to_nist,
    _nist_family,
)


CROSSWALK = {
    "mappings": [
        {
            "ccmv4_objectives": ["IAM-01", "IAM-02"],
            "nist_controls": ["AC-2", "AC-3", "IA-2"],
        },
        {
            "ccmv4_objectives": ["LOG-03"],
            "nist_controls": ["AU-6", "AU-12"],
        },
    ]
}


def _mapping(objectives):
    return {"framework_mapping": objectives}


def test_build_ccm_to_nist():
    idx = build_ccm_to_nist(CROSSWALK)
    assert idx["IAM-01"] == {"AC-2", "AC-3", "IA-2"}
    assert idx["LOG-03"] == {"AU-6", "AU-12"}


def test_nist_family_strips_enhancement():
    assert _nist_family("AC-2(1)") == "AC-2"
    assert _nist_family("AC-2") == "AC-2"


def test_catalog_supported():
    snapshot = {"framework_items": {"NIST-800-53": ["AC-2", "SC-7"]}}
    mapping = _mapping([
        {"objective_id": "IAM-01", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-1"}]},
    ])
    results = assess_mappings(mapping, CROSSWALK, snapshot)
    assert len(results) == 1
    assert results[0]["verdict"] == "CATALOG_SUPPORTED"


def test_low_confidence_when_nist_absent_from_catalog():
    # IAM-01 bridges to AC-2/AC-3/IA-2; catalog only has unrelated SC-7.
    snapshot = {"framework_items": {"NIST-800-53": ["SC-7", "SC-28"]}}
    mapping = _mapping([
        {"objective_id": "IAM-01", "status": "MAPPED",
         "controls": [{"control_id": "CTRL-1"}]},
    ])
    results = assess_mappings(mapping, CROSSWALK, snapshot)
    assert results[0]["verdict"] == "LOW_CONFIDENCE"


def test_no_bridge_for_unknown_objective():
    snapshot = {"framework_items": {"NIST-800-53": ["AC-2"]}}
    mapping = _mapping([
        {"objective_id": "GRC-99", "status": "MAPPED", "controls": []},
    ])
    results = assess_mappings(mapping, CROSSWALK, snapshot)
    assert results[0]["verdict"] == "NO_BRIDGE"


def test_snapshot_absent_skips():
    mapping = _mapping([
        {"objective_id": "IAM-01", "status": "MAPPED", "controls": []},
    ])
    results = assess_mappings(mapping, CROSSWALK, None)
    assert results[0]["verdict"] == "SKIPPED"


def test_only_mapped_objectives_assessed():
    snapshot = {"framework_items": {"NIST-800-53": ["AC-2"]}}
    mapping = _mapping([
        {"objective_id": "IAM-01", "status": "MAPPED", "controls": []},
        {"objective_id": "A&A-01", "status": "N/A", "controls": []},
    ])
    results = assess_mappings(mapping, CROSSWALK, snapshot)
    assert [r["objective_id"] for r in results] == ["IAM-01"]


def test_catalog_supported_ignores_non_nist_frameworks():
    # Only an ISO framework block present; IAM-01 bridges to NIST -> not supported.
    snapshot = {"framework_items": {"ISO-IEC-27001:2013-Annex-A": ["A.9.2.1"]}}
    mapping = _mapping([
        {"objective_id": "IAM-01", "status": "MAPPED", "controls": []},
    ])
    results = assess_mappings(mapping, CROSSWALK, snapshot)
    assert results[0]["verdict"] == "LOW_CONFIDENCE"
