"""Regression tests for scripts/map-assemble.py behavioral changes.

Covers the threat-ID traceability feature and the merge asset-distinctness fix
shipped in PR #2. Lives under tools/validate/ (not scripts/) so the Makefile CI
target `pytest tools/validate/ tools/evidence/` actually runs it — scripts/ is
NOT on the CI test path.

The module has a dash in its filename, so it's loaded via spec_from_file_location
rather than a plain import.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_MA_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "map-assemble.py"
_spec = importlib.util.spec_from_file_location("map_assemble", _MA_PATH)
map_assemble = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(map_assemble)


# ---------------------------------------------------------------------------
# propagate_threat_ids: native threat IDs land on controls[] AND framework_mapping[]
# ---------------------------------------------------------------------------
def _mitigations():
    return [
        {"id": "M-0367", "statement": "tag", "source_threat_id": "T-0522"},
        {"id": "M-0412", "statement": "role", "source_threat_id": "T-0530"},
        {"id": "M-GAP-IAM-01", "statement": "gap"},  # no source_threat_id
    ]


def _controls():
    return [
        {"id": "CTRL-ORG-PRV-001", "category": "PRV", "mitigation_ids": ["M-0367"]},
        {"id": "CTRL-ACC-DET-001", "category": "DET", "mitigation_ids": ["M-0367", "M-0412"]},
        {"id": "CTRL-ACC-COR-001", "category": "COR", "mitigation_ids": ["M-GAP-IAM-01"]},
    ]


def _fw_mapped():
    return {
        "framework_mapping": [
            {"objective_id": "IAM-01", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ORG-PRV-001"}, {"control_id": "CTRL-ACC-DET-001"}]},
            {"objective_id": "LOG-99", "status": "MAPPED",
             "controls": [{"control_id": "CTRL-ACC-COR-001"}]},  # gap-only -> no threat
            {"objective_id": "PHY-01", "status": "N/A", "controls": []},
        ]
    }


def test_propagate_threat_ids_enriches_controls() -> None:
    controls = _controls()
    map_assemble.propagate_threat_ids(_mitigations(), controls, _fw_mapped())
    by_id = {c["id"]: c for c in controls}
    assert by_id["CTRL-ORG-PRV-001"]["source_threat_ids"] == ["T-0522"]
    # control linked to two mitigations gets the union, sorted
    assert by_id["CTRL-ACC-DET-001"]["source_threat_ids"] == ["T-0522", "T-0530"]
    # gap-only mitigation has no source threat -> empty
    assert by_id["CTRL-ACC-COR-001"]["source_threat_ids"] == []


def test_propagate_threat_ids_enriches_framework_objectives() -> None:
    controls = _controls()
    fw = _fw_mapped()
    map_assemble.propagate_threat_ids(_mitigations(), controls, fw)
    by_obj = {f["objective_id"]: f for f in fw["framework_mapping"]}
    # MAPPED objective: union across its controls' threat IDs
    assert by_obj["IAM-01"]["threat_ids"] == ["T-0522", "T-0530"]
    # MAPPED but gap-only: empty
    assert by_obj["LOG-99"]["threat_ids"] == []
    # N/A objective: not annotated at all
    assert "threat_ids" not in by_obj["PHY-01"]


# ---------------------------------------------------------------------------
# build_threat_mitigation_map: threat_id + attack_techniques on each entry
# ---------------------------------------------------------------------------
def test_threat_mitigation_map_carries_threat_id_and_techniques() -> None:
    mits = [
        {"id": "M-0367", "statement": "s", "resource_type": "R", "source_threat_id": "T-0522"},
        {"id": "M-GAP-IAM-01", "statement": "s", "resource_type": "R"},
    ]
    ctrls = [
        {"id": "CTRL-ORG-PRV-001", "category": "PRV", "mitigation_ids": ["M-0367"],
         "attack_techniques": ["T1078", "T1562"]},
        {"id": "CTRL-ACC-DET-001", "category": "DET", "mitigation_ids": ["M-0367"],
         "attack_techniques": ["T1078"]},
    ]
    tmm = {t["mitigation_id"]: t for t in map_assemble.build_threat_mitigation_map(mits, ctrls)}
    assert tmm["M-0367"]["threat_id"] == "T-0522"
    assert tmm["M-0367"]["attack_techniques"] == ["T1078", "T1562"]  # union, sorted
    assert tmm["M-0367"]["coverage"] == "FULL"  # PRV + DET
    # mitigation with no source threat / no controls
    assert tmm["M-GAP-IAM-01"]["threat_id"] is None
    assert tmm["M-GAP-IAM-01"]["attack_techniques"] == []


# ---------------------------------------------------------------------------
# Merge asset-distinctness: maximal-token + variant-guard keep distinct CFN types
# (regression for the greedy-substring merge that dropped Url / LayerVersionPermission)
# ---------------------------------------------------------------------------
def _enrich_and_dedupe(assets_by_cfn, op_names):
    """Replicates the research/SKILL.md merge enrichment + dedup as shipped."""
    VERBS = ("Create", "Update", "Delete", "Invoke", "Put", "Add", "Remove", "Publish")
    for op_name in op_names:
        if not op_name.startswith(VERBS):
            continue
        matched = [(cfn, cfn.split("::")[-1]) for cfn in assets_by_cfn
                   if (cfn.split("::")[-1]).lower() in op_name.lower()]
        for cfn, token in matched:
            if any(ot != token and token.lower() in ot.lower() for _, ot in matched):
                continue  # non-maximal
            assets_by_cfn[cfn].setdefault("entry_points", [])
            if op_name not in assets_by_cfn[cfn]["entry_points"]:
                assets_by_cfn[cfn]["entry_points"].append(op_name)

    GENERIC = {"TagResource", "UntagResource", "ListTagsForResource",
               "PutResourcePolicy", "DeleteResourcePolicy", "GetResourcePolicy"}

    def variants(a, b):
        x, y = a.split("::")[-1].lower(), b.split("::")[-1].lower()
        return x in y or y in x

    deduped: dict = {}
    for cfn, asset in assets_by_cfn.items():
        eps = frozenset(asset.get("entry_points", [])) - GENERIC
        merged = False
        for ex_cfn, ex_asset in deduped.items():
            ex_eps = frozenset(ex_asset.get("entry_points", [])) - GENERIC
            if (eps and ex_eps
                    and len(eps & ex_eps) > min(len(eps), len(ex_eps)) * 0.5
                    and variants(cfn, ex_cfn)):
                if len(eps) > len(ex_eps):
                    deduped[cfn] = asset
                    del deduped[ex_cfn]
                merged = True
                break
        if not merged:
            deduped[cfn] = asset
    return set(deduped)


def test_merge_keeps_distinct_cfn_types_sharing_op_substrings() -> None:
    # The historical failure: AddLayerVersionPermission over-attached to Permission +
    # LayerVersion; *FunctionUrlConfig ops gave Url 100% overlap with Function. Both
    # cases silently dropped a distinct CFN type.
    assets = {c: {} for c in [
        "AWS::Lambda::Function", "AWS::Lambda::Url", "AWS::Lambda::Permission",
        "AWS::Lambda::LayerVersionPermission", "AWS::Lambda::LayerVersion",
    ]}
    ops = [
        "CreateFunction", "CreateFunctionUrlConfig", "DeleteFunctionUrlConfig",
        "AddPermission", "RemovePermission",
        "AddLayerVersionPermission", "RemoveLayerVersionPermission",
        "PublishLayerVersion", "DeleteLayerVersion",
    ]
    survivors = _enrich_and_dedupe(assets, ops)
    assert survivors == set(assets), f"merge dropped distinct CFN types: {set(assets) - survivors}"


def test_variant_guard_permits_merge_when_entry_points_actually_overlap() -> None:
    # The variant guard must still ALLOW a merge between substring-variant tokens
    # (Runtime / AgentRuntime) when they do share >50% of entry_points. We seed the
    # overlap directly to isolate the dedup guard from the maximal-token enrichment
    # (which, on its own, routes a shared op only to the longer token — see
    # test_maximal_token_does_not_feed_variant_merge).
    assets = {
        "AWS::Svc::Runtime": {"entry_points": ["CreateAgentRuntime", "DeleteAgentRuntime"]},
        "AWS::Svc::AgentRuntime": {"entry_points": ["CreateAgentRuntime", "DeleteAgentRuntime"]},
    }
    survivors = _enrich_and_dedupe(assets, [])  # no enrichment; dedup only
    assert len(survivors) == 1


def test_variant_guard_blocks_merge_of_distinct_nouns_even_at_full_overlap() -> None:
    # Function / Url fully overlap (both seeded with the same op) but are distinct
    # nouns — the variant guard must keep them separate.
    assets = {
        "AWS::Lambda::Function": {"entry_points": ["CreateFunctionUrlConfig"]},
        "AWS::Lambda::Url": {"entry_points": ["CreateFunctionUrlConfig"]},
    }
    survivors = _enrich_and_dedupe(assets, [])
    assert survivors == {"AWS::Lambda::Function", "AWS::Lambda::Url"}
