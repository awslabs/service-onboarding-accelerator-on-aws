"""Tests for scripts/anchor-custom-framework.py — deterministic semantic anchoring
of a custom / non-CCMv4 framework's objectives to CCMv4.

A custom objective is anchored to its nearest CCMv4 objective(s) by DESCRIPTION
(TF-IDF cosine over title+intent text), so a non-CCMv4 framework can reuse the
CCMv4 per-domain guidance. An objective that anchors weakly (below threshold) is
marked 'uncertain' rather than force-fit — the mapper then maps it UNCERTAIN.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "anchor-custom-framework.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("anchor_custom_framework", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


acf = _load_module()


def test_encryption_objective_anchors_to_cek():
    """A custom 'cryptography of data at rest' objective should anchor to a CEK
    (Cryptography/Encryption/Key) CCMv4 objective by description."""
    custom = [{
        "id": "CRI-CRYPTO-1",
        "title": "Cryptographic Protection of Data at Rest",
        "specification": "Sensitive data stored by the service must be encrypted at "
                         "rest using strong customer-managed cryptographic keys.",
        "domain": "Cryptography",
    }]
    anchors = acf.anchor_objectives(custom, threshold=0.3)
    a = anchors["CRI-CRYPTO-1"]
    assert a["ccmv4_ids"], "should anchor somewhere"
    assert any(cid.startswith("CEK") or cid.startswith("DSP") for cid in a["ccmv4_ids"]), \
        f"expected a cryptography/data anchor, got {a['ccmv4_ids']}"


def test_network_objective_anchors_to_ivs():
    custom = [{
        "id": "CRI-NET-1",
        "title": "Network Segmentation and Isolation",
        "specification": "Workloads must be placed in isolated network segments with "
                         "security groups and private subnets restricting traffic.",
        "domain": "Network Security",
    }]
    anchors = acf.anchor_objectives(custom, threshold=0.3)
    assert any(cid.startswith("IVS") for cid in anchors["CRI-NET-1"]["ccmv4_ids"]), \
        anchors["CRI-NET-1"]["ccmv4_ids"]


def test_unanchorable_objective_is_uncertain():
    """An objective with no CCMv4 counterpart (pure gibberish/off-domain) scores
    below threshold and is marked uncertain, not force-fit."""
    custom = [{
        "id": "CRI-XYZ-1",
        "title": "Zorptastic Flibbergibbet Wibblewobble",
        "specification": "Quuxical borogove mimsy raths outgrabe frumious bandersnatch.",
        "domain": "Nonsense",
    }]
    anchors = acf.anchor_objectives(custom, threshold=_default_threshold())
    assert anchors["CRI-XYZ-1"]["status"] == "uncertain"


def test_deterministic_repeatable():
    custom = [{
        "id": "CRI-LOG-1",
        "title": "Audit Logging",
        "specification": "The service must record access and activity events to an "
                         "audit log for accountability.",
        "domain": "Logging",
    }]
    a1 = acf.anchor_objectives(custom)
    a2 = acf.anchor_objectives(custom)
    assert a1 == a2, "anchoring must be deterministic"


def test_threshold_governs_status():
    custom = [{
        "id": "CRI-IAM-1",
        "title": "Least Privilege Access",
        "specification": "Grant identities the least privilege necessary; segregate "
                         "privileged roles and enforce authorization.",
        "domain": "Access",
    }]
    low = acf.anchor_objectives(custom, threshold=0.01)["CRI-IAM-1"]
    high = acf.anchor_objectives(custom, threshold=0.999)["CRI-IAM-1"]
    assert low["status"] == "anchored"
    assert high["status"] == "uncertain"
    # Same underlying match either way — only the status label changes.
    assert low["ccmv4_ids"] == high["ccmv4_ids"]
    assert low["anchor_score"] == high["anchor_score"]


def test_build_result_summary_counts():
    parsed = {
        "framework": {"name": "CRI Profile"},
        "framework_objectives": [
            {"id": "CRI-CRYPTO-1", "title": "Encryption at rest",
             "specification": "Encrypt stored data with customer-managed keys.",
             "domain": "Cryptography"},
            {"id": "CRI-XYZ-1", "title": "Zorptastic Flibbergibbet",
             "specification": "Quuxical borogove mimsy raths.", "domain": "Nonsense"},
        ],
    }
    result = acf.build_result(parsed, threshold=_default_threshold())
    assert result["summary"]["total"] == 2
    assert result["summary"]["anchored"] + result["summary"]["uncertain"] == 2
    assert result["framework"] == "CRI Profile"


def _default_threshold() -> float:
    return acf._DEFAULT_THRESHOLD
