"""Tests for scripts/compute-applicability-matrix.py — the corrected capability
+ category + applicability screen.

The prior derivation read entity-description prose and inferred customer-managed
patching for a serverless service, which flipped TVM-10 to applicable (the
opposite of correct). These tests fix-pin the corrected behavior:

  - capability flags derive from mitigation STATEMENTS only, never entity prose;
  - flags are three-valued (present / absent / unknown);
  - an UNKNOWN capability never forces an objective N/A (it defers to the KB);
  - N/A only comes from a positive structural reason (intrinsic org objective,
    or a category fact), and every decision cites its rule (`derived_from`).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "compute-applicability-matrix.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("compute_applicability_matrix", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cam = _load_module()


def _canopy(mitigation_statements, entity_infos=None):
    """Build a minimal Canopy doc with the given mitigation statements and,
    optionally, entity information prose (which must NEVER drive a capability)."""
    return {
        "metadata": {"name": "test-service"},
        "mitigations": [{"id": f"m{i}", "statement": s} for i, s in enumerate(mitigation_statements)],
        "entities": [{"id": f"e{i}", "name": f"E{i}", "information": info}
                     for i, info in enumerate(entity_infos or [])],
        "threats": [],
    }


# --- capability derivation: statements only, three-valued -------------------

def test_capability_present_from_statement():
    caps = cam.derive_capabilities(
        _canopy(["An AWS Lambda function should be encrypted with an AWS KMS Customer Managed Key (CMK)"]),
        json.loads((REPO / "data" / "service-capability-rules.json").read_text()),
    )
    assert caps["customer_manages_keys"]["state"] == cam.PRESENT
    assert "kms" in caps["customer_manages_keys"]["evidence"].lower()


def test_patching_not_inferred_from_entity_prose():
    """REGRESSION: a Layer entity's 'custom runtime' description must NOT assert
    customer-managed patching. With no patching STATEMENT, the flag is unknown."""
    canopy = _canopy(
        mitigation_statements=["An AWS Lambda function should be encrypted with an AWS KMS Customer Managed Key (CMK)"],
        entity_infos=["A custom runtime, or configuration files that can be reused across multiple lambda functions"],
    )
    caps = cam.derive_capabilities(
        canopy, json.loads((REPO / "data" / "service-capability-rules.json").read_text())
    )
    assert caps["customer_managed_patching"]["state"] == cam.UNKNOWN


def test_absent_wins_over_present():
    caps = cam.derive_capabilities(
        _canopy(["The operating system is patched by AWS; the customer should also patch the operating system"]),
        json.loads((REPO / "data" / "service-capability-rules.json").read_text()),
    )
    # 'patched by aws' is an absent_when signal and wins over any present match.
    assert caps["customer_managed_patching"]["state"] == cam.ABSENT


# --- category derivation ----------------------------------------------------

def test_serverless_category_derived():
    caps = cam.derive_capabilities(
        _canopy([
            "An AWS Lambda function IAM execution role should be accessed only by trusted identities",
            "An AWS Lambda function should be configured to send application and system logs to CloudWatch Logs",
        ]),
        json.loads((REPO / "data" / "service-capability-rules.json").read_text()),
    )
    cats = cam.derive_categories(
        caps, json.loads((REPO / "data" / "service-category-rules.json").read_text())
    )
    assert "serverless_compute" in cats
    assert "managed_compute" not in cats


# --- applicability screen: unknown never forces N/A -------------------------

def test_unknown_capability_defers_to_kb_default():
    """A serverless service with no backup signal must NOT list CEK-03/LOG-02 as
    N/A — those defer to the KB default (absent from the matrix)."""
    canopy = _canopy([
        "An AWS Lambda function IAM execution role should be accessed only by trusted identities",
        "An AWS Lambda function should be encrypted with an AWS KMS Customer Managed Key (CMK)",
    ])
    result = cam.evaluate_applicability(
        cam.derive_capabilities(canopy, json.loads((REPO / "data" / "service-capability-rules.json").read_text())),
        ["serverless_compute"],
        json.loads((REPO / "data" / "objective-applicability-rules.json").read_text()),
    )
    assert "CEK-03" not in result
    assert "LOG-02" not in result


def test_tvm10_na_for_serverless_via_category_not_prose():
    canopy = _canopy([
        "An AWS Lambda function IAM execution role should be accessed only by trusted identities",
    ])
    caps = cam.derive_capabilities(
        canopy, json.loads((REPO / "data" / "service-capability-rules.json").read_text())
    )
    result = cam.evaluate_applicability(
        caps, ["serverless_compute"],
        json.loads((REPO / "data" / "objective-applicability-rules.json").read_text()),
    )
    assert result["TVM-10"]["applicable"] is False
    assert result["TVM-10"]["derived_from"]["rule"] == "category_na"


def test_backup_capability_unlocks_bcr08_over_category_na():
    """A service that IS serverless-shaped but demonstrably exposes a backup API
    keeps BCR-08 applicable — a present capability beats the category fact."""
    canopy = _canopy([
        "An execution role should only be assumable by the service principal",
        "The datastore should have automated backup with point-in-time recovery enabled",
    ])
    caps = cam.derive_capabilities(
        canopy, json.loads((REPO / "data" / "service-capability-rules.json").read_text())
    )
    result = cam.evaluate_applicability(
        caps, ["serverless_compute"],
        json.loads((REPO / "data" / "objective-applicability-rules.json").read_text()),
    )
    assert result["BCR-08"]["applicable"] is True
    assert result["BCR-08"]["derived_from"]["rule"] == "capability_unlock"


def test_intrinsic_na_capability_independent():
    result = cam.evaluate_applicability(
        {}, [], json.loads((REPO / "data" / "objective-applicability-rules.json").read_text())
    )
    assert result["DCS-01"]["applicable"] is False
    assert result["HRS-01"]["applicable"] is False


# --- end-to-end on the real Lambda Canopy -----------------------------------

def test_real_lambda_matrix_acceptance():
    lambda_canopy = REPO / "runs" / "with-canopy" / "input" / "lambda-canopy.json"
    if not lambda_canopy.exists():
        return
    result = cam.compute_matrix(lambda_canopy)
    assert result["service_categories"] == ["serverless_compute"]
    caps = result["derived_capabilities"]
    # The prose bug is gone: patching is unknown, not present.
    assert "customer_managed_patching" in caps["unknown"]
    assert "customer_managed_patching" not in caps["present"]
    oa = result["objective_applicability"]
    assert oa["TVM-10"]["applicable"] is False
    assert oa["BCR-08"]["applicable"] is False
    # Encryption/log objectives defer to KB default, not force-N/A.
    assert "CEK-03" not in oa
    assert "LOG-02" not in oa
    # Every N/A carries a reason + derived_from.
    for oid, e in oa.items():
        if not e["applicable"]:
            assert e["reason"], f"{oid} N/A without reason"
            assert e["derived_from"], f"{oid} N/A without derived_from"
