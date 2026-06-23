"""Tests for the deterministic preventive-coverage rollup builder.

Verifies the rollup buckets each plan decision (authored / referred /
routed-to-detective), re-buckets a control the root-cause critic routed,
produces counts that match the rows, keeps every count row traceable to a real
control id + citation, and validates against the schema.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "tools" / "validate"))

from _schemas import schema_errors  # noqa: E402
import build_preventive_coverage as bpc  # noqa: E402


def _plan() -> dict:
    return {
        "_metadata": {"service": "lambda"},
        "decisions": [
            {
                "control_id": "CTRL-ORG-PRV-001", "mechanism": "SCP",
                "decision": "GENERATE_SCP",
                "anchor": {"example_id": "scp-ex-1", "repo": "r", "url": "u"},
                "citation": {"type": "canopy", "id": "M-fn.0"},
                "rationale": "condition key gates CreateFunction",
            },
            {
                "control_id": "CTRL-ACC-PRV-002", "mechanism": "IAM Permission Boundary",
                "decision": "REFER_TO_REFERENCE",
                "anchor": {"example_id": "pb-ex-1", "repo": "r", "url": "u"},
                "citation": {"type": "reference", "id": "pb-ex-1", "url": "u"},
                "rationale": "boundary refer-by-default; org attaches it",
            },
            {
                "control_id": "CTRL-ORG-PRV-003", "mechanism": "SCP",
                "decision": "ROUTE_DETECTIVE",
                "anchor": None,
                "citation": {"type": "service-doc", "url": "https://docs.aws.amazon.com/x"},
                "rationale": "no condition key gates DeleteFunction",
            },
        ],
    }


def test_buckets_and_totals_match_rows() -> None:
    cov = bpc.build_coverage(_plan())
    assert cov["totals"] == {
        "objectives": 3, "authored": 1, "referred": 1, "routed_to_detective": 1,
    }
    cats = {r["control_id"]: r["category"] for r in cov["controls"]}
    assert cats["CTRL-ORG-PRV-001"] == "authored"
    assert cats["CTRL-ACC-PRV-002"] == "referred"
    assert cats["CTRL-ORG-PRV-003"] == "routed_to_detective"


def test_critic_routing_rebuckets_authored_control() -> None:
    """A GENERATE_* control the root-cause critic later routed to detective must
    be counted under routed_to_detective, not authored."""
    rootcause = {
        "routed_to_detective": [
            {"control_id": "CTRL-ORG-PRV-001", "reason": "authored policy did not enforce"}
        ]
    }
    cov = bpc.build_coverage(_plan(), rootcause)
    assert cov["totals"]["authored"] == 0
    assert cov["totals"]["routed_to_detective"] == 2
    row = next(r for r in cov["controls"] if r["control_id"] == "CTRL-ORG-PRV-001")
    assert row["category"] == "routed_to_detective"
    assert "did not enforce" in row["reason"]
    assert "rootcause-report.json" in cov["_metadata"]["sources"]


def test_every_count_row_is_traceable() -> None:
    """Each row carries a real control id and a typed citation so a reader can
    verify each number against the plan."""
    cov = bpc.build_coverage(_plan())
    for r in cov["controls"]:
        assert r["control_id"].startswith("CTRL-")
        assert r["citation"]["type"] in {"canopy", "reference", "catalog", "service-doc"}
        assert r["reason"]


def test_rollup_validates_against_schema() -> None:
    cov = bpc.build_coverage(_plan(), {"routed_to_detective": []})
    errors = schema_errors(cov, "preventive-coverage")
    assert errors == [], errors


def test_build_for_slug_writes_file(tmp_path: Path) -> None:
    base = tmp_path / ".service-approval" / "lambda" / "05-generate"
    (base / "preventive").mkdir(parents=True)
    (base / "preventive-plan.json").write_text(json.dumps(_plan()))
    cov = bpc.build_for_slug("lambda", root=tmp_path)
    assert cov is not None
    written = json.loads((base / "preventive-coverage.json").read_text())
    assert written["totals"]["objectives"] == 3


def test_build_for_slug_missing_plan_returns_none(tmp_path: Path) -> None:
    assert bpc.build_for_slug("nope", root=tmp_path) is None


def test_application_guidance_carried_for_authored_and_referred() -> None:
    """application_guidance on a GENERATE_*/REFER_TO_REFERENCE decision is carried
    verbatim into its coverage row; routed-to-detective rows never carry it."""
    plan = _plan()
    plan["decisions"][0]["application_guidance"] = {
        "placement": "Attach to the workload OU SCP",
        "placeholders": ["<ORG_ID>", "<WORKLOAD_OU_ID>"],
        "test": "simulate a non-compliant create",
        "rollback": "detach the SCP",
    }
    plan["decisions"][1]["application_guidance"] = {
        "placement": "Attach as a permission boundary to the execution role",
        "placeholders": ["the execution role ARN"],
    }
    # A routed-to-detective decision should drop any guidance even if present.
    plan["decisions"][2]["application_guidance"] = {"placement": "n/a"}

    cov = bpc.build_coverage(_plan_with(plan))
    rows = {r["control_id"]: r for r in cov["controls"]}
    assert rows["CTRL-ORG-PRV-001"]["application_guidance"]["placement"].startswith("Attach to the workload OU")
    assert rows["CTRL-ACC-PRV-002"]["application_guidance"]["placeholders"] == ["the execution role ARN"]
    assert "application_guidance" not in rows["CTRL-ORG-PRV-003"]
    assert schema_errors(cov, "preventive-coverage") == []


def _plan_with(plan: dict) -> dict:
    """Identity helper so the guidance test reads naturally; build_coverage
    consumes the plan dict directly."""
    return plan


def test_missing_citation_falls_back_to_service_doc() -> None:
    plan = {
        "_metadata": {"service": "x"},
        "decisions": [
            {"control_id": "CTRL-ORG-PRV-009", "mechanism": "SCP",
             "decision": "GENERATE_SCP", "anchor": {"example_id": "e"}},
        ],
    }
    cov = bpc.build_coverage(plan)
    row = cov["controls"][0]
    assert row["citation"]["type"] == "service-doc"
    assert schema_errors(cov, "preventive-coverage") == []
