"""Doc-assertion tests for the orchestrator's two review gates.

The post-map and post-generate review gates must both (1) appear as explicit
orchestrator steps, (2) declare a machine-readable review artifact, and (3) the
post-generate gate must run the full enforcement validator set, so correctness
does not depend on any single check being remembered. These are doc assertions
over skills/service-approval/SKILL.md — the runtime execution is exercised
end-to-end, but the declaration must not regress.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ORCHESTRATOR = REPO / "skills" / "service-approval" / "SKILL.md"


def _skill_text() -> str:
    return ORCHESTRATOR.read_text()


def test_both_review_gates_present():
    text = _skill_text()
    assert "Mapping review gate" in text
    assert "Generation review gate" in text


def test_gates_declare_review_artifacts():
    """Each gate must persist a machine-readable trace artifact."""
    text = _skill_text()
    assert "mapping-review.json" in text
    assert "generation-review.json" in text


def test_post_generate_gate_runs_full_validator_set():
    """The post-generate gate must invoke every enforcement validator — the
    deterministic backstops for G1–G5 — not just the anchor check."""
    text = _skill_text()
    for validator in (
        "validate_reference_anchor.py",
        "validate_preventability.py",
        "validate_enforcement.py",
        "validate_action_scope.py",
        "validate_cross.py",
        "validate_detective_routing.py",
    ):
        assert validator in text, f"post-generate gate is missing {validator}"


def test_gates_emit_lifecycle_logging():
    """Both gates must emit start/end lifecycle lines to pipeline.log so a run
    shows the gate ran (the audit-from-outputs requirement)."""
    text = _skill_text()
    assert "skill:map-review" in text
    assert "skill:generate-review" in text
    assert "tools.validate.log" in text
