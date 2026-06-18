"""Doc + schema assertions for the documented source-priority hierarchy.

ONE source-priority hierarchy is applied consistently wherever the pipeline
pulls an external fact or citation:

    1. Canopy  →  2. AWS Control Catalog API  →  3. service-specific AWS docs

(the reference-repo index supplies the vetted policy *body* under that intent).
The hierarchy must be stated in the skills that pull facts/citations — not only
in the recommender — and the recommender's typed-citation enum must stay intact
and required so every preventive decision records its highest-priority source.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SKILLS = REPO / "skills"

# Skills that must state the source-priority hierarchy where facts are pulled.
_NAMED_SKILLS = (
    "research-capabilities",
    "validate",
    "map",
    "generate-preventive-recommend",
)


def _skill_text(slug: str) -> str:
    return (SKILLS / slug / "SKILL.md").read_text()


def test_named_skills_state_the_hierarchy():
    """Each named skill must name all three tiers in priority order."""
    for slug in _NAMED_SKILLS:
        text = _skill_text(slug)
        low = text.lower()
        assert "canopy" in low, f"{slug} does not mention Canopy"
        assert "control catalog" in low, f"{slug} does not mention the Control Catalog"
        # The service-doc tier — accept either phrasing.
        assert (
            "service-specific aws doc" in low
            or "service-specific aws documentation" in low
            or "service's own pages" in low
        ), f"{slug} does not name the service-doc tier"


def test_named_skills_order_canopy_before_catalog_before_docs():
    """The three tiers must appear in the documented order in each skill."""
    for slug in _NAMED_SKILLS:
        low = _skill_text(slug).lower()
        i_canopy = low.find("canopy")
        i_catalog = low.find("control catalog")
        i_doc = low.find("service-specific aws doc")
        if i_doc == -1:
            i_doc = low.find("service's own pages")
        assert -1 < i_canopy < i_catalog < i_doc, (
            f"{slug}: tiers not in Canopy → Control Catalog → service-doc order "
            f"(positions: canopy={i_canopy}, catalog={i_catalog}, doc={i_doc})"
        )


def test_skills_note_reference_repo_supplies_body_not_citation():
    """The known wrinkle must be reconciled: reference repos supply the vetted
    policy BODY under the Canopy/catalog/doc intent — they are not a
    fact/citation source themselves."""
    for slug in ("research-capabilities", "validate", "map"):
        low = _skill_text(slug).lower()
        assert "reference-repo index" in low or "reference repo" in low, slug
        assert "body" in low, f"{slug} must state the repo supplies the policy body"


def test_recommender_citation_enum_unchanged_and_required():
    """The recommender's typed citation enum must stay exactly the four sources
    and remain required on every decision row."""
    schema = json.loads((REPO / "schemas" / "preventive-plan.schema.json").read_text())
    decision = schema["$defs"]["decision"]
    assert "citation" in decision["required"], "citation must be required on every decision"
    enum = decision["properties"]["citation"]["properties"]["type"]["enum"]
    assert enum == ["canopy", "reference", "catalog", "service-doc"], enum
