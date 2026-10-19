"""Tests for the control-prose lint.

Tone-of-voice rule: control `description` / `security_rationale` /
mapped-objective `rationale` strings should stay broad and verified.
The lint flags two drift signals — over-long strings and banned causal
filler phrases — that historically signal LLM speculation.
"""

from __future__ import annotations

from lint_control_prose import (
    BANNED_PHRASES,
    DEFAULT_DESCRIPTION_BUDGET,
    DEFAULT_RATIONALE_BUDGET,
    find_banned_phrases,
    find_md_divergences,
    lint_control_prose,
    lint_mapping_file,
    lint_markdown_prose,
)


# ---- find_banned_phrases ----------------------------------------------


def test_find_banned_phrases_clean_text() -> None:
    """A broad, hedged sentence has no banned phrases."""
    text = (
        "SCP denies CreateFunction without KMSKeyArn at request time — "
        "supports the encryption-at-rest objective."
    )
    assert find_banned_phrases(text) == []


def test_find_banned_phrases_catches_ensures() -> None:
    """`ensures` is an obvious causal overreach."""
    text = "This SCP ensures no resource is created without encryption."
    assert "ensures" in find_banned_phrases(text)


def test_find_banned_phrases_case_insensitive() -> None:
    """Phrase matching is case-insensitive."""
    assert "guarantees" in find_banned_phrases("It Guarantees blocking.")
    assert "completely blocks" in find_banned_phrases(
        "The control Completely Blocks unauthorized calls."
    )


def test_find_banned_phrases_honors_word_boundaries() -> None:
    """`censure` and `assured` should not trigger the `ensures`/`assured`
    matchers; the regex uses word boundaries."""
    text = "This control reassured the auditor; no censure was issued."
    # `assured` as a standalone word is not in the banned list, only
    # `ensures` etc. Make sure the substring `sures` doesn't false-match.
    found = find_banned_phrases(text)
    assert "ensures" not in found
    assert "guarantees" not in found


def test_banned_phrases_constant_is_non_empty() -> None:
    """The banned-phrase list must have content, otherwise the lint is
    a no-op. Sanity-pin so a future refactor that empties it fails."""
    assert len(BANNED_PHRASES) >= 5


# ---- lint_control_prose -----------------------------------------------


def test_lint_passes_for_clean_control() -> None:
    """A control whose strings are short, mechanism-named, and free of
    causal filler returns no findings."""
    ctrl = {
        "id": "CTRL-ORG-PRV-001",
        "description": "SCP denies CreateFunction without KMSKeyArn.",
        "security_rationale": (
            "Supports the encryption-at-rest objective by gating the create "
            "call on the customer-managed key parameter at request time."
        ),
    }
    findings = lint_control_prose(ctrl)
    assert findings == [], f"Expected clean control to lint clean; got: {findings}"


def test_lint_flags_banned_phrase() -> None:
    """A control whose security_rationale uses 'ensures' must be flagged."""
    ctrl = {
        "id": "CTRL-ORG-PRV-001",
        "description": "SCP denies CreateFunction without KMSKeyArn.",
        "security_rationale": (
            "This SCP ensures no Lambda function is ever created without "
            "encryption."
        ),
    }
    findings = lint_control_prose(ctrl)
    kinds = {(f.field, f.kind) for f in findings}
    assert ("security_rationale", "banned_phrase") in kinds


def test_lint_flags_overlong_rationale() -> None:
    """A rationale longer than the budget must be flagged."""
    long_rationale = "x" * (DEFAULT_RATIONALE_BUDGET + 50)
    ctrl = {
        "id": "CTRL-ORG-PRV-001",
        "description": "short description",
        "security_rationale": long_rationale,
    }
    findings = lint_control_prose(ctrl)
    kinds = {(f.field, f.kind) for f in findings}
    assert ("security_rationale", "length") in kinds


def test_lint_flags_overlong_description() -> None:
    """description has its own (looser) budget; over-long descriptions are
    flagged independently."""
    ctrl = {
        "id": "CTRL-ORG-PRV-001",
        "description": "x" * (DEFAULT_DESCRIPTION_BUDGET + 1),
        "security_rationale": "Supports the encryption-at-rest objective.",
    }
    findings = lint_control_prose(ctrl)
    assert any(f.field == "description" and f.kind == "length" for f in findings)


def test_lint_handles_nested_rationale() -> None:
    """The framework-mapping output nests rationale on each control entry
    under a framework objective. The lint must still pick it up."""
    nested = {
        "control_id": "CTRL-ORG-PRV-001",
        "coverage_level": "Full Coverage",
        "rationale": (
            "This control completely prevents every misconfigured deployment."
        ),
    }
    findings = lint_control_prose(nested)
    kinds = {(f.field, f.kind) for f in findings}
    assert ("rationale", "banned_phrase") in kinds


def test_lint_treats_missing_fields_as_clean() -> None:
    """A control without description/rationale is fine — no findings."""
    assert lint_control_prose({"id": "CTRL-ORG-PRV-001"}) == []


# ---- lint_mapping_file ------------------------------------------------


def test_lint_mapping_file_scans_top_level_and_nested() -> None:
    """Findings are collected from controls[] and framework_mapping[].controls[]."""
    mapping = {
        "controls": [
            {"control_id": "CTRL-ORG-PRV-001", "security_rationale": "This ensures safety."},
            {"control_id": "CTRL-ORG-PRV-002", "description": "A short, verified note."},
        ],
        "framework_mapping": [
            {
                "objective_id": "CCC-04",
                "controls": [
                    {"control_id": "CTRL-ACC-DET-009", "rationale": "Eliminates all risk."}
                ],
            }
        ],
    }
    results = lint_mapping_file(mapping)
    flagged = {cid for cid, _ in results}
    assert "CTRL-ORG-PRV-001" in flagged  # banned: ensures
    assert "CTRL-ACC-DET-009" in flagged  # banned: eliminates
    assert "CTRL-ORG-PRV-002" not in flagged  # clean


def test_lint_mapping_file_empty_is_clean() -> None:
    assert lint_mapping_file({}) == []


# ---- widened banned phrases -------------------------------------------


def test_bare_prevents_and_blocks_are_flagged() -> None:
    """Bare 'prevents'/'blocks'/'blocking'/'cannot' are overreach in a claim."""
    assert "prevents" in find_banned_phrases("This control prevents data loss.")
    assert "blocks" in find_banned_phrases("It blocks unauthorized calls.")
    assert "blocking" in find_banned_phrases("Blocking the create call.")
    assert "cannot" in find_banned_phrases("The resource cannot be created.")


def test_confused_deputy_claim_is_flagged() -> None:
    assert "confused-deputy" in find_banned_phrases(
        "Stops the confused-deputy attack entirely."
    )


def test_standalone_only_is_flagged() -> None:
    assert "only" in find_banned_phrases("Denies all callers, allowing trusted only.")


def test_supportive_only_label_not_flagged() -> None:
    """The coverage-level label 'Supportive Only' must not trip the 'only' check."""
    assert find_banned_phrases("Coverage: Supportive Only") == []


def test_read_only_and_write_only_not_flagged() -> None:
    assert find_banned_phrases("Grants read-only access.") == []
    assert find_banned_phrases("A write-only sink.") == []


def test_denies_untrusted_claim_is_flagged() -> None:
    assert "denies … untrusted" in find_banned_phrases(
        "The policy denies any untrusted principal."
    )


# ---- rendered-markdown scanning ---------------------------------------


_CATALOG_MD_CLEAN = """\
# Security Controls Catalog — Amazon Foo

## Resource-Level Controls

#### CTRL-RES-PRV-001 — Enforce CMK encryption

- **Description:** Constrains Foo creation to require encryption at request time via SCP.
- **Implementation:** Apply the SCP at the organization root.
- **Governs:** the resource's encryption-key setting
"""

_CATALOG_MD_OVERREACH = """\
# Security Controls Catalog — Amazon Foo

## Resource-Level Controls

#### CTRL-RES-PRV-001 — Enforce CMK encryption

- **Description:** This SCP ensures no Foo is ever created without encryption and completely blocks bad calls.
- **Implementation:** Apply the SCP at the organization root.
"""


def test_lint_markdown_clean_catalog_passes() -> None:
    assert lint_markdown_prose(_CATALOG_MD_CLEAN) == []


def test_mapping_citation_limitations_are_not_rendered_control_claims() -> None:
    md = """| Control ID | Title | Rationale | Source |
|---|---|---|---|
| CTRL-ACC-DET-001 | Monitor events | Records access events. | detection only; no blocking |
"""
    mapping = {"controls": [{"id": "CTRL-ACC-DET-001", "name": "Monitor events",
                             "description": "Records access events."}]}
    assert lint_markdown_prose(md) == []
    assert find_md_divergences(md, mapping) == []
    overclaim = md.replace("Records access events.", "Guarantees event detection.")
    assert lint_markdown_prose(overclaim)
    assert find_md_divergences(overclaim, mapping)


def test_lint_markdown_flags_overreach_in_catalog_bullet() -> None:
    results = lint_markdown_prose(_CATALOG_MD_OVERREACH)
    flagged = {cid for cid, _ in results}
    assert "CTRL-RES-PRV-001" in flagged
    phrases = " ".join(f.detail for _, f in results)
    assert "ensures" in phrases and "completely blocks" in phrases


def test_lint_markdown_flags_overreach_in_table_row() -> None:
    """A mapping/MITRE table row that names a control id is per-control prose."""
    md = (
        "| Control ID | How It Mitigates |\n"
        "|---|---|\n"
        "| CTRL-ORG-PRV-002 | The SCP ensures every call is denied unless trusted. |\n"
    )
    results = lint_markdown_prose(md)
    assert any(cid == "CTRL-ORG-PRV-002" for cid, _ in results)


def test_lint_markdown_skips_na_reason_and_labels() -> None:
    """Objective-level N/A reasons and coverage labels are NOT per-control prose
    and legitimately use words like 'cannot'/'only' — they must not be flagged."""
    md = (
        "#### AIS-01: Application Security\n\n"
        "**Status:** Not Applicable\n"
        "**Coverage:** Supportive Only\n"
        "**Reason:** This objective cannot be enforced at the AWS service level.\n"
    )
    assert lint_markdown_prose(md) == []


# ---- divergence (upward re-wording) -----------------------------------


def test_divergence_flags_md_stronger_than_json() -> None:
    """The .md says 'ensures' for a control whose JSON rationale does not — that
    is upward re-wording and must be flagged."""
    mapping = {
        "controls": [
            {"control_id": "CTRL-RES-PRV-001",
             "description": "Constrains Foo creation to require encryption.",
             "security_rationale": "Supports encryption-at-rest at request time."}
        ]
    }
    md = (
        "#### CTRL-RES-PRV-001 — Enforce CMK encryption\n\n"
        "- **Description:** This SCP ensures no Foo is created without encryption.\n"
    )
    results = find_md_divergences(md, mapping)
    flagged = {cid for cid, _ in results}
    assert "CTRL-RES-PRV-001" in flagged
    assert any("ensures" in f.detail for _, f in results)


def test_divergence_clean_when_md_matches_json() -> None:
    """If the JSON itself already carries the word, the .md is not 'upward' —
    the JSON lint catches that separately; divergence stays quiet."""
    mapping = {
        "controls": [
            {"control_id": "CTRL-RES-PRV-001",
             "description": "This SCP ensures encryption."}
        ]
    }
    md = (
        "#### CTRL-RES-PRV-001 — Enforce CMK encryption\n\n"
        "- **Description:** This SCP ensures encryption.\n"
    )
    assert find_md_divergences(md, mapping) == []
