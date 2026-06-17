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
    lint_control_prose,
    lint_mapping_file,
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
