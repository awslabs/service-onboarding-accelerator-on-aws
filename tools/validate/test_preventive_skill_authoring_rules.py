"""Regression tests for the preventive-skill authoring rules.

Guards against re-introducing four wrong rules that previously appeared in the
generate-preventive* SKILL.md files:

  1. Treating the SAR/Bookkeeper condition-key list as a closed set rather than
     a lower bound (ignored doc-cited service-specific keys).
  2/3. Sourcing IAM `Action` strings from API operation names (botocore /
     `api_surface.operations[].operation` or `research-api-surface.json`) — IAM
     Action strings are NOT operation names; they come from the Service
     Authorization Reference IAM action list, with `data/botocore-iam-alias.json`
     resolving operation→action drift.
  4. The "zero-service-condition-keys deterministically if every key starts
     with `aws:`" branch — services don't always publish their service-specific
     keys in the SAR/Bookkeeper, so absence of a non-`aws:` key is not proof
     the service has none.

These tests scan the shipped SKILL.md text directly so a future edit that
re-introduces any banned phrasing fails CI.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


def _repo_root() -> Path:
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "manifest.yaml").exists():
            return current
        current = current.parent
    raise RuntimeError("Could not find repository root (no manifest.yaml found)")


_PREVENTIVE_SKILLS = (
    "generate-preventive",
    "generate-preventive-iam",
    "generate-preventive-scp",
    "generate-preventive-rcp",
    "generate-preventive-recommend",
    "generate-preventive-rootcause",
)


def _skill_paths() -> list[Path]:
    root = _repo_root()
    paths = [root / "skills" / s / "SKILL.md" for s in _PREVENTIVE_SKILLS]
    for p in paths:
        assert p.exists(), f"missing preventive skill file: {p}"
    return paths


# --- Wrong-rule 2/3: Action MUST come from operations[].operation as a SOURCE ---
#
# A "rule" form names operations[].operation (or research-api-surface...operation)
# as the place an `Action` is sourced from. CHECK-17's documentation legitimately
# names `operations[].operation` as the *implementation* of the valid-action set
# (the validator builds `<prefix>:Op` strings from it), so we only flag wording
# that asserts an Action string is *sourced* from an operation name.
_BANNED_ACTION_SOURCE_PATTERNS = (
    # "Action ... MUST come from ... operations[].operation"
    re.compile(
        r"`?Action`?[^\n]{0,200}\bMUST come from[^\n]{0,200}operations\[\]\.operation",
        re.IGNORECASE,
    ),
    # "research-api-surface.json.api_surface.operations[].operation" listed as a valid Action source
    re.compile(
        r"research-api-surface[^\n]{0,200}operations\[\]\.operation",
        re.IGNORECASE,
    ),
    # "Every `Action` ... exists in ... operations[].operation OR ... permission_only_actions"
    # — the legacy CRITICAL paragraph sourcing Action from operation names.
    re.compile(
        r"Action`?\s+value\s+exists\s+in[^\n]{0,200}operations\[\]\.operation",
        re.IGNORECASE,
    ),
)


# --- Wrong-rule 4: zero-service-condition-keys deterministic branch ---
#
# The deleted branch used the heuristic "if every condition_keys[] entry starts
# with `aws:`, the service has no service-specific keys." Flag both the section
# heading and the deterministic-detection phrasing.
_BANNED_DETERMINISTIC_BRANCH_PATTERNS = (
    re.compile(r"Zero-service-condition-keys\s+branch", re.IGNORECASE),
    re.compile(
        r"every\s+(entry\S?s\s+`?key`?|key)\s+starts\s+with\s+`?aws:`?",
        re.IGNORECASE,
    ),
    re.compile(
        r"deterministically[^\n]{0,80}every[^\n]{0,80}aws:",
        re.IGNORECASE,
    ),
)


# --- Wrong-rule 1: condition keys MUST come from a closed set ---
#
# The replacement framing must say keys are a *lower bound* and may include
# doc-cited service-specific keys. Flag the strict closed-set phrasing.
_BANNED_CLOSED_CONDITION_KEY_PATTERNS = (
    re.compile(
        r"Every\s+Condition-block\s+key\s+MUST\s+come\s+from\s+`validated\.json"
        r"\.capabilities\.iam\.condition_keys\[\]`",
        re.IGNORECASE,
    ),
)


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_no_banned_action_source_phrasing(skill_path: Path) -> None:
    """No preventive skill should source IAM `Action` from API operation names."""
    text = skill_path.read_text()
    for pat in _BANNED_ACTION_SOURCE_PATTERNS:
        m = pat.search(text)
        assert not m, (
            f"{skill_path} contains banned Action-source phrasing matching "
            f"/{pat.pattern}/: {text[max(0, m.start()-40):m.end()+40]!r}. "
            f"IAM Action strings come from the SAR IAM action list (with "
            f"data/botocore-iam-alias.json resolving operation→action drift), "
            f"not from api_surface.operations[].operation."
        )


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_no_zero_service_condition_keys_deterministic_branch(skill_path: Path) -> None:
    """No preventive skill should ship the deterministic 'every key starts with aws:' branch."""
    text = skill_path.read_text()
    for pat in _BANNED_DETERMINISTIC_BRANCH_PATTERNS:
        m = pat.search(text)
        assert not m, (
            f"{skill_path} contains banned deterministic-no-service-keys phrasing "
            f"matching /{pat.pattern}/: {text[max(0, m.start()-40):m.end()+40]!r}. "
            f"Absence of a service-specific key in the SAR snapshot is NOT proof "
            f"the key does not exist — the SAR is a lower bound."
        )


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_no_closed_set_condition_key_rule(skill_path: Path) -> None:
    """Condition keys are a lower bound, not a closed set."""
    text = skill_path.read_text()
    for pat in _BANNED_CLOSED_CONDITION_KEY_PATTERNS:
        m = pat.search(text)
        assert not m, (
            f"{skill_path} contains the banned closed-set condition-key rule "
            f"matching /{pat.pattern}/: {text[max(0, m.start()-40):m.end()+40]!r}. "
            f"The SAR/Bookkeeper condition-key list is a lower bound; doc-cited "
            f"service-specific keys are valid even when absent from the snapshot."
        )
