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


# ---------------------------------------------------------------------------
# Wrong-pattern: confused-deputy Deny that fires on absent keys.
# ---------------------------------------------------------------------------
#
# The dangerous pre-fix pattern was a two-statement example whose second
# statement (`DenyConfusedDeputyAcrossAccount`) used bare `StringNotEquals`
# on `aws:SourceAccount`. `aws:SourceAccount` is only present in the
# authorization context when an AWS service is calling the target on
# behalf of a customer resource — for every other request (in-account
# direct calls, identity-based calls without service mediation) the key is
# absent and `null != "<account>"` evaluates true, so the Deny would fire
# on every in-account `sts:AssumeRole`. The fix is a single
# `StringNotEqualsIfExists` (paired with a `Null` presence check) so the
# Deny only fires when the keys are PRESENT and mismatched.
_BANNED_DANGEROUS_SIDS = (
    re.compile(r'"Sid"\s*:\s*"DenyServicePrincipalUnscoped"'),
    re.compile(r'"Sid"\s*:\s*"DenyConfusedDeputyAcrossAccount"'),
)


# Match a Condition-block clause that uses bare `StringNotEquals` on
# `aws:SourceAccount` (no `IfExists` suffix). The `(?!IfExists)` lookahead
# is what distinguishes it from the safe form.
_BANNED_BARE_STRING_NOT_EQUALS_SOURCE_ACCOUNT = re.compile(
    r'"StringNotEquals"(?!IfExists)\s*:\s*\{\s*"aws:SourceAccount"',
)


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_no_dangerous_confused_deputy_sid_pair(skill_path: Path) -> None:
    """The dangerous DenyServicePrincipalUnscoped + DenyConfusedDeputyAcrossAccount
    Sid pair must not appear in any preventive skill."""
    text = skill_path.read_text()
    for pat in _BANNED_DANGEROUS_SIDS:
        m = pat.search(text)
        assert not m, (
            f"{skill_path} contains the dangerous confused-deputy Sid "
            f"matching /{pat.pattern}/. The pattern's "
            f"DenyConfusedDeputyAcrossAccount statement uses bare "
            f"StringNotEquals on aws:SourceAccount, which fires on every "
            f"in-account AssumeRole because the key is absent in that "
            f"authorization context. Rewrite as a single statement using "
            f"StringNotEqualsIfExists with a Null presence check."
        )


# ---------------------------------------------------------------------------
# Sourcing-order rule (recommender): Canopy must be the first-priority intent
# source, and the SKILL must state Canopy supplies intent + citation but not
# policy body — Canopy implementations are Config rules + CFN hooks only.
# ---------------------------------------------------------------------------


def _recommend_skill_text() -> str:
    return (_repo_root() / "skills" / "generate-preventive-recommend" / "SKILL.md").read_text()


def test_recommend_skill_documents_canopy_first() -> None:
    """The recommend SKILL must declare Canopy mitigations as the
    first-priority preventive sourcing source — ahead of the reference-repo
    index, the AWS Control Catalog, and AWS service docs."""
    text = _recommend_skill_text()
    m = re.search(r"##\s+Sourcing order[^\n]*\n([\s\S]+?)(?=\n##\s)", text)
    assert m, "recommend SKILL is missing a `## Sourcing order` section"
    section = m.group(1)
    first = re.search(r"^\s*1\.\s+(.+)$", section, re.MULTILINE)
    assert first, "Sourcing order section has no numbered list"
    assert "Canopy" in first.group(1), (
        f"first-priority source must be Canopy; got: {first.group(1)!r}"
    )


def test_recommend_skill_states_canopy_supplies_intent_not_body() -> None:
    """Canopy contains no preventive policy text — the recommend SKILL must
    say so and require a separate reference-repo body anchor (or downgrade
    to detective/proactive)."""
    text = _recommend_skill_text()
    assert re.search(
        r"Canopy.{0,200}(no|NO).{0,80}(preventive|policy).{0,80}(text|body|TEXT|BODY)",
        text,
        re.DOTALL,
    ), "recommend SKILL must state Canopy contains no preventive policy text/body"
    assert re.search(
        r"Canopy.{0,200}(intent|citation).{0,400}(reference[- ]repo|policy\s+body|policy\s+BODY|downgrade)",
        text,
        re.DOTALL,
    ), (
        "recommend SKILL must say Canopy supplies intent + citation and that "
        "the policy body still requires a reference-repo anchor (or downgrade)"
    )


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_no_bare_string_not_equals_on_source_account(skill_path: Path) -> None:
    """Bare `StringNotEquals` on `aws:SourceAccount` is forbidden — must use
    `StringNotEqualsIfExists` (or equivalent presence-guarded form) so absent
    keys do not trigger the Deny."""
    text = skill_path.read_text()
    m = _BANNED_BARE_STRING_NOT_EQUALS_SOURCE_ACCOUNT.search(text)
    assert not m, (
        f"{skill_path} contains a bare StringNotEquals on aws:SourceAccount "
        f"without an IfExists guard. When aws:SourceAccount is absent (every "
        f"non-cross-service call), the comparison evaluates true and the "
        f"Deny fires on legitimate traffic. Use StringNotEqualsIfExists "
        f"paired with a Null presence check, or restructure so the Deny "
        f"only fires when the key is PRESENT and the value mismatches."
    )
