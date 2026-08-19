"""Regression tests for PostToolUse legacy-layout detection.

The hook classifies writes under `.service-approval/` as current-layout or
legacy-layout (`.service-approval/state/`, `.service-approval/controls/`).
Classification must be anchored to the `.service-approval/` jail: matching a
bare `/state/`, `/controls/`, or `/service-approval/` anywhere in the absolute
path let an *ancestor* directory of the same name (e.g. a repo cloned under
`~/work/controls/`) masquerade as the pipeline's own layout, spuriously
warning — and, after the 24h grace window, hard-failing — on every write.
"""
from __future__ import annotations

from pathlib import Path

from hook_post_tool_use import (  # type: ignore
    _emit_legacy_migration_warning,
    _rel_under_service_approval,
)


# --- _rel_under_service_approval: anchor to the jail, not ancestors ---------

def test_rel_returns_none_outside_service_approval():
    assert _rel_under_service_approval("/home/u/repo/skills/map/SKILL.md") is None


def test_rel_strips_prefix_to_jail_root():
    rel = _rel_under_service_approval(
        "/home/u/repo/.service-approval/awslambda/04-map/mapping-results.json"
    )
    assert rel == "awslambda/04-map/mapping-results.json"


def test_rel_ignores_ancestor_named_controls():
    # Ancestor dir 'controls' must NOT be treated as the jail root.
    rel = _rel_under_service_approval(
        "/home/u/controls/repo/.service-approval/awslambda/05-recommended-guidance/preventive/scp.json"
    )
    assert rel == "awslambda/05-recommended-guidance/preventive/scp.json"


def test_rel_uses_last_service_approval_occurrence():
    # A clone nested inside another .service-approval/ resolves to its own jail.
    rel = _rel_under_service_approval(
        "/home/u/.service-approval/clone/.service-approval/svc/04-map/x.json"
    )
    assert rel == "svc/04-map/x.json"


# --- _emit_legacy_migration_warning: only genuine legacy children fire ------

def _write(tmp_path: Path, rel: str) -> str:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}")
    return str(p)


def test_new_layout_under_ancestor_controls_is_not_legacy(tmp_path):
    # Repo checked out under a directory literally named 'controls'.
    fp = _write(
        tmp_path,
        "controls/repo/.service-approval/awslambda/05-recommended-guidance/preventive/scp.json",
    )
    norm = fp.replace("\\", "/")
    assert _emit_legacy_migration_warning(norm, fp) is None
    # No spurious marker anywhere under the jail.
    assert not list(tmp_path.rglob(".LEGACY-LAYOUT-DETECTED"))


def test_new_layout_under_ancestor_state_is_not_legacy(tmp_path):
    fp = _write(tmp_path, "state/repo/.service-approval/awslambda/04-map/x.json")
    norm = fp.replace("\\", "/")
    assert _emit_legacy_migration_warning(norm, fp) is None
    assert not list(tmp_path.rglob(".LEGACY-LAYOUT-DETECTED"))


def test_genuine_legacy_state_child_warns(tmp_path):
    fp = _write(tmp_path, "repo/.service-approval/state/foo.json")
    norm = fp.replace("\\", "/")
    marker = _emit_legacy_migration_warning(norm, fp)
    assert marker is not None
    # Marker lands at the jail root, not doubled or under an ancestor.
    assert Path(marker) == tmp_path / "repo" / ".service-approval" / ".LEGACY-LAYOUT-DETECTED"
    assert Path(marker).exists()


def test_genuine_legacy_controls_child_warns(tmp_path):
    fp = _write(tmp_path, "repo/.service-approval/controls/preventive/scp.json")
    norm = fp.replace("\\", "/")
    marker = _emit_legacy_migration_warning(norm, fp)
    assert marker is not None
    assert Path(marker) == tmp_path / "repo" / ".service-approval" / ".LEGACY-LAYOUT-DETECTED"


def test_write_outside_jail_is_not_legacy(tmp_path):
    fp = _write(tmp_path, "repo/skills/map/SKILL.md")
    norm = fp.replace("\\", "/")
    assert _emit_legacy_migration_warning(norm, fp) is None
