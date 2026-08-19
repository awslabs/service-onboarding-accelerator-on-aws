#!/usr/bin/env python3
"""Shorten over-long reference-example ids and their vendored filenames.

Descriptive reference-repo slugs reach 160+ characters. Nested under
`data/reference-repos/<repo>/examples/`, they push the full checkout path
toward the Windows MAX_PATH (~260) limit, which can break `git clone`/checkout
for users on Windows.

This migration rewrites `data/reference-repos/index.yaml` in place:

  * Each example `id` longer than the cap is replaced with a bounded,
    deterministic short id (see `build_reference_index.shorten_id`).
  * The vendored example file (`source_path`) is renamed to match the new id.
  * `source_url`, `license`, `intent`, and every other field are left intact —
    provenance (the real upstream path) must survive.

The transform is deterministic and idempotent: short ids are fixed points, so
re-running this — or regenerating the index with `build_reference_index.py`,
which applies the same `shorten_id` — is a no-op.

Usage:
    python3 tools/post-process/shorten_reference_ids.py           # apply
    python3 tools/post-process/shorten_reference_ids.py --check   # report only
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install -r requirements.txt",
          file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from paths import repo_root  # type: ignore
except ImportError:
    print("ERROR: tools.paths module not found. Run from the repo root with the "
          "project venv.", file=sys.stderr)
    sys.exit(1)

# shorten_id lives with the index generator so the migration and a fresh
# regeneration produce identical ids.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_reference_index import shorten_id  # type: ignore  # noqa: E402


def _index_path() -> Path:
    return repo_root() / "data" / "reference-repos" / "index.yaml"


def plan_renames(index: dict) -> list[dict]:
    """Return the list of id/path changes needed, enforcing global uniqueness."""
    changes: list[dict] = []
    used_ids: set[str] = set()
    # Pre-seed with ids that are already short and won't change, so a shortened
    # id can't collide with an untouched one.
    for ex in index.get("examples", []):
        old_id = ex.get("id")
        if old_id and shorten_id(old_id) == old_id:
            used_ids.add(old_id)

    for ex in index.get("examples", []):
        old_id = ex.get("id")
        if not old_id:
            continue
        new_id = shorten_id(old_id)
        if new_id == old_id:
            continue
        # Guarantee global uniqueness (hash collisions are astronomically
        # unlikely, but never silently overwrite).
        unique = new_id
        n = 1
        while unique in used_ids:
            n += 1
            unique = f"{new_id}-{n}"
        used_ids.add(unique)

        old_sp = ex.get("source_path")
        new_sp = None
        if old_sp:
            p = Path(old_sp)
            new_sp = str(p.with_name(f"{unique}{p.suffix}"))
        changes.append(
            {"old_id": old_id, "new_id": unique, "old_sp": old_sp, "new_sp": new_sp}
        )
    return changes


def apply_changes(root: Path, index_path: Path, changes: list[dict]) -> None:
    raw = index_path.read_text(encoding="utf-8")
    for c in changes:
        # Rename the vendored body on disk (if this repo vendors bodies).
        if c["old_sp"] and c["new_sp"]:
            src = root / c["old_sp"]
            dst = root / c["new_sp"]
            if src.exists():
                os.rename(src, dst)
            elif not dst.exists():
                raise FileNotFoundError(
                    f"expected reference file missing: {src} (and no {dst})"
                )
        # Surgical text edits: replace only the `id:` and `source_path:` lines.
        # Old ids are unique full strings, and source_url uses the upstream
        # (underscore) filename, so these replacements can't touch it.
        raw = raw.replace(f"- id: {c['old_id']}\n", f"- id: {c['new_id']}\n")
        if c["old_sp"] and c["new_sp"]:
            raw = raw.replace(
                f"  source_path: {c['old_sp']}\n",
                f"  source_path: {c['new_sp']}\n",
            )
    index_path.write_text(raw, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="report changes without modifying anything")
    args = ap.parse_args()

    root = repo_root()
    index_path = _index_path()
    index = yaml.safe_load(index_path.read_text(encoding="utf-8"))
    changes = plan_renames(index)

    if not changes:
        print("All reference ids are within the length cap; nothing to do.")
        return 0

    longest_after = max(len(c["new_id"]) for c in changes)
    print(f"{len(changes)} example id(s) exceed the cap and will be shortened "
          f"(longest new id: {longest_after} chars).")
    for c in changes[:10]:
        print(f"  {c['old_id'][:70]}… -> {c['new_id']}")
    if len(changes) > 10:
        print(f"  … and {len(changes) - 10} more")

    if args.check:
        print("\n--check: no changes written.")
        return 1

    apply_changes(root, index_path, changes)
    print(f"\nRewrote {index_path.relative_to(root)} and renamed vendored files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
