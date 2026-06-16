#!/usr/bin/env python3
"""
Reader for the reference-repo anchor index (data/reference-repos/index.yaml).

The index is built by tools/post-process/build_reference_index.py. Skills and
validators read it through this module so the load/lookup logic lives in one
place. Preventive controls anchor to entries here; an artifact that claims a
reference (`_metadata.reference`) must resolve to an example id present in the
index (enforced by validate_reference_anchor.py).
"""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    print("PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    raise


ALLOWED_MECHANISMS = {
    "SCP",
    "RCP",
    "IAM",
    "permission-boundary",
    "data-perimeter",
    "VPCE",
}


def _repo_root() -> Path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from paths import repo_root  # type: ignore

    return repo_root()


def index_path() -> Path:
    return _repo_root() / "data" / "reference-repos" / "index.yaml"


@lru_cache(maxsize=4)
def _load_cached(path_str: str, mtime: float) -> dict:
    return yaml.safe_load(Path(path_str).read_text(encoding="utf-8")) or {}


def load_index(path: Path | None = None) -> dict:
    """Load and return the full index dict. Cached on (path, mtime).

    Raises FileNotFoundError if the index has not been built.
    """
    p = path or index_path()
    if not p.exists():
        raise FileNotFoundError(
            f"reference index not found at {p}; run "
            f"tools/post-process/build_reference_index.py --repos-dir <clones>"
        )
    return _load_cached(str(p), p.stat().st_mtime)


def examples(path: Path | None = None) -> list[dict]:
    return load_index(path).get("examples", [])


def example_ids(path: Path | None = None) -> set[str]:
    """Return the set of all anchor ids the pipeline may reference."""
    return {e["id"] for e in examples(path) if "id" in e}


def get_example(example_id: str, path: Path | None = None) -> dict | None:
    """Return the index entry for an example id, or None if absent."""
    for e in examples(path):
        if e.get("id") == example_id:
            return e
    return None


def examples_for_mechanism(mechanism: str, path: Path | None = None) -> list[dict]:
    """Return all anchor entries for a given mechanism (SCP/RCP/IAM/...)."""
    return [e for e in examples(path) if e.get("mechanism") == mechanism]
