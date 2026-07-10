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


# Mechanisms that the recommender groups under one anchor family. A control's
# mapping mechanism maps to one or more index mechanisms to search.
#
# Keys MUST match the mechanism strings map-generate-controls actually emits
# (see its mechanism enum): "SCP", "RCP", "IAM Policy", "IAM Trust Policy",
# "IAM Permission Boundary", "Resource Policy", "VPC Endpoint Policy",
# "KMS Key Policy". Matching is case-insensitive and tolerant of a few common
# aliases so a minor upstream wording change doesn't silently drop a control to
# REFER_TO_REFERENCE. Index mechanism values are the families in the reference
# index: SCP, RCP, IAM, permission-boundary, data-perimeter, VPCE.
_MECHANISM_FAMILIES = {
    "scp": ["SCP"],
    "rcp": ["RCP"],
    "iam policy": ["IAM"],
    # Trust policies are REFER-ONLY (see REFER_ONLY_MECHANISMS below): there is
    # no vetted trust-policy example library, and the confused-deputy patterns
    # they implement are documented per-service. mechanism_family() returns an
    # empty family for them, so rank_anchors/best_anchor never resolve a repo
    # anchor — the recommender must emit REFER_TO_REFERENCE with a service-doc
    # citation. Mapping a trust policy to the IAM identity-policy family (its
    # old behavior) stamped it with an unrelated access-check example anchor —
    # an incoherent shape — which is exactly what this prevents.
    "iam trust policy": [],
    "trust policy": [],
    # Permission boundaries anchor ONLY to the curated permission-boundary
    # example set, never to the much larger IAM (identity-policy) family. A
    # boundary is a structural scaffold (a scoped Allow allowlist plus the
    # Denies that enforce the control); pulling its body from an
    # identity-policy access-check example is the wrong shape. See
    # PERMISSION_BOUNDARY_FAMILY below for why this family bypasses the
    # zero-overlap anchor gate.
    "iam permission boundary": ["permission-boundary"],
    "permission boundary": ["permission-boundary"],
    "resource policy": ["IAM", "data-perimeter"],
    "resource-based policy": ["IAM", "data-perimeter"],
    "vpc endpoint policy": ["VPCE", "data-perimeter"],
    "vpce policy": ["VPCE", "data-perimeter"],
    "kms key policy": ["IAM"],
}

# The permission-boundary example set is a small, curated collection of
# structural boundary scaffolds (aws-samples/example-permissions-boundary).
# Unlike SCP/RCP/IAM examples — which must overlap the control's actions or
# condition keys to be a meaningful anchor — a boundary scaffold legitimately
# shares few or no actions with any single control: its actions are supplied
# by the target service, and the example contributes the *shape* (scoped Allow
# allowlist + wildcard-only reads + enforcing Denies). So for this family we
# accept the top-ranked example even at a zero overlap score, rather than
# returning None and dropping the control to REFER_TO_REFERENCE.
PERMISSION_BOUNDARY_FAMILY = "permission-boundary"

# Mechanisms that are REFER-ONLY: the tool never authors a policy body for them
# and never resolves a repo anchor — it points the customer at the relevant AWS
# documentation pattern instead. Trust policies live here because there is no
# vetted trust-policy example library; the cross-service confused-deputy
# prevention they implement is documented per-service (the aws:SourceArn /
# aws:SourceAccount condition pattern). Keys are the lowercased mechanism
# strings map-generate-controls emits.
REFER_ONLY_MECHANISMS = frozenset({"iam trust policy", "trust policy"})


def is_refer_only(control_mechanism: str) -> bool:
    """True if `control_mechanism` is refer-only (never authored / anchored)."""
    return (control_mechanism or "").strip().lower() in REFER_ONLY_MECHANISMS


def mechanism_family(control_mechanism: str) -> list[str]:
    """Map a control's mapping mechanism to the index mechanism(s) to search.

    Lookup is case-insensitive on the mechanism string. Falls back to treating
    the mechanism string itself as an index mechanism so an exact-match
    mechanism (e.g. "SCP") still works without a family entry.
    """
    key = (control_mechanism or "").strip().lower()
    return _MECHANISM_FAMILIES.get(key, [control_mechanism])


def _bare_action(action: str) -> str:
    """`s3:DeleteBucket` -> `deletebucket`; tolerant, case-insensitive."""
    a = action.split(":", 1)[1] if ":" in action else action
    return a.strip().lower().rstrip("*")


def _norm_key(key: str) -> str:
    return key.strip().lower()


def score_example(example: dict, actions: list[str], condition_keys: list[str]) -> float:
    """Score one reference example against a control's actions + condition keys.

    Condition-key overlap is the stronger signal (an example that uses the same
    gating key is a closer structural match), so it is weighted 2x action
    overlap. Score is the weighted Jaccard-style overlap, in [0, 1+]. Higher is
    a better anchor. Action matching is on bare operation names (case-insensitive,
    trailing-wildcard-stripped) so cross-service prefixes don't block a match.
    """
    ex_actions = {_bare_action(a) for a in example.get("governed_actions", [])}
    ex_keys = {_norm_key(k) for k in example.get("condition_keys", [])}
    c_actions = {_bare_action(a) for a in actions}
    c_keys = {_norm_key(k) for k in condition_keys}

    action_overlap = len(ex_actions & c_actions)
    key_overlap = len(ex_keys & c_keys)

    # Normalize by the control's own counts so a small focused example that
    # covers the control's actions/keys scores well, not penalized for the
    # example's breadth.
    action_score = action_overlap / len(c_actions) if c_actions else 0.0
    key_score = key_overlap / len(c_keys) if c_keys else 0.0
    return round(2 * key_score + action_score, 4)


def rank_anchors(
    control_mechanism: str,
    actions: list[str],
    condition_keys: list[str],
    path: Path | None = None,
) -> list[dict]:
    """Rank reference examples as anchor candidates for a control.

    Returns a list of {example, score} dicts sorted by score descending (ties
    broken by example id for determinism), restricted to the control's mechanism
    family. An empty list means no example in the family — the recommender should
    emit REFER_TO_REFERENCE for the control. A best score of 0.0 means the family
    has examples but none overlap the control's actions/keys — still a weak
    anchor; the recommender should treat 0.0 as "no real anchor".
    """
    families = set(mechanism_family(control_mechanism))
    candidates = [e for e in examples(path) if e.get("mechanism") in families]
    scored = [
        {"example": e, "score": score_example(e, actions, condition_keys)}
        for e in candidates
    ]
    scored.sort(key=lambda s: (-s["score"], s["example"].get("id", "")))
    return scored


def best_anchor(
    control_mechanism: str,
    actions: list[str],
    condition_keys: list[str],
    path: Path | None = None,
) -> dict | None:
    """Return the single best anchor example for a control, or None.

    None when the mechanism family has no examples OR the best score is 0.0
    (no overlap) — in both cases the recommender must NOT claim an anchor.

    Exception: the permission-boundary family is a curated set of structural
    scaffolds whose actions come from the target service, so a zero overlap
    score is expected and still a valid anchor (see PERMISSION_BOUNDARY_FAMILY).
    """
    ranked = rank_anchors(control_mechanism, actions, condition_keys, path)
    if not ranked:
        return None
    families = set(mechanism_family(control_mechanism))
    if families == {PERMISSION_BOUNDARY_FAMILY}:
        # Curated boundary scaffolds — accept the top rank even at score 0.0.
        return ranked[0]["example"]
    if ranked[0]["score"] <= 0.0:
        return None
    return ranked[0]["example"]
