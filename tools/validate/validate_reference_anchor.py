#!/usr/bin/env python3
"""
Reference-anchor enforcement for generated preventive controls.

Preventive control generation is repo-anchored: every emitted preventive policy
artifact must trace to a known-good example in the reference index
(data/reference-repos/index.yaml). This validator proves that anchoring — it is
the gate that makes "we only generate when we can anchor to a reference"
checkable rather than aspirational.

Rule: every policy artifact under <slug>/05-generate/preventive/ MUST carry a
`_metadata.reference` whose `example_id` resolves to a real entry in the
reference index. An artifact with no resolvable anchor is a hard failure.

`_metadata.reference` shape (written by the preventive authoring sub-skills):

    "_metadata": {
      ...
      "reference": {
        "example_id": "service-control-policy-examples-deny-...",
        "repo": "service-control-policy-examples",
        "url": "https://github.com/aws-samples/.../blob/<sha>/<path>"
      }
    }

Exempt (no anchor required) — these emit no enforcing policy:
  - gap/skip stubs: _metadata.status == "NOT_APPLICABLE", or a *_gap note
    (scp_gap / rcp_gap / etc.) is present and the policy body is empty.
  - documentation-only files: compensating-controls-documentation.json.
  - non-JSON files (the policy artifacts under preventive/ are JSON).

CLI:
    python3 validate_reference_anchor.py <file>            # single artifact
    python3 validate_reference_anchor.py --slug <slug>     # whole preventive dir
Exit codes: 0 ok, 2 anchor violation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Reuse the shared index loader.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from reference_index import example_ids  # type: ignore
except Exception:  # pragma: no cover - import guard
    example_ids = None  # resolved lazily in _known_ids


# Files under preventive/ that are documentation, not enforcing policy.
_DOC_ONLY_BASENAMES = {
    "compensating-controls-documentation.json",
}


def _known_ids() -> set[str]:
    """Return the set of valid anchor ids, or empty set if index is absent.

    A missing index is itself a failure mode, but it is surfaced per-artifact
    (an artifact that claims an anchor we cannot resolve) rather than here, so
    the caller still gets a precise message.
    """
    if example_ids is None:
        return set()
    try:
        return example_ids()
    except FileNotFoundError:
        return set()


def _is_gap_or_stub(meta: dict, data: dict) -> bool:
    """True when the artifact is an explicit gap/skip stub (no policy emitted)."""
    status = str(meta.get("status", "")).upper()
    if status in {"NOT_APPLICABLE", "SKIPPED", "GAP"}:
        return True
    # *_gap note + empty statement body.
    has_gap_note = any(k.endswith("_gap") for k in meta)
    statements = data.get("Statement")
    body_empty = not statements  # None or []
    return has_gap_note and body_empty


def check_artifact(file_path: str, known_ids: set[str] | None = None) -> list[str]:
    """Validate one preventive artifact's reference anchor. Returns errors."""
    errors: list[str] = []
    basename = os.path.basename(file_path)
    if not basename.endswith(".json"):
        return errors
    if basename in _DOC_ONLY_BASENAMES:
        return errors

    try:
        with open(file_path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        # JSON syntax is validated elsewhere (CHECK-7); don't double-report.
        return errors
    if not isinstance(data, dict):
        return errors

    meta = data.get("_metadata")
    if not isinstance(meta, dict):
        errors.append(
            f"P8 reference_anchor: {basename} has no _metadata block — a "
            f"preventive artifact must carry a reference anchor."
        )
        return errors

    if _is_gap_or_stub(meta, data):
        return errors  # gap/skip stubs emit no policy; no anchor required

    reference = meta.get("reference")
    if not isinstance(reference, dict) or not reference.get("example_id"):
        errors.append(
            f"P8 reference_anchor: {basename} emits a preventive policy but "
            f"carries no _metadata.reference.example_id. Every preventive control "
            f"must anchor to a reference example in data/reference-repos/index.yaml "
            f"(or be a gap/skip stub). If no reference covers this objective, do not "
            f"author a policy — point to the reference or route to detective."
        )
        return errors

    ids = known_ids if known_ids is not None else _known_ids()
    example_id = reference["example_id"]
    if example_id not in ids:
        errors.append(
            f"P8 reference_anchor: {basename} references example_id "
            f"'{example_id}' which does not resolve to any entry in "
            f"data/reference-repos/index.yaml. The anchor must be a real, "
            f"current index id (rebuild the index or fix the reference)."
        )
    return errors


def check_service(service_root: Path) -> list[str]:
    """Validate every preventive artifact under a service root. Returns errors."""
    errors: list[str] = []
    prev_dir = service_root / "05-generate" / "preventive"
    if not prev_dir.is_dir():
        return errors
    ids = _known_ids()
    for fpath in sorted(prev_dir.glob("*.json")):
        errors.extend(check_artifact(str(fpath), ids))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="single artifact path")
    parser.add_argument("--slug", help="validate a service's preventive/ dir")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.file:
        errors = check_artifact(args.file)
    else:
        parser.error("provide a file path OR --slug")

    if errors:
        print(f"REFERENCE ANCHOR FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
