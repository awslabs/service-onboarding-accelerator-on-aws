#!/usr/bin/env python3
"""
Validate the preventive→detective routing hand-off.

When the preventive root-cause critic finds an objective that is NOT_PREVENTABLE
(no condition key gates the target action), it must not author a non-firing SCP —
it routes the objective to a detective control instead. That routing is recorded
in detective-routing.json, and the detective generator must actually cover each
routed entry. This validator closes the loop:

  1. Schema (detective-routing.schema.json) — shape + control-id pattern.
  2. Coverage — every routed entry must have a non-empty `covered_by`, and each
     named detective artifact must exist on disk under 05-recommended-guidance/detective/ or
     05-recommended-guidance/responsive/.

Advisory by default (warn, exit 0); --strict exits 2 on an uncovered routed
objective so a run can hard-gate the hand-off once detective coverage is mature.

CLI:
    python3 validate_detective_routing.py --slug <slug> [--strict]
    python3 validate_detective_routing.py <routing.json> [--generate-dir <dir>] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _covered_files(entry: dict) -> list[str]:
    cb = entry.get("covered_by")
    if not cb:
        return []
    return [cb] if isinstance(cb, str) else list(cb)


def check_routing(routing: dict, generate_dir: Path | None) -> list[str]:
    """Validate the routing doc. Returns error strings (empty = clean).

    `generate_dir` is the 05-recommended-guidance/ directory; when provided, covered_by
    filenames are checked for existence under detective/ or responsive/.
    """
    errors: list[str] = []

    # Schema layer.
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from _schemas import schema_errors  # type: ignore

        errors.extend(schema_errors(routing, "detective-routing"))
    except ImportError:
        pass
    if errors:
        return errors

    for entry in routing.get("routed", []):
        cid = entry.get("control_id")
        files = _covered_files(entry)
        if not files:
            errors.append(
                f"detective-routing: {cid} is routed to detective but has no "
                f"covered_by — the detective generator did not produce coverage "
                f"for this objective. Generate a detective control for it."
            )
            continue
        if generate_dir is not None:
            for fname in files:
                # Accept a bare filename or a path relative to 05-recommended-guidance/.
                candidates = [
                    generate_dir / fname,
                    generate_dir / "detective" / fname,
                    generate_dir / "responsive" / fname,
                ]
                if not any(c.exists() for c in candidates):
                    errors.append(
                        f"detective-routing: {cid} covered_by '{fname}' but no such "
                        f"artifact exists under detective/ or responsive/."
                    )
    return errors


def check_service(service_root: Path) -> list[str]:
    """Validate a service's detective-routing.json (no-op if absent)."""
    routing_path = service_root / "05-recommended-guidance" / "detective-routing.json"
    if not routing_path.exists():
        return []  # routing is only present when objectives were routed
    routing = _load_json(routing_path)
    return check_routing(routing, service_root / "05-recommended-guidance")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routing", nargs="?", help="path to detective-routing.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--generate-dir", help="05-recommended-guidance dir (for coverage existence checks)")
    parser.add_argument("--strict", action="store_true", help="exit 2 on uncovered routed objective")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.routing:
        gdir = Path(args.generate_dir) if args.generate_dir else None
        errors = check_routing(_load_json(args.routing), gdir)
    else:
        parser.error("provide a routing path OR --slug")

    if errors:
        print(f"DETECTIVE ROUTING ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if args.strict:
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
