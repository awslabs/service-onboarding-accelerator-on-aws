#!/usr/bin/env python3
"""
Validate that the assembled control set carries no semantic duplicates.

map-assemble's Phase 0 collapses controls that share a canonical identity
(name + scope + category + mechanism + resource_types + actions + posture) into
one survivor. This validator is the count guard that proves the collapse held:
it re-derives the canonical key for every control in mapping-results.json and
fails if any two controls share it (i.e. a duplicate slipped through). It also
surfaces `distinct_controls` vs `total_controls` so Phase 6 reports the honest,
deduplicated count.

The canonical key is imported from scripts/map-assemble.py so this check can
never drift from the collapse logic it guards.

Advisory by default (warn, exit 0); --strict exits 2 on any duplicate so a run
can hard-gate the count.

CLI:
    python3 validate_control_dedup.py --slug <slug> [--strict]
    python3 validate_control_dedup.py <mapping-results.json> [--strict]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


def _load_canonical_key():
    """Load canonical_control_key from scripts/map-assemble.py (hyphenated name
    forces importlib). Falls back to a local definition if the script can't be
    loaded, so the validator still runs standalone."""
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "map-assemble.py"
    if script.exists():
        try:
            spec = importlib.util.spec_from_file_location("map_assemble", script)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module.canonical_control_key
        except Exception:
            pass

    def _fallback(ctrl: dict) -> tuple:
        return (
            " ".join((ctrl.get("name", "") or "").split()).lower(),
            ctrl.get("scope", ""),
            ctrl.get("category", ""),
            ctrl.get("mechanism", ""),
            tuple(sorted(ctrl.get("resource_types", []))),
            tuple(sorted(ctrl.get("actions", []))),
            ctrl.get("posture", ""),
        )

    return _fallback


canonical_control_key = _load_canonical_key()


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def check_dedup(mapping_results: dict) -> tuple[list[str], dict]:
    """Return (errors, stats). errors is empty when no canonical key repeats."""
    controls = mapping_results.get("controls", [])
    groups: dict[tuple, list[str]] = {}
    for ctrl in controls:
        groups.setdefault(canonical_control_key(ctrl), []).append(ctrl.get("id", "?"))

    errors: list[str] = []
    for key, ids in groups.items():
        if len(ids) > 1:
            name = key[0]
            errors.append(
                f"control-dedup: {len(ids)} controls share one canonical identity "
                f"(name={name!r}, scope={key[1]}, mechanism={key[3]}): "
                f"{', '.join(sorted(ids))} — collapse them to one control."
            )

    stats = {
        "total_controls": len(controls),
        "distinct_controls": len(groups),
        "duplicate_groups": sum(1 for ids in groups.values() if len(ids) > 1),
    }
    return errors, stats


def check_service(service_root: Path) -> tuple[list[str], dict]:
    mr_path = service_root / "04-map" / "mapping-results.json"
    if not mr_path.exists():
        return [], {"total_controls": 0, "distinct_controls": 0, "duplicate_groups": 0}
    return check_dedup(_load_json(mr_path))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mapping_results", nargs="?", help="path to mapping-results.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--strict", action="store_true", help="exit 2 on any duplicate")
    args = parser.parse_args()

    if args.slug:
        errors, stats = check_service(Path(os.getcwd()) / ".service-approval" / args.slug)
    elif args.mapping_results:
        errors, stats = check_dedup(_load_json(args.mapping_results))
    else:
        parser.error("provide a mapping-results.json path OR --slug")

    print(
        f"control-dedup: {stats['distinct_controls']} distinct / "
        f"{stats['total_controls']} total controls "
        f"({stats['duplicate_groups']} duplicate group(s))"
    )
    if errors:
        print(f"CONTROL DEDUP ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if args.strict:
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
