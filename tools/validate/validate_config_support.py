#!/usr/bin/env python3
"""
Config-supportability gate for detective Config rules.

Some services/resources are not recordable by AWS Config, so a Config rule for
them is a no-op. This validator proves that every emitted Config-rule artifact
targets a resource type AWS Config actually supports — the deterministic gate
that makes "we never emit a Config rule for an unsupported type" checkable.

Source of truth: data/config-supported-resource-types.json (built by
tools/post-process/build_config_supported_types.py from the botocore config
`ResourceType` enum unioned with doc-confirmed additions from the public AWS
Config "Supported Resource Types" reference).

Rule: for every Config-rule artifact under
<slug>/05-recommended-guidance/detective/ (config-rules.json,
config-org-rules.json — files carrying a `rules[]` array whose entries name a
`resource_type`), each rule's `resource_type` MUST be in the supported set. A
Config rule targeting an unsupported type is a hard failure — route that control
to CloudTrail/EventBridge or record a reasoned gap instead.

Rules with no `resource_type` (e.g. periodic account-level rules that evaluate
API state, not a recorded CI) are not gated — there is no CI type to check.

CLI:
    python3 validate_config_support.py --slug <slug>            # gate a service
    python3 validate_config_support.py --slug <slug> --json     # machine output
    python3 validate_config_support.py --resource-type AWS::DSQL::Cluster
                                                                # single lookup
Exit codes: 0 supported/no-op, 2 an emitted Config rule targets an unsupported type.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from .artifact_rules import iter_rules, resource_types
except ImportError:
    from artifact_rules import iter_rules, resource_types

_DATA_FILE = (
    Path(__file__).resolve().parents[2] / "data" / "config-supported-resource-types.json"
)

# Config-rule artifact basenames the gate inspects (files with a rules[] array).
_CONFIG_RULE_BASENAMES = {"config-rules.json", "config-org-rules.json"}


def load_supported_types(path: Path | None = None) -> set[str]:
    """Return the set of Config-supported CFN resource types.

    A missing data file is a broken install — fail loudly rather than silently
    passing every type (which would defeat the gate).
    """
    p = path or _DATA_FILE
    with open(p) as fh:
        data = json.load(fh)
    supported = data.get("supported", [])
    return {t for t in supported if isinstance(t, str)}


def is_config_supported(resource_type: str, supported: set[str] | None = None) -> bool:
    """True when a CFN resource type is recordable by AWS Config."""
    types = supported if supported is not None else load_supported_types()
    return resource_type in types


def _iter_config_rules(artifact: dict):
    """Yield (rule_name, resource_type) for each rule entry that names a type.

    A Config-rule artifact carries a top-level `rules[]` array; each entry may
    carry a `resource_type`. Entries without one (periodic API-state rules) are
    skipped — there is no recorded CI type to gate.
    """
    for name, rule in iter_rules(artifact):
        for resource_type in resource_types(rule):
            yield name, resource_type


def check_artifact(file_path: str, supported: set[str] | None = None) -> list[dict]:
    """Return one result dict per Config rule in the artifact.

    Each result: {artifact, rule_name, resource_type, status: SUPPORTED|UNSUPPORTED}.
    Non-Config-rule files and gap/skip stubs yield no results.
    """
    basename = os.path.basename(file_path)
    if basename not in _CONFIG_RULE_BASENAMES:
        return []
    try:
        with open(file_path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    meta = data.get("_metadata") or {}
    if str(meta.get("status", "")).upper() in {"NOT_APPLICABLE", "SKIPPED", "GAP"}:
        return []

    types = supported if supported is not None else load_supported_types()
    results: list[dict] = []
    for rule_name, rt in _iter_config_rules(data):
        results.append(
            {
                "artifact": basename,
                "rule_name": rule_name,
                "resource_type": rt,
                "status": "SUPPORTED" if rt in types else "UNSUPPORTED",
            }
        )
    return results


def check_service(service_root: Path, supported: set[str] | None = None) -> list[dict]:
    """Return the per-rule Config-support results for a service's detective dir."""
    types = supported if supported is not None else load_supported_types()
    results: list[dict] = []
    det_dir = service_root / "05-recommended-guidance" / "detective"
    if not det_dir.is_dir():
        return results
    for basename in sorted(_CONFIG_RULE_BASENAMES):
        fpath = det_dir / basename
        if fpath.is_file():
            results.extend(check_artifact(str(fpath), types))
    return results


def _unsupported(results: list[dict]) -> list[dict]:
    return [r for r in results if r["status"] == "UNSUPPORTED"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("file", nargs="?", help="single Config-rule artifact path")
    parser.add_argument(
        "--resource-type", help="check a single CFN resource type and exit"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON results")
    args = parser.parse_args()

    supported = load_supported_types()

    # Single-type lookup — used by the detective skill as a pre-generation probe.
    if args.resource_type:
        ok = is_config_supported(args.resource_type, supported)
        if args.json:
            print(json.dumps({"resource_type": args.resource_type,
                              "status": "SUPPORTED" if ok else "UNSUPPORTED"}))
        else:
            print(f"{'SUPPORTED' if ok else 'UNSUPPORTED'} {args.resource_type}")
        sys.exit(0 if ok else 2)

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        results = check_service(root, supported)
    elif args.file:
        results = check_artifact(args.file, supported)
    else:
        parser.error("provide --slug, a file path, or --resource-type")

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['status']:12} {r['resource_type']:40} {r['rule_name']}")

    unsupported = _unsupported(results)
    if unsupported:
        print(
            f"\nCONFIG SUPPORT FAILED: {len(unsupported)} Config rule(s) target a "
            f"resource type AWS Config does not support — route to "
            f"CloudTrail/EventBridge or record a reasoned gap:",
            file=sys.stderr,
        )
        for r in unsupported:
            print(
                f"  {r['artifact']} rule '{r['rule_name']}': AWS Config does not "
                f"support {r['resource_type']}",
                file=sys.stderr,
            )
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
