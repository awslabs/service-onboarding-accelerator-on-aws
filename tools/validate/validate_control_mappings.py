#!/usr/bin/env python3
"""
Mapping-accuracy cross-check against the AWS Control Catalog.

The pipeline's control→framework-objective mapping is the least deterministic
part of the run ("different every time, some don't make sense"). This validator
cross-checks each mapped framework objective against an authoritative external
source — the AWS Control Catalog (`ListControlMappings` / `ListControls`) — and
flags objectives with no catalog support as LOW-CONFIDENCE. It is advisory: it
WARNS, it does not block (exit 0 always, unless --strict).

Framework bridge: our default framework is CSA CCMv4, but the Control Catalog
exposes mappings to NIST 800-53, ISO 27001, PCI-DSS, etc. — not CCM directly. We
bridge CCMv4 objective → NIST 800-53 controls via the repo's crosswalk
(data/attack-nist-ccm-crosswalk.json) → catalog framework items. An objective is
"catalog-supported" when at least one AWS control in the catalog maps to a NIST
control the objective bridges to.

Catalog data source (no-hardcode rule): the catalog contents are NOT baked into
this file. They are read from an optional snapshot at
data/control-catalog-snapshot.json, refreshable from the live API with creds:

    python3 validate_control_mappings.py --refresh    # calls ListControlMappings (needs AWS creds)

When the snapshot is absent, the cross-check is SKIPPED honestly (the run is not
penalized for a missing optional input) — it does not invent catalog data.

Snapshot shape:
    {
      "_metadata": {"source": "controlcatalog:ListControlMappings", "fetched": "<iso>"},
      "framework_items": {              # framework name -> set of mapped item ids
        "NIST-800-53": ["AC-2", "AC-3", "SC-7", ...],
        "ISO-IEC-27001:2013-Annex-A": ["A.9.2.1", ...]
      }
    }

CLI:
    python3 validate_control_mappings.py --slug <slug>
    python3 validate_control_mappings.py --mapping <path> [--snapshot <path>] [--strict]
Exit codes: 0 advisory (default); 2 only with --strict when low-confidence found.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _repo_root() -> Path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from paths import repo_root  # type: ignore

    return repo_root()


def crosswalk_path() -> Path:
    return _repo_root() / "data" / "attack-nist-ccm-crosswalk.json"


def snapshot_path() -> Path:
    return _repo_root() / "data" / "control-catalog-snapshot.json"


def build_ccm_to_nist(crosswalk: dict) -> dict[str, set[str]]:
    """CCMv4 objective id -> set of NIST 800-53 control ids (via the crosswalk)."""
    out: dict[str, set[str]] = {}
    for m in crosswalk.get("mappings", []):
        nist = set(m.get("nist_controls", []))
        for ccm in m.get("ccmv4_objectives", []):
            out.setdefault(ccm, set()).update(nist)
    return out


def _nist_family(control_id: str) -> str:
    """`AC-2(1)` -> `AC-2`; `AC-2` -> `AC-2`. Catalog items use base ids."""
    base = control_id.split("(", 1)[0].strip()
    return base


def assess_mappings(
    mapping: dict, crosswalk: dict, snapshot: dict | None
) -> list[dict]:
    """Return a verdict per MAPPED framework objective.

    Verdicts: "CATALOG_SUPPORTED" | "LOW_CONFIDENCE" | "NO_BRIDGE".
      - CATALOG_SUPPORTED: bridges to a NIST control present in the catalog snapshot.
      - LOW_CONFIDENCE: bridges to NIST control(s) but none appear in the catalog.
      - NO_BRIDGE: the objective has no CCM->NIST crosswalk entry (cannot be
        cross-checked — reported separately, not counted as a failure).
    When snapshot is None, every objective is "SKIPPED" (no authoritative source).
    """
    ccm_to_nist = build_ccm_to_nist(crosswalk)
    # Flatten all catalog NIST items into a base-id set for membership tests.
    catalog_nist: set[str] = set()
    if snapshot:
        for fw, items in snapshot.get("framework_items", {}).items():
            if "NIST" in fw.upper() or "800-53" in fw:
                catalog_nist.update(_nist_family(i) for i in items)

    results: list[dict] = []
    for obj in mapping.get("framework_mapping", []):
        if obj.get("status") != "MAPPED":
            continue
        oid = obj.get("objective_id")
        nist = {_nist_family(c) for c in ccm_to_nist.get(oid, set())}
        entry = {
            "objective_id": oid,
            "bridged_nist_controls": sorted(nist),
            "control_ids": [c.get("control_id") for c in obj.get("controls", [])],
        }
        if snapshot is None:
            entry["verdict"] = "SKIPPED"
            entry["reason"] = "no catalog snapshot; run --refresh with AWS creds"
        elif not nist:
            entry["verdict"] = "NO_BRIDGE"
            entry["reason"] = (
                f"no CCMv4->NIST crosswalk entry for {oid}; cannot cross-check "
                f"against the Control Catalog"
            )
        elif nist & catalog_nist:
            entry["verdict"] = "CATALOG_SUPPORTED"
            entry["reason"] = (
                f"bridges to NIST control(s) {sorted(nist & catalog_nist)} present "
                f"in the Control Catalog"
            )
        else:
            entry["verdict"] = "LOW_CONFIDENCE"
            entry["reason"] = (
                f"bridges to NIST {sorted(nist)} but none appear in the Control "
                f"Catalog snapshot — mapping may be inaccurate; review"
            )
        results.append(entry)
    return results


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def refresh_snapshot(out_path: Path, fetched: str) -> None:
    """Fetch ListControlMappings from the live Control Catalog and write a snapshot.

    Requires AWS credentials. `fetched` is an ISO timestamp passed in by the
    caller (this module avoids wall-clock calls so it stays deterministic/testable).
    """
    import boto3  # imported here so the module loads without boto3 for tests

    client = boto3.client("controlcatalog")
    framework_items: dict[str, set[str]] = {}
    paginator = client.get_paginator("list_control_mappings")
    for page in paginator.paginate(Filter={"MappingTypes": ["FRAMEWORK"]}):
        for m in page.get("ControlMappings", []):
            fw = m.get("Mapping", {}).get("Framework", {})
            name, item = fw.get("Name"), fw.get("Item")
            if name and item:
                framework_items.setdefault(name, set()).add(item)
    snapshot = {
        "_metadata": {"source": "controlcatalog:ListControlMappings", "fetched": fetched},
        "framework_items": {k: sorted(v) for k, v in framework_items.items()},
    }
    out_path.write_text(json.dumps(snapshot, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--mapping", help="path to mapping-results.json")
    parser.add_argument("--snapshot", help="path to control-catalog snapshot json")
    parser.add_argument("--refresh", action="store_true", help="fetch live catalog snapshot (needs AWS creds)")
    parser.add_argument("--fetched", default="unknown", help="ISO timestamp to stamp on --refresh")
    parser.add_argument("--strict", action="store_true", help="exit 2 if any LOW_CONFIDENCE")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.refresh:
        refresh_snapshot(snapshot_path(), args.fetched)
        print(f"Wrote {snapshot_path()}")
        return

    if args.slug:
        mapping_path = args.mapping or (
            Path(os.getcwd()) / ".service-approval" / args.slug / "04-map" / "mapping-results.json"
        )
    elif args.mapping:
        mapping_path = args.mapping
    else:
        parser.error("provide --slug OR --mapping (or --refresh)")

    mapping = _load_json(mapping_path)
    crosswalk = _load_json(crosswalk_path())
    snap_path = Path(args.snapshot) if args.snapshot else snapshot_path()
    snapshot = _load_json(snap_path) if snap_path.exists() else None

    results = assess_mappings(mapping, crosswalk, snapshot)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        from collections import Counter

        counts = Counter(r["verdict"] for r in results)
        if snapshot is None:
            print(
                "Control Catalog snapshot absent — mapping cross-check SKIPPED.\n"
                "  Refresh with: python3 tools/validate/validate_control_mappings.py --refresh"
            )
        for verdict in ("LOW_CONFIDENCE", "NO_BRIDGE", "CATALOG_SUPPORTED", "SKIPPED"):
            n = counts.get(verdict, 0)
            if n:
                print(f"{verdict}: {n}")
        for r in results:
            if r["verdict"] == "LOW_CONFIDENCE":
                print(f"  ⚠ {r['objective_id']}: {r['reason']}")

    if args.strict and any(r["verdict"] == "LOW_CONFIDENCE" for r in results):
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
