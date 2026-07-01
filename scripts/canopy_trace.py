#!/usr/bin/env python3
"""Deterministic Canopy traceability resolver.

Canopy threat-model exports carry MITRE ATT&CK technique IDs on the *threat*
objects, not on the mitigations. Every mitigation links to the threats it
addresses, and every threat links to the frameworks (MITRE ATT&CK) it belongs
to. So a mitigation's MITRE techniques are recoverable by walking a two-hop
chain entirely inside the golden-source file — no external lookup:

    mitigation.mappings[type=="THREAT"].id
        -> threats[].id
            -> threat.mappings[type=="FRAMEWORK", frameworkName=="MITRE ATT&CK"].id

This module builds, per mitigation UUID, the traceability record
{alias, statement, mitre_techniques[], threat_aliases[]} and threads the
alias / UUID / MITRE techniques onto generated controls (additive fields).

Controls generated from synthetic assessment gaps (no Canopy mitigation
behind them) have no alias/UUID/MITRE — they carry empty arrays and a
`source: "assessment_gap"` marker rather than an error.

Usage:
    python3 scripts/canopy_trace.py <canopy-json> [--output <path>]
    python3 scripts/canopy_trace.py --slug <slug>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_MITRE_FRAMEWORK_NAME = "MITRE ATT&CK"


def _threats_by_id(canopy: dict[str, Any]) -> dict[str, dict]:
    """threat UUID -> threat entry."""
    out: dict[str, dict] = {}
    for t in canopy.get("threats", []) or []:
        if isinstance(t, dict) and t.get("id"):
            out[t["id"]] = t
    return out


def _threat_mitre_ids(threat: dict[str, Any]) -> list[str]:
    """MITRE ATT&CK technique ids on a single threat's FRAMEWORK mappings."""
    ids: list[str] = []
    for m in threat.get("mappings", []) or []:
        if not isinstance(m, dict):
            continue
        if m.get("type") == "FRAMEWORK" and m.get("frameworkName") == _MITRE_FRAMEWORK_NAME:
            tid = m.get("id")
            if isinstance(tid, str) and tid:
                ids.append(tid)
    return ids


def build_trace_index(canopy: dict[str, Any]) -> dict[str, dict]:
    """Build mitigation-UUID -> traceability record from a Canopy export.

    Each record:
      {
        "alias": <mitigation alias, e.g. Mitigation.LAMBDA.Function.1>,
        "statement": <full mitigation statement>,
        "mitre_techniques": [<sorted, de-duplicated MITRE ATT&CK ids>],
        "threat_aliases": [<sorted threat aliases the mitigation addresses>],
      }

    A mitigation with no THREAT mapping (or whose threats carry no MITRE
    FRAMEWORK mapping) yields empty lists — never a crash.
    """
    threats = _threats_by_id(canopy)
    index: dict[str, dict] = {}

    for mit in canopy.get("mitigations", []) or []:
        if not isinstance(mit, dict):
            continue
        uuid = mit.get("id")
        if not uuid:
            continue

        mitre: set[str] = set()
        threat_aliases: set[str] = set()
        for mp in mit.get("mappings", []) or []:
            if not isinstance(mp, dict) or mp.get("type") != "THREAT":
                continue
            threat = threats.get(mp.get("id"))
            if not threat:
                continue
            alias = threat.get("alias")
            if isinstance(alias, str) and alias:
                threat_aliases.add(alias)
            mitre.update(_threat_mitre_ids(threat))

        index[uuid] = {
            "alias": mit.get("alias", ""),
            "statement": mit.get("statement", ""),
            "mitre_techniques": sorted(mitre),
            "threat_aliases": sorted(threat_aliases),
        }

    return index


def build_alias_index(canopy: dict[str, Any]) -> dict[str, dict]:
    """Same records as build_trace_index but keyed by mitigation alias.

    Controls thread mitigation *aliases* (e.g. Mitigation.LAMBDA.Function.1)
    onto themselves via research-mitigations, so a by-alias lookup is what the
    control-threading step needs. Mitigations without an alias are skipped
    from this index (they are still present in the by-UUID index).
    """
    by_alias: dict[str, dict] = {}
    for uuid, rec in build_trace_index(canopy).items():
        alias = rec.get("alias")
        if alias:
            by_alias[alias] = {"mitigation_uuid": uuid, **rec}
    return by_alias


def thread_onto_control(control: dict[str, Any], alias_index: dict[str, dict]) -> dict[str, Any]:
    """Attach additive traceability fields to a single control in place.

    A control's `mitigation_alias`/`mitigation_uuid` (when set by
    research-mitigations from a Canopy source) resolve to the traceability
    record; the control gains:
      - mitigation_uuid, mitigation_alias  (the Canopy source identity)
      - mitre_techniques[]                 (union across the control's mitigations)
      - trace_source: "canopy" | "assessment_gap"

    A control with no resolvable Canopy alias (a synthetic assessment-gap
    control) gets empty MITRE + trace_source "assessment_gap" — never an error.
    The pre-existing `mitigation_ids[]` (M-<Resource>.N) are left untouched for
    backward compatibility.
    """
    aliases: list[str] = []
    # A control may carry a single alias or a list of them, plus we fall back
    # to any alias already stamped on the control by research-mitigations.
    for key in ("mitigation_aliases", "mitigation_alias"):
        val = control.get(key)
        if isinstance(val, list):
            aliases.extend(a for a in val if isinstance(a, str))
        elif isinstance(val, str) and val:
            aliases.append(val)

    mitre: set[str] = set()
    uuids: list[str] = []
    resolved_aliases: list[str] = []
    for alias in aliases:
        rec = alias_index.get(alias)
        if not rec:
            continue
        resolved_aliases.append(alias)
        if rec.get("mitigation_uuid"):
            uuids.append(rec["mitigation_uuid"])
        mitre.update(rec.get("mitre_techniques", []))

    if resolved_aliases:
        control["mitigation_alias"] = resolved_aliases[0]
        control["mitigation_aliases"] = sorted(set(resolved_aliases))
        control["mitigation_uuids"] = sorted(set(uuids))
        if uuids:
            control["mitigation_uuid"] = sorted(set(uuids))[0]
        control["mitre_techniques"] = sorted(mitre)
        control["trace_source"] = "canopy"
    else:
        # Synthetic / no-Canopy control: empty traceability, explicit marker.
        control.setdefault("mitre_techniques", [])
        control["trace_source"] = "assessment_gap"

    return control


def thread_controls(controls: list[dict], canopy: dict[str, Any]) -> list[dict]:
    """Thread traceability onto every control (in place) and return the list."""
    alias_index = build_alias_index(canopy)
    for ctrl in controls:
        if isinstance(ctrl, dict):
            thread_onto_control(ctrl, alias_index)
    return controls


def _load_json(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("canopy_json", nargs="?", help="Path to Canopy threat model JSON")
    parser.add_argument("--slug", help="Service slug (looks in .service-approval/<slug>/input/)")
    parser.add_argument("--output", "-o", help="Output path (default: stdout JSON)")
    args = parser.parse_args()

    if args.slug:
        input_dir = Path.cwd() / ".service-approval" / args.slug / "input"
        candidates = [p for p in input_dir.glob("*.json")] if input_dir.exists() else []
        if not candidates:
            print(f"SKIP: no JSON files in {input_dir}", file=sys.stderr)
            sys.exit(0)
        canopy_path = candidates[0]
        output_path: Path | None = (
            Path.cwd() / ".service-approval" / args.slug / "04-map" / "canopy-trace.json"
        )
    elif args.canopy_json:
        canopy_path = Path(args.canopy_json)
        output_path = Path(args.output) if args.output else None
    else:
        parser.error("Provide a Canopy JSON path or --slug")
        return

    if not canopy_path.exists():
        print(f"ERROR: file not found: {canopy_path}", file=sys.stderr)
        sys.exit(1)

    canopy = _load_json(canopy_path)
    index = build_trace_index(canopy)
    resolved = sum(1 for r in index.values() if r["mitre_techniques"])
    result = {
        "schema_version": "1.0",
        "source_file": canopy_path.name,
        "mitigation_count": len(index),
        "mitigations_with_mitre": resolved,
        "trace": index,
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print(
            f"Canopy trace written: {output_path}\n"
            f"  Mitigations: {len(index)}\n"
            f"  With >=1 MITRE technique: {resolved}",
            file=sys.stderr,
        )
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
