#!/usr/bin/env python3
"""Deterministic AWS Threat Model traceability resolver.

AWS Threat Model threat-model exports carry MITRE ATT&CK technique IDs on the *threat*
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

Controls generated from synthetic assessment gaps (no AWS Threat Model mitigation
behind them) have no alias/UUID/MITRE — they carry empty arrays and a
`source: "assessment_gap"` marker rather than an error.

Usage:
    python3 scripts/threat_model_trace.py <threat-model-json> [--output <path>]
    python3 scripts/threat_model_trace.py --slug <slug>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from tools import paths
except ImportError:
    print("ERROR: tools.paths module not found. Run from the repo root with the "
          "project venv.", file=sys.stderr)
    sys.exit(1)

_MITRE_FRAMEWORK_NAME = "MITRE ATT&CK"


def _threats_by_id(threat_model: dict[str, Any]) -> dict[str, dict]:
    """threat UUID -> threat entry."""
    out: dict[str, dict] = {}
    for t in threat_model.get("threats", []) or []:
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


def build_trace_index(threat_model: dict[str, Any]) -> dict[str, dict]:
    """Build mitigation-UUID -> traceability record from an AWS Threat Model export.

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
    threats = _threats_by_id(threat_model)
    index: dict[str, dict] = {}

    for mit in threat_model.get("mitigations", []) or []:
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


def build_alias_index(threat_model: dict[str, Any]) -> dict[str, dict]:
    """Same records as build_trace_index but keyed by mitigation alias.

    Controls thread mitigation *aliases* (e.g. Mitigation.LAMBDA.Function.1)
    onto themselves via research-mitigations, so a by-alias lookup is what the
    control-threading step needs. Mitigations without an alias are skipped
    from this index (they are still present in the by-UUID index).
    """
    by_alias: dict[str, dict] = {}
    for uuid, rec in build_trace_index(threat_model).items():
        alias = rec.get("alias")
        if alias:
            by_alias[alias] = {"mitigation_uuid": uuid, **rec}
    return by_alias


def thread_onto_control(control: dict[str, Any], alias_index: dict[str, dict]) -> dict[str, Any]:
    """Attach additive traceability fields to a single control in place.

    A control's `mitigation_alias`/`mitigation_uuid` (when set by
    research-mitigations from an AWS Threat Model source) resolve to the traceability
    record; the control gains:
      - mitigation_uuid, mitigation_alias  (the AWS Threat Model source identity)
      - mitre_techniques[]                 (union across the control's mitigations)
      - trace_source: "threat_model" | "assessment_gap"

    A control with no resolvable AWS Threat Model alias (a synthetic assessment-gap
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
    statement_by_alias: dict[str, str] = {}
    for alias in aliases:
        rec = alias_index.get(alias)
        if not rec:
            continue
        resolved_aliases.append(alias)
        if rec.get("mitigation_uuid"):
            uuids.append(rec["mitigation_uuid"])
        mitre.update(rec.get("mitre_techniques", []))
        if rec.get("statement"):
            statement_by_alias[alias] = rec["statement"]

    if resolved_aliases:
        control["mitigation_alias"] = resolved_aliases[0]
        control["mitigation_aliases"] = sorted(set(resolved_aliases))
        control["mitigation_uuids"] = sorted(set(uuids))
        if uuids:
            control["mitigation_uuid"] = sorted(set(uuids))[0]
        control["mitre_techniques"] = sorted(mitre)
        # Verbatim AWS Threat Model statement of the primary mitigation, so a downstream
        # citation can quote it and be provenance-checked against the export.
        primary_stmt = statement_by_alias.get(control["mitigation_alias"], "")
        if primary_stmt:
            control["mitigation_statement"] = primary_stmt
        control["trace_source"] = "threat_model"
    else:
        # Synthetic / no-AWS Threat Model control: empty traceability, explicit marker.
        control.setdefault("mitre_techniques", [])
        control["trace_source"] = "assessment_gap"

    return control


def thread_controls(controls: list[dict], threat_model: dict[str, Any]) -> list[dict]:
    """Thread traceability onto every control (in place) and return the list."""
    alias_index = build_alias_index(threat_model)
    for ctrl in controls:
        if isinstance(ctrl, dict):
            thread_onto_control(ctrl, alias_index)
    return controls


def _load_json(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("threat_model_json", nargs="?", help="Path to AWS Threat Model threat model JSON")
    parser.add_argument("--slug", help="Service slug (looks in .service-approval/<slug>/input/)")
    parser.add_argument("--output", "-o", help="Output path (default: stdout JSON)")
    args = parser.parse_args()

    if args.slug:
        try:
            svc_root = paths.service_root(args.slug)
        except paths.PathResolutionError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(2)
        input_dir = svc_root / "input"
        candidates = [p for p in input_dir.glob("*.json")] if input_dir.exists() else []
        if not candidates:
            print(f"SKIP: no JSON files in {input_dir}", file=sys.stderr)
            sys.exit(0)
        threat_model_path = candidates[0]
        output_path: Path | None = svc_root / "04-map" / "threat-model-trace.json"
    elif args.threat_model_json:
        threat_model_path = Path(args.threat_model_json)
        output_path = Path(args.output) if args.output else None
    else:
        parser.error("Provide an AWS Threat Model JSON path or --slug")
        return

    if not threat_model_path.exists():
        print(f"ERROR: file not found: {threat_model_path}", file=sys.stderr)
        sys.exit(1)

    threat_model = _load_json(threat_model_path)
    index = build_trace_index(threat_model)
    resolved = sum(1 for r in index.values() if r["mitre_techniques"])
    result = {
        "schema_version": "1.0",
        "source_file": threat_model_path.name,
        "mitigation_count": len(index),
        "mitigations_with_mitre": resolved,
        "trace": index,
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(result, fh, indent=2)
        print(
            f"AWS Threat Model trace written: {output_path}\n"
            f"  Mitigations: {len(index)}\n"
            f"  With >=1 MITRE technique: {resolved}",
            file=sys.stderr,
        )
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
