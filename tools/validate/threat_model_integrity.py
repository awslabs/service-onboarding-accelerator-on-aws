"""Deterministic source-defect reporting, identity repair, and source accounting.

Source findings and honest coverage gaps are advisory. Invalid/mutated source
bytes fail the prerequisite. Missing/stale disclosure or generated identity errors
fail reporting checks; merely finding defects in the source never fails them.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

SECTIONS = {"ENTITY": "entities", "THREAT": "threats", "MITIGATION": "mitigations", "IMPLEMENTATION": "implementations"}
BEGIN = "<!-- threat-model-integrity:start -->"
END = "<!-- threat-model-integrity:end -->"
STATE_FILES = (
    "02-research/threat-model-index.json",
    "02-research/research-mitigations.json", "02-research/research.json",
    "03-validate/validated.json", "04-map/map-controls-generated.json",
    "04-map/map-framework-mapped.json", "04-map/mapping-results.json",
    "05-recommended-guidance/preventive-plan.json",
)
REPORT_FILES = ("04-map/controls-catalog.md", "04-map/framework-mapping.md", "06-summarize/SUMMARY-REPORT.md")


def rows(data, key):
    value = data.get(key, []) if isinstance(data, dict) else []
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def unique_mitigations(model):
    """Never guess a mapping for a duplicate source alias or UUID."""
    mits = rows(model, "mitigations")
    aliases = Counter(m.get("alias") for m in mits)
    ids = Counter(m.get("id") for m in mits)
    return {m["alias"]: m for m in mits if m.get("alias") and m.get("id")
            and aliases[m["alias"]] == 1 and ids[m["id"]] == 1}


def control_aliases(control):
    aliases = set(a for a in control.get("mitigation_aliases", []) if isinstance(a, str))
    if isinstance(control.get("mitigation_alias"), str):
        aliases.add(control["mitigation_alias"])
    aliases.update(r["alias"] for r in rows(control, "mitigation_references") if isinstance(r.get("alias"), str))
    return sorted(aliases)


def finding(check, record, detail, *, stage="source", owner="AWS Threat Model author", uuid="", target="", aliases=(), controls=(), repaired=False):
    key = json.dumps([check, stage, record, uuid, target, detail], ensure_ascii=True)
    return {"id": "TM-" + hashlib.sha256(key.encode()).hexdigest()[:16],
            "check": check, "record": record, "source_uuid": uuid, "target": target,
            "detail": detail, "stage": stage, "owner": owner,
            "mitigation_aliases": sorted(set(aliases)), "affected_controls": sorted(set(controls)),
            "auto_fixed": repaired}


def source_findings(model, source):
    """Check only internal relationships; catalog/FRAMEWORK links are external."""
    out = []
    ids = {kind: {r.get("id") for r in rows(model, section) if isinstance(r.get("id"), str)} for kind, section in SECTIONS.items()}
    mits = rows(model, "mitigations")

    def impacted(kind, row):
        if kind == "MITIGATION":
            return [row.get("alias", "")]
        result = {m.get("alias", "") for m in mits if any(
            link.get("type") == kind and link.get("id") == row.get("id") for link in rows(m, "mappings"))}
        if kind == "IMPLEMENTATION":
            linked = {link.get("id") for link in rows(row, "mappings") if link.get("type") == "MITIGATION"}
            result.update(m.get("alias", "") for m in mits if m.get("id") in linked)
        return sorted(result - {""})

    for kind, section in SECTIONS.items():
        records = rows(model, section)
        for field in ("id", "alias"):
            counts = Counter(r.get(field) for r in records if isinstance(r.get(field), str) and r[field])
            for value, count in sorted(counts.items()):
                if count > 1:
                    affected = {a for r in records if r.get(field) == value for a in impacted(kind, r)}
                    out.append(finding("duplicate_identity", value, f"{section}: {count} records share {field}; identity is ambiguous.", aliases=affected))
        for row in records:
            alias = row.get("alias") or row.get("id", section)
            affected = impacted(kind, row)
            for link in rows(row, "mappings"):
                target_kind = link.get("type")
                if isinstance(target_kind, str) and target_kind in ids and (not isinstance(link.get("id"), str) or link["id"] not in ids[target_kind]):
                    out.append(finding("broken_reference", alias,
                        f"{target_kind} reference does not resolve in the saved model; related coverage cannot be inferred.",
                        uuid=row.get("id", ""), target=str(link.get("id", "")), aliases=affected))
            if (kind != "ENTITY" and row.get("alias") and source.get("report_status", "verified") == "verified"
                    and row["alias"] not in source.get("report_aliases", [])):
                out.append(finding("missing_report_anchor", alias, "No verified heading for this alias in the readable report.",
                                   uuid=row.get("id", ""), aliases=affected))
    if source.get("report_status") == "unavailable":
        out.append(finding("readable_report_unavailable", source.get("namespace", "service"),
                           source.get("report_error") or "Readable report unavailable; use the saved JSON source.",
                           aliases=[m.get("alias", "") for m in mits]))
    return sorted(out, key=lambda f: f["id"])


def repair_control_identity(control, model, *, stage="map"):
    """Canonicalize unique alias/UUID pairs, preserving an explicitly chosen primary."""
    index = unique_mitigations(model)
    aliases = control_aliases(control)
    if not aliases:
        return []
    known = [a for a in aliases if a in index]
    primary = control.get("mitigation_alias")
    if not primary:
        primary = known[0] if known else aliases[0]
    expected = {"mitigation_references": [{"alias": a, "uuid": index[a]["id"]} for a in known],
                "mitigation_aliases": aliases, "mitigation_uuids": [index[a]["id"] for a in known],
                "mitigation_alias": primary, "trace_source": "threat_model"}
    if primary in index:
        expected["mitigation_uuid"] = index[primary]["id"]
        expected["mitigation_statement"] = index[primary].get("statement", "")
    repairs = []
    for key, value in expected.items():
        if key in control and control[key] != value:
            repairs.append(finding("identity_repaired", primary,
                f"Corrected {key} from {json.dumps(control[key], sort_keys=True)} to {json.dumps(value, sort_keys=True)}.",
                stage=stage, owner="Service Approval", aliases=known, controls=[control.get("id", "")], repaired=True))
        control[key] = value
    if primary not in index:
        # Ambiguous source identities must not retain a misleading prior UUID.
        control.pop("mitigation_uuid", None)
        control.pop("mitigation_statement", None)
    return repairs


def repair_citations(document, model, *, stage="map"):
    """Repair UUID fields only when the cited alias unambiguously identifies a source row."""
    index = unique_mitigations(model)
    repairs = []
    def walk(obj, control_id=""):
        if isinstance(obj, list):
            for item in obj: walk(item, control_id)
        elif isinstance(obj, dict):
            cid = obj.get("control_id") or obj.get("id") or control_id
            cit = obj.get("citation")
            if isinstance(cit, dict) and (cit.get("source") == "threat_model" or cit.get("type") == "threat_model"):
                alias = cit.get("mitigation_alias") or cit.get("id")
                if alias in index:
                    expected = index[alias]["id"]
                    if cit.get("mitigation_uuid") not in (None, expected):
                        repairs.append(finding("identity_repaired", alias,
                            f"Corrected citation UUID from {cit['mitigation_uuid']} to {expected}.",
                            stage=stage, owner="Service Approval", aliases=[alias], controls=[cid], repaired=True))
                    cit["mitigation_uuid"] = expected
            for value in obj.values(): walk(value, cid)
    walk(document)
    return repairs


def valid_disposition(row):
    return (isinstance(row, dict) and row.get("status") in ("manual_guidance", "not_applicable", "unresolved")
            and isinstance(row.get("rationale"), str) and bool(row["rationale"].strip())
            and (row.get("status") != "manual_guidance" or
                 isinstance(row.get("guidance"), str) and bool(row["guidance"].strip())))


def disposition_errors(dispositions, model, normalized=None):
    index = unique_mitigations(model)
    errors = []
    seen = set()
    internal = {r.get("id"): r for r in normalized or []}
    for d in dispositions:
        alias = d.get("mitigation_alias")
        if (not valid_disposition(d) or alias not in index or
                d.get("mitigation_uuid") != index[alias]["id"] or alias in seen):
            errors.append(f"Invalid/ambiguous mitigation disposition for {alias!r}; require a unique source pair, status, rationale, and manual guidance when applicable.")
        seen.add(alias)
        if normalized is not None:
            row = internal.get(d.get("mitigation_id"))
            if not row or row.get("alias") != alias or row.get("source_uuid", d.get("mitigation_uuid")) != d.get("mitigation_uuid"):
                errors.append(f"Disposition internal ID {d.get('mitigation_id')!r} does not match its source alias/UUID crosswalk.")
    return errors


def _read(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def build_run_audit(root):
    from validate_threat_model_input import load_run_export
    path, errors = load_run_export(root)
    if errors:
        raise ValueError("; ".join(errors))
    model = _read(path)
    source = _read(root / "00-intake/intake-manifest.json")["inputs"]["threat_model_source"]
    docs = {name: _read(root / name) for name in STATE_FILES if (root / name).exists()}
    current = docs.get("04-map/mapping-results.json", docs.get("04-map/map-controls-generated.json", {}))
    controls = rows(current, "controls")
    generated = docs.get("04-map/map-controls-generated.json", {})
    dispositions = rows(generated, "mitigation_dispositions")
    out = source_findings(model, source)
    normalized = rows(docs.get("03-validate/validated.json", {}), "existing_mitigations")
    validation_rows = normalized if "03-validate/validated.json" in docs else None
    for error in disposition_errors(dispositions, model, validation_rows):
        out.append(finding("invalid_disposition", "dispositions", error, stage="04-map", owner="Service Approval"))
    counts = Counter(d.get("mitigation_alias") for d in dispositions)
    valid = {d["mitigation_alias"]: d for d in dispositions
             if counts[d.get("mitigation_alias")] == 1 and not disposition_errors([d], model, validation_rows)}
    expected = unique_mitigations(model)
    # Never count duplicated/ambiguous source identities as successfully covered.
    inventory = rows(model, "mitigations")
    accounting = []
    inventories = [(name, "mitigations" if name.endswith("threat-model-index.json") else "existing_mitigations")
                   for name in docs if name.startswith(("02-research/", "03-validate/"))]
    for mitigation in inventory:
        alias, uuid = mitigation["alias"], mitigation["id"]
        for name, key in inventories:
            present = any(r.get("alias") == alias and r.get("source_uuid", r.get("id") if key == "mitigations" else uuid) == uuid
                          for r in rows(docs[name], key))
            if not present:
                out.append(finding("mitigation_missing", alias, "Source mitigation is absent or has mismatched identity in this stage.",
                                   stage=name, owner="Service Approval", uuid=uuid, aliases=[alias]))
        related = [c.get("id", "") for c in controls if alias in control_aliases(c)]
        if alias not in expected:
            status = "ambiguous_source"
        elif related:
            status = "covered"
        elif alias in valid:
            status = valid[alias]["status"]
        else:
            status = "unresolved" if current else "pending_map"
        d = valid.get(alias, {})
        accounting.append({"alias": alias, "uuid": uuid, "status": status,
                           "control_ids": sorted(related), "rationale": d.get("rationale", ""), "guidance": d.get("guidance", "")})
        if status == "unresolved":
            out.append(finding("mitigation_unresolved", alias, d.get("rationale") or "No control or documented disposition accounts for this source mitigation.",
                               stage="04-map", owner="Service Approval", uuid=uuid, aliases=[alias]))
    crosswalk = {r.get("id"): r.get("alias") for r in normalized if r.get("alias") in expected}
    for c in controls:
        expected_aliases = {crosswalk[mid] for mid in c.get("mitigation_ids", []) if mid in crosswalk}
        for alias in expected_aliases - set(control_aliases(c)):
            out.append(finding("control_provenance_missing", alias, "A control references this internal mitigation ID but lost its original source alias.",
                               stage="04-map", owner="Service Approval", uuid=expected[alias]["id"], aliases=[alias], controls=[c.get("id", "")]))
    for name, document in docs.items():
        for error in identity_errors(document, model):
            out.append(finding("identity_mismatch", name, error, stage=name, owner="Service Approval"))
    for f in out:
        f["affected_controls"] = sorted(set(f["affected_controls"]) | {c.get("id", "") for c in controls if set(f["mitigation_aliases"]) & set(control_aliases(c))})
    repairs = []
    for document in docs.values():
        repairs.extend(rows(document.get("_metadata", {}), "threat_model_repairs"))
        for c in rows(document, "controls"):
            repairs.extend(rows(c, "threat_model_repairs"))
    unique_repairs = {r["id"]: r for r in repairs if r.get("auto_fixed") and r.get("id")}
    return {"schema_version": "1.0", "source_commit": source["commit"], "source_sha256": source["data"]["sha256"],
            "source_url": source["data_url"], "report_url": source.get("report_url", ""),
            "checked_artifacts": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(docs)},
            "findings": sorted({f["id"]: f for f in out}.values(), key=lambda f: f["id"]),
            "repairs": sorted(unique_repairs.values(), key=lambda r: r["id"]),
            "mitigations": accounting}


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def render_details(audit):
    lines = ["# AWS Threat Model integrity", "", f"Source commit: `{audit['source_commit']}`; SHA-256: `{audit['source_sha256']}`.",
             "", f"[Saved source version]({audit['source_url']})", "",
             "Source findings and coverage gaps identify source defects or incomplete processing, not AWS service vulnerabilities. Incorrect generated identity pairs must be repaired.", "",
             "## Findings and repairs", "", "| ID | Check | Record / source UUID | Detail / target | Affected controls | Owner | Stage |",
             "|---|---|---|---|---|---|---|"]
    for f in audit["findings"] + audit["repairs"]:
        lines.append("| " + " | ".join(_cell(v) for v in (f["id"], f["check"], f"{f['record']} / {f.get('source_uuid', '')}",
            f"{f['detail']} {f.get('target', '')}", ", ".join(f["affected_controls"]) or "—", f["owner"], f["stage"])) + " |")
    if not audit["findings"] and not audit["repairs"]:
        lines.append("| — | Checks completed | — | No findings detected by these checks. | — | — | — |")
    lines += ["", "## Source mitigation accounting", "", "| Alias | Source UUID | Status | Controls | Rationale / guidance |", "|---|---|---|---|---|"]
    for m in audit["mitigations"]:
        lines.append("| " + " | ".join(_cell(v) for v in (m["alias"], m["uuid"], m["status"], ", ".join(m["control_ids"]),
                                                        m["rationale"] + " " + m["guidance"])) + " |")
    return "\n".join(lines) + "\n"


def report_block(audit):
    statuses = Counter(m["status"] for m in audit["mitigations"])
    counts = ", ".join(f"{count} {status.replace('_', ' ')}" for status, count in sorted(statuses.items()))
    lines = [BEGIN, "", "## AWS Threat Model integrity", "",
             f"Checked source commit `{audit['source_commit']}`: **{len(audit['findings'])} findings; {len(audit['repairs'])} recorded repairs**.",
             f"Source mitigation accounting: {counts or 'none'}. This check does not verify every AWS capability claim.",
             "[Finding details and mitigation accounting](../threat-model-integrity.md).", ""]
    for f in audit["findings"] + audit["repairs"]:
        lines.append(f"- **{_cell(f['id'])} — {_cell(f['record'])}:** {_cell(f['detail'])} "
                     f"Target: {_cell(f.get('target') or '—')}. Controls: {_cell(', '.join(f['affected_controls']) or '—')}.")
    lines += ["", END]
    return "\n".join(lines)


def write_audit(root, *, update_reports=True):
    from threat_model_source import atomic_write
    audit = build_run_audit(root)
    atomic_write(root / "threat-model-integrity.json", (json.dumps(audit, indent=2) + "\n").encode())
    atomic_write(root / "threat-model-integrity.md", render_details(audit).encode())
    if update_reports:
        block = report_block(audit)
        for name in REPORT_FILES:
            path = root / name
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            pattern = re.escape(BEGIN) + r".*?" + re.escape(END)
            text = re.sub(pattern, "", text, flags=re.DOTALL).lstrip("\n")
            title, sep, rest = text.partition("\n")
            atomic_write(path, (title + "\n\n" + block + "\n\n" + rest.lstrip("\n")).encode())
    return audit


def check_reporting(root):
    """Require exact deterministic disclosure once customer-facing reports exist."""
    present = [root / name for name in REPORT_FILES if (root / name).exists()]
    if not present:
        return []
    try:
        expected = build_run_audit(root)
        saved = _read(root / "threat-model-integrity.json")
        if saved != expected:
            return ["Threat-model integrity accounting is stale; run audit_threat_model.py before reporting."]
        errors = [f["detail"] for f in expected["findings"] if f["check"] in ("identity_mismatch", "invalid_disposition")]
        if (root / "threat-model-integrity.md").read_text() != render_details(expected):
            errors.append("Threat-model integrity details are missing or stale.")
        for path in present:
            if report_block(expected) not in path.read_text():
                errors.append(f"{path.name} omits or changes threat-model integrity findings; run audit_threat_model.py.")
        return errors
    except (OSError, ValueError) as exc:
        return [f"Threat-model integrity reporting incomplete: {exc}"]


def identity_errors(document, model):
    """Verify generated pairings; source ambiguities are reported, never guessed."""
    index = unique_mitigations(model)
    source_aliases = {m.get("alias") for m in rows(model, "mitigations")}
    errors = []
    def check_pair(alias, uuid, label):
        if alias in index and uuid is not None and uuid != index[alias]["id"]:
            errors.append(f"THREAT_MODEL-IDENTITY {label}: {alias} has UUID {uuid!r}, expected {index[alias]['id']!r}.")
    def walk(obj, label="document"):
        if isinstance(obj, list):
            for row in obj: walk(row, label)
        elif isinstance(obj, dict):
            label = str(obj.get("control_id") or obj.get("id") or label)
            alias = obj.get("mitigation_alias") or (obj.get("id") if obj.get("type") == "threat_model" else None)
            check_pair(alias, obj.get("mitigation_uuid"), label)
            aliases = obj.get("mitigation_aliases")
            uuids = obj.get("mitigation_uuids")
            if isinstance(aliases, list) and isinstance(uuids, list) and all(a in index for a in aliases):
                if uuids != [index[a]["id"] for a in aliases]:
                    errors.append(f"THREAT_MODEL-IDENTITY {label}: mitigation_aliases and mitigation_uuids are not corresponding pairs.")
            for ref in rows(obj, "mitigation_references"):
                check_pair(ref.get("alias"), ref.get("uuid"), label)
                if ref.get("alias") not in source_aliases:
                    errors.append(f"THREAT_MODEL-IDENTITY {label}: unknown mitigation reference {ref.get('alias')!r}.")
            for key, value in obj.items():
                # Repair history intentionally records previous wrong values.
                if key not in ("threat_model_repairs", "threat_model_source"):
                    walk(value, label)
    walk(document)
    return errors
