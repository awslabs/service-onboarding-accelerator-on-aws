#!/usr/bin/env python3
"""Phase 3d: Deterministic assembly of map sub-skill outputs into final mapping state files."""

import json
import sys
from collections import defaultdict
from pathlib import Path

STATE_DIR = Path(".service-approval/state")


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def write_json(path: Path, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Wrote {path} ({path.stat().st_size:,} bytes)")


def write_text(path: Path, text: str) -> None:
    with open(path, "w") as f:
        f.write(text)
    print(f"  Wrote {path} ({path.stat().st_size:,} bytes)")


# ---------------------------------------------------------------------------
# Phase 1: Build Reverse Index (controls -> framework objectives)
# ---------------------------------------------------------------------------
def build_reverse_index(fw_mapped: dict, controls: list[dict]) -> dict[str, list[str]]:
    ctrl_to_objs: dict[str, list[str]] = {}
    for f in fw_mapped["framework_mapping"]:
        if f.get("status") != "MAPPED":
            continue
        for c in f.get("controls", []):
            ctrl_to_objs.setdefault(c["control_id"], []).append(f["objective_id"])
    # Enrich controls with framework_objectives
    for ctrl in controls:
        ctrl["framework_objectives"] = sorted(set(ctrl_to_objs.get(ctrl["id"], [])))
    return ctrl_to_objs


# ---------------------------------------------------------------------------
# Phase 2: Build Threat-Mitigation-Control Map
# ---------------------------------------------------------------------------
def build_threat_mitigation_map(
    mitigations: list[dict], controls: list[dict]
) -> list[dict]:
    # Index controls by mitigation
    mit_to_ctrls: dict[str, list[dict]] = defaultdict(list)
    for ctrl in controls:
        for mid in ctrl.get("mitigation_ids", []):
            mit_to_ctrls[mid].append(ctrl)

    threat_mitigation_map = []
    for mit in mitigations:
        mid = mit["id"]
        associated_ctrls = mit_to_ctrls.get(mid, [])

        # Determine coverage layers
        categories = {c["category"] for c in associated_ctrls}
        has_preventive = bool(categories & {"PRV", "PRO"})
        has_detective = bool(categories & {"DET"})

        # Coverage determination
        if not associated_ctrls:
            coverage = "NONE"
        elif has_preventive and has_detective:
            coverage = "FULL"
        else:
            coverage = "PARTIAL"

        # Residual gaps
        residual = []
        if not has_preventive:
            residual.append("No preventive/proactive control")
        if not has_detective:
            residual.append("No detective control")
        if not any(c["category"] == "COR" for c in associated_ctrls):
            residual.append("No corrective control")

        # Union of framework_objectives from every control associated with this
        # mitigation (controls were enriched in build_reverse_index).
        fw_objs = sorted(
            {
                obj
                for c in associated_ctrls
                for obj in c.get("framework_objectives", [])
            }
        )

        entry = {
            "mitigation_id": mid,
            "statement": mit["statement"],
            "resource_type": mit.get("resource_type", ""),
            "coverage": coverage,
            "control_ids": sorted({c["id"] for c in associated_ctrls}),
            "framework_objectives": fw_objs,
            "layers": {
                "preventive": sorted(
                    {c["id"] for c in associated_ctrls if c["category"] == "PRV"}
                ),
                "proactive": sorted(
                    {c["id"] for c in associated_ctrls if c["category"] == "PRO"}
                ),
                "detective": sorted(
                    {c["id"] for c in associated_ctrls if c["category"] == "DET"}
                ),
                "corrective": sorted(
                    {c["id"] for c in associated_ctrls if c["category"] == "COR"}
                ),
            },
            "residual_gaps": residual,
        }
        threat_mitigation_map.append(entry)

    return threat_mitigation_map


# ---------------------------------------------------------------------------
# Phase 3: Identify Coverage Gaps
# ---------------------------------------------------------------------------
def identify_coverage_gaps(
    threat_mitigation_map: list[dict],
    controls: list[dict],
    fw_mapped: dict,
    ctrl_to_objs: dict[str, list[str]],
    upstream_gaps: list[dict] | None = None,
) -> dict:
    # mitigation_gap: mitigations with NONE coverage
    mitigation_gap = [
        {"mitigation_id": t["mitigation_id"], "statement": t["statement"]}
        for t in threat_mitigation_map
        if t["coverage"] == "NONE"
    ]

    # single_layer: only preventive/proactive OR only detective (not both)
    single_layer = []
    for t in threat_mitigation_map:
        if t["coverage"] == "NONE":
            continue
        has_prev = bool(t["layers"]["preventive"] or t["layers"]["proactive"])
        has_det = bool(t["layers"]["detective"])
        if has_prev != has_det:  # XOR: one but not both
            layer = "preventive/proactive" if has_prev else "detective"
            single_layer.append(
                {
                    "mitigation_id": t["mitigation_id"],
                    "present_layer": layer,
                    "missing_layer": "detective" if has_prev else "preventive/proactive",
                }
            )

    # framework_gap: MAPPED objectives with only SUPPORTS coverage
    framework_gap = [
        {
            "objective_id": f["objective_id"],
            "domain": f["domain"],
            "title": f["title"],
        }
        for f in fw_mapped["framework_mapping"]
        if f.get("status") == "MAPPED" and f.get("coverage") == "SUPPORTS"
    ]

    # control_orphan: controls not mapped to any objective
    control_orphan = [
        {"control_id": c["id"], "name": c["name"]}
        for c in controls
        if not ctrl_to_objs.get(c["id"])
    ]

    # posture_gap: Rule C1 infeasibility entries forwarded from upstream
    # map-generate-controls coverage_gaps (where each entry carries a
    # {mitigation_id, posture, reason} triple and the posture could not be
    # mapped to a feasible mechanism).
    posture_gap = [
        {
            "mitigation_id": g["mitigation_id"],
            "posture": g["posture"],
            "reason": g.get("reason", ""),
        }
        for g in (upstream_gaps or [])
        if isinstance(g, dict) and g.get("posture") and g.get("mitigation_id")
    ]

    return {
        "mitigation_gap": mitigation_gap,
        "single_layer": single_layer,
        "framework_gap": framework_gap,
        "control_orphan": control_orphan,
        "posture_gap": posture_gap,
    }


# ---------------------------------------------------------------------------
# Phase 4: Assemble mapping-results.json
# ---------------------------------------------------------------------------
def build_control_summary(controls: list[dict]) -> dict:
    by_scope: dict[str, int] = defaultdict(int)
    by_category: dict[str, int] = defaultdict(int)
    by_mechanism: dict[str, int] = defaultdict(int)
    for c in controls:
        by_scope[c["scope"]] += 1
        by_category[c["category"]] += 1
        by_mechanism[c["mechanism"]] += 1
    return {
        "total": len(controls),
        "by_scope": dict(sorted(by_scope.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_mechanism": dict(sorted(by_mechanism.items())),
    }


def build_framework_coverage_summary(fw_mapped: dict) -> dict:
    summary = fw_mapped.get("framework_coverage_summary", {})
    # Enrich with coverage breakdown
    full = 0
    partial = 0
    supports = 0
    for f in fw_mapped["framework_mapping"]:
        if f["status"] != "MAPPED":
            continue
        if f["coverage"] == "FULL":
            full += 1
        elif f["coverage"] == "PARTIAL":
            partial += 1
        elif f["coverage"] == "SUPPORTS":
            supports += 1
    summary["coverage_breakdown"] = {
        "FULL": full,
        "PARTIAL": partial,
        "SUPPORTS": supports,
    }
    return summary


def build_framework_header_canonical(fw_parsed: dict, fw_mapped: dict) -> str:
    """Compute the canonical full-union framework header string.

    Every generated artifact's `_metadata.framework` / `# FRAMEWORK:` header
    MUST be this string verbatim. CHECK-X1 in validate_cross.py enforces
    header identity across artifacts; computing the union here once lets
    the 3 generate skills read+copy rather than re-derive.
    """
    framework = fw_parsed.get("framework", {}) or {}
    name = framework.get("name", "framework")
    mapped = sorted(
        {
            f["objective_id"]
            for f in fw_mapped.get("framework_mapping", [])
            if isinstance(f, dict)
            and f.get("status") == "MAPPED"
            and f.get("objective_id")
        }
    )
    if not mapped:
        return name
    return f"{name} — {', '.join(mapped)}"


def assemble_mapping_results(
    controls: list[dict],
    threat_mitigation_map: list[dict],
    fw_parsed: dict,
    fw_mapped: dict,
    coverage_gaps: dict,
    service: str,
) -> dict:
    return {
        "schema_version": "1.0",
        "service": service,
        "framework": fw_parsed["framework"],
        "framework_header_canonical": build_framework_header_canonical(
            fw_parsed, fw_mapped
        ),
        "controls": controls,
        "threat_mitigation_map": threat_mitigation_map,
        "framework_mapping": fw_mapped["framework_mapping"],
        "framework_coverage_summary": build_framework_coverage_summary(fw_mapped),
        "coverage_gaps": coverage_gaps,
        "control_summary": build_control_summary(controls),
    }


# ---------------------------------------------------------------------------
# Phase 5: Write controls-catalog.md
# ---------------------------------------------------------------------------
SCOPE_ORDER = {"ORG": 0, "ACC": 1, "RES": 2}
SCOPE_LABELS = {"ORG": "Organisation", "ACC": "Account", "RES": "Resource"}
CATEGORY_ORDER = {"PRO": 0, "PRV": 1, "DET": 2, "COR": 3}
CATEGORY_LABELS = {
    "PRO": "Proactive",
    "PRV": "Preventive",
    "DET": "Detective",
    "COR": "Corrective",
}


def write_controls_catalog(controls: list[dict], path: Path) -> None:
    lines = []
    lines.append("# Controls Catalog -- Bedrock AgentCore\n")
    lines.append("")
    lines.append(f"**Total Controls**: {len(controls)}\n")
    lines.append("")

    # Control matrix summary table
    lines.append("## Control Matrix Summary\n")
    lines.append("")
    lines.append(
        "| Scope | Proactive | Preventive | Detective | Corrective | Total |"
    )
    lines.append("|-------|-----------|------------|-----------|------------|-------|")

    matrix: dict[str, dict[str, int]] = {}
    for scope in ["ORG", "ACC", "RES"]:
        matrix[scope] = {"PRO": 0, "PRV": 0, "DET": 0, "COR": 0}
    for c in controls:
        matrix[c["scope"]][c["category"]] += 1

    grand_total = 0
    for scope in ["ORG", "ACC", "RES"]:
        row = matrix[scope]
        total = sum(row.values())
        grand_total += total
        lines.append(
            f"| {SCOPE_LABELS[scope]} | {row['PRO']} | {row['PRV']} | {row['DET']} | {row['COR']} | {total} |"
        )
    lines.append(
        f"| **Total** | **{sum(matrix[s]['PRO'] for s in matrix)}** | **{sum(matrix[s]['PRV'] for s in matrix)}** | **{sum(matrix[s]['DET'] for s in matrix)}** | **{sum(matrix[s]['COR'] for s in matrix)}** | **{grand_total}** |"
    )
    lines.append("")

    # Group controls by scope then category
    grouped: dict[str, dict[str, list[dict]]] = {}
    for c in controls:
        grouped.setdefault(c["scope"], {}).setdefault(c["category"], []).append(c)

    for scope in sorted(grouped, key=lambda s: SCOPE_ORDER.get(s, 99)):
        lines.append(f"## {SCOPE_LABELS.get(scope, scope)} Scope\n")
        lines.append("")
        categories = grouped[scope]
        for cat in sorted(categories, key=lambda c: CATEGORY_ORDER.get(c, 99)):
            lines.append(f"### {CATEGORY_LABELS.get(cat, cat)} Controls\n")
            lines.append("")
            for ctrl in categories[cat]:
                lines.append(f"#### {ctrl['id']}: {ctrl['name']}\n")
                lines.append("")
                lines.append(
                    f"- **Resource Types**: {', '.join(ctrl.get('resource_types', []))}"
                )
                lines.append(f"- **Scope**: {SCOPE_LABELS.get(ctrl['scope'], ctrl['scope'])}")
                lines.append(f"- **Mechanism**: {ctrl['mechanism']}")
                lines.append(f"- **Description**: {ctrl['description']}")
                if ctrl.get("actions"):
                    lines.append(f"- **Actions**: `{'`, `'.join(ctrl['actions'])}`")
                if ctrl.get("condition_keys"):
                    lines.append(
                        f"- **Condition Keys**: `{'`, `'.join(ctrl['condition_keys'])}`"
                    )
                if ctrl.get("parameters_controlled"):
                    lines.append(
                        f"- **Parameters Controlled**: `{'`, `'.join(ctrl['parameters_controlled'])}`"
                    )
                lines.append(
                    f"- **Mitigations**: {', '.join(ctrl.get('mitigation_ids', []))}"
                )
                if ctrl.get("framework_objectives"):
                    lines.append(
                        f"- **Framework Objectives**: {', '.join(ctrl['framework_objectives'])}"
                    )
                lines.append(f"- **Security Rationale**: {ctrl['security_rationale']}")
                lines.append("")

    write_text(path, "\n".join(lines))


# ---------------------------------------------------------------------------
# Phase 6: Write framework-mapping.md
# ---------------------------------------------------------------------------
def write_framework_mapping(
    fw_mapped: dict,
    controls: list[dict],
    ctrl_to_objs: dict[str, list[str]],
    coverage_gaps: dict,
    threat_mitigation_map: list[dict],
    path: Path,
) -> None:
    ctrl_index = {c["id"]: c for c in controls}
    lines = []
    lines.append("# Framework Mapping -- CCMv4 x Bedrock AgentCore\n")
    lines.append("")

    # Framework coverage summary from the mapped file
    summary = fw_mapped.get("framework_coverage_summary", {})
    total_obj = summary.get("total_objectives", 197)
    mapped_count = summary.get("mapped", 0)
    na_count = summary.get("not_applicable", 0)

    # Count coverage levels
    full_count = sum(
        1
        for f in fw_mapped["framework_mapping"]
        if f["status"] == "MAPPED" and f["coverage"] == "FULL"
    )
    partial_count = sum(
        1
        for f in fw_mapped["framework_mapping"]
        if f["status"] == "MAPPED" and f["coverage"] == "PARTIAL"
    )
    supports_count = sum(
        1
        for f in fw_mapped["framework_mapping"]
        if f["status"] == "MAPPED" and f["coverage"] == "SUPPORTS"
    )

    lines.append("## Coverage Summary\n")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Objectives | {total_obj} |")
    lines.append(f"| Mapped | {mapped_count} |")
    lines.append(f"| Not Applicable | {na_count} |")
    lines.append(f"| FULL Coverage | {full_count} |")
    lines.append(f"| PARTIAL Coverage | {partial_count} |")
    lines.append(f"| SUPPORTS Coverage | {supports_count} |")
    lines.append("")

    # Domain coverage summary table
    lines.append("## Domain Coverage Summary\n")
    lines.append("")
    lines.append("| Domain | Total | Mapped | N/A | Coverage % |")
    lines.append("|--------|-------|--------|-----|------------|")
    by_domain = summary.get("by_domain", {})
    for domain in sorted(by_domain):
        d = by_domain[domain]
        lines.append(
            f"| {domain} | {d['total']} | {d['mapped']} | {d['not_applicable']} | {d['coverage_percentage']:.1f}% |"
        )
    lines.append("")

    # Detailed mappings by domain
    lines.append("## Detailed Mappings by Domain\n")
    lines.append("")

    # Group mappings by domain
    domain_mappings: dict[str, list[dict]] = defaultdict(list)
    for f in fw_mapped["framework_mapping"]:
        domain_mappings[f["domain"]].append(f)

    for domain in sorted(domain_mappings):
        mappings = domain_mappings[domain]
        mapped_objs = [m for m in mappings if m["status"] == "MAPPED"]
        na_objs = [m for m in mappings if m["status"] != "MAPPED"]

        lines.append(f"### {domain}\n")
        lines.append("")
        lines.append(
            f"*{len(mapped_objs)} mapped, {len(na_objs)} not applicable*\n"
        )
        lines.append("")

        if mapped_objs:
            for obj in mapped_objs:
                lines.append(f"**{obj['objective_id']}: {obj['title']}** -- Coverage: {obj['coverage']}\n")
                lines.append("")
                if obj.get("controls"):
                    lines.append(
                        "| Control ID | Title | Category | Scope | Confidence | Rationale |"
                    )
                    lines.append(
                        "|------------|-------|----------|-------|------------|-----------|"
                    )
                    for cm in obj["controls"]:
                        cid = cm["control_id"]
                        ctrl = ctrl_index.get(cid, {})
                        cat = CATEGORY_LABELS.get(
                            ctrl.get("category", ""), ctrl.get("category", "?")
                        )
                        scope = SCOPE_LABELS.get(
                            ctrl.get("scope", ""), ctrl.get("scope", "?")
                        )
                        title = ctrl.get("name", "?")
                        conf = cm.get("confidence", "?")
                        rat = cm.get("rationale", "")
                        lines.append(
                            f"| {cid} | {title} | {cat} | {scope} | {conf} | {rat} |"
                        )
                    lines.append("")

                lines.append(f"*Reason*: {obj.get('reason', '')}\n")
                lines.append("")

        if na_objs:
            lines.append(f"**Not Applicable Objectives**: {', '.join(o['objective_id'] for o in na_objs)}\n")
            lines.append("")

    # Unmapped controls section
    orphans = coverage_gaps.get("control_orphan", [])
    if orphans:
        lines.append("## Unmapped Controls\n")
        lines.append("")
        lines.append(
            "Controls not mapped to any framework objective:\n"
        )
        lines.append("")
        lines.append("| Control ID | Name |")
        lines.append("|------------|------|")
        for o in orphans:
            lines.append(f"| {o['control_id']} | {o['name']} |")
        lines.append("")

    # Coverage gaps section
    lines.append("## Coverage Gaps\n")
    lines.append("")

    mit_gaps = coverage_gaps.get("mitigation_gap", [])
    if mit_gaps:
        lines.append(f"### Mitigations Without Controls ({len(mit_gaps)})\n")
        lines.append("")
        for mg in mit_gaps:
            lines.append(f"- **{mg['mitigation_id']}**: {mg['statement']}")
        lines.append("")

    single = coverage_gaps.get("single_layer", [])
    if single:
        lines.append(f"### Single-Layer Coverage ({len(single)})\n")
        lines.append("")
        lines.append("| Mitigation | Present Layer | Missing Layer |")
        lines.append("|------------|---------------|---------------|")
        for s in single:
            lines.append(
                f"| {s['mitigation_id']} | {s['present_layer']} | {s['missing_layer']} |"
            )
        lines.append("")

    fw_gaps = coverage_gaps.get("framework_gap", [])
    if fw_gaps:
        lines.append(
            f"### Framework Objectives with SUPPORTS-Only Coverage ({len(fw_gaps)})\n"
        )
        lines.append("")
        for fg in fw_gaps:
            lines.append(
                f"- **{fg['objective_id']}** ({fg['domain']}): {fg['title']}"
            )
        lines.append("")

    # Mitigation traceability table
    lines.append("## Mitigation Traceability\n")
    lines.append("")
    lines.append(
        "| Mitigation ID | Resource Type | Coverage | Preventive | Detective | Corrective |"
    )
    lines.append(
        "|---------------|---------------|----------|------------|-----------|------------|"
    )
    for t in threat_mitigation_map:
        prev = len(t["layers"]["preventive"]) + len(t["layers"]["proactive"])
        det = len(t["layers"]["detective"])
        cor = len(t["layers"]["corrective"])
        lines.append(
            f"| {t['mitigation_id']} | {t['resource_type']} | {t['coverage']} | {prev} | {det} | {cor} |"
        )
    lines.append("")

    write_text(path, "\n".join(lines))


# ---------------------------------------------------------------------------
# Phase 7: Validate
# ---------------------------------------------------------------------------
def validate(
    mapping_results: dict,
    catalog_path: Path,
    fw_mapping_path: Path,
    threat_mitigation_map: list[dict],
) -> bool:
    errors = []

    # Check required top-level keys
    required_keys = [
        "schema_version",
        "service",
        "framework",
        "controls",
        "threat_mitigation_map",
        "framework_mapping",
        "framework_coverage_summary",
        "coverage_gaps",
        "control_summary",
    ]
    for k in required_keys:
        if k not in mapping_results:
            errors.append(f"Missing top-level key: {k}")

    # Check markdown files exist and are non-empty
    if not catalog_path.exists() or catalog_path.stat().st_size == 0:
        errors.append(f"{catalog_path} is missing or empty")
    if not fw_mapping_path.exists() or fw_mapping_path.stat().st_size == 0:
        errors.append(f"{fw_mapping_path} is missing or empty")

    # Validate mitigation coverage counts
    full = sum(1 for t in threat_mitigation_map if t["coverage"] == "FULL")
    partial = sum(1 for t in threat_mitigation_map if t["coverage"] == "PARTIAL")
    none_ = sum(1 for t in threat_mitigation_map if t["coverage"] == "NONE")
    total = len(threat_mitigation_map)
    if full + partial + none_ != total:
        errors.append(
            f"Coverage count mismatch: {full}+{partial}+{none_} != {total}"
        )

    # Validate control_summary total matches controls count
    cs = mapping_results.get("control_summary", {})
    if cs.get("total") != len(mapping_results.get("controls", [])):
        errors.append("control_summary.total does not match controls count")

    # Validate all controls have framework_objectives field
    for c in mapping_results.get("controls", []):
        if "framework_objectives" not in c:
            errors.append(f"Control {c['id']} missing framework_objectives")
            break

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    print("Map (Assemble) starting...\n")

    # Load inputs
    fw_parsed = load_json(STATE_DIR / "map-framework-parsed.json")
    cg = load_json(STATE_DIR / "map-controls-generated.json")
    fw_mapped = load_json(STATE_DIR / "map-framework-mapped.json")
    validated = load_json(STATE_DIR / "validated.json")

    controls = cg["controls"]
    mitigations = validated["existing_mitigations"]

    num_objectives = len(fw_parsed["framework_objectives"])
    num_controls = len(controls)
    num_mitigations = len(mitigations)

    print("  Inputs:")
    print(f"    Framework objectives: {num_objectives}")
    print(f"    Controls: {num_controls}")
    print(
        f"    Framework mappings: {len(fw_mapped['framework_mapping'])} "
        f"(MAPPED={sum(1 for f in fw_mapped['framework_mapping'] if f['status']=='MAPPED')}, "
        f"N/A={sum(1 for f in fw_mapped['framework_mapping'] if f['status']!='MAPPED')})"
    )
    print(f"    Mitigations: {num_mitigations}")
    print()

    # Phase 1: Build reverse index
    print("Phase 1: Building reverse index (controls -> framework objectives)...")
    ctrl_to_objs = build_reverse_index(fw_mapped, controls)
    mapped_ctrl_count = sum(1 for c in controls if c["framework_objectives"])
    orphan_ctrl_count = sum(1 for c in controls if not c["framework_objectives"])
    print(f"  {mapped_ctrl_count} controls mapped to objectives, {orphan_ctrl_count} orphaned")
    print()

    # Phase 2: Build threat-mitigation-control map
    print("Phase 2: Building threat-mitigation-control map...")
    threat_mitigation_map = build_threat_mitigation_map(mitigations, controls)
    full = sum(1 for t in threat_mitigation_map if t["coverage"] == "FULL")
    partial = sum(1 for t in threat_mitigation_map if t["coverage"] == "PARTIAL")
    none_ = sum(1 for t in threat_mitigation_map if t["coverage"] == "NONE")
    print(f"  Coverage: FULL={full}, PARTIAL={partial}, NONE={none_}")
    print()

    # Phase 3: Identify coverage gaps
    print("Phase 3: Identifying coverage gaps...")
    upstream_gaps = cg.get("coverage_gaps", [])
    coverage_gaps = identify_coverage_gaps(
        threat_mitigation_map, controls, fw_mapped, ctrl_to_objs,
        upstream_gaps=upstream_gaps,
    )
    print(f"  Mitigation gaps (NONE coverage): {len(coverage_gaps['mitigation_gap'])}")
    print(f"  Single-layer mitigations: {len(coverage_gaps['single_layer'])}")
    print(f"  Framework SUPPORTS-only: {len(coverage_gaps['framework_gap'])}")
    print(f"  Control orphans: {len(coverage_gaps['control_orphan'])}")
    print(f"  Posture gaps (Rule C1 infeasibility): {len(coverage_gaps['posture_gap'])}")
    print()

    # Phase 4: Assemble mapping-results.json
    print("Phase 4: Assembling mapping-results.json...")
    service = validated.get("service") or cg.get("service") or "unknown"
    mapping_results = assemble_mapping_results(
        controls, threat_mitigation_map, fw_parsed, fw_mapped, coverage_gaps, service,
    )
    mapping_results_path = STATE_DIR / "mapping-results.json"
    write_json(mapping_results_path, mapping_results)
    print()

    # Phase 5: Write controls-catalog.md
    print("Phase 5: Writing controls-catalog.md...")
    catalog_path = STATE_DIR / "controls-catalog.md"
    write_controls_catalog(controls, catalog_path)
    print()

    # Phase 6: Write framework-mapping.md
    print("Phase 6: Writing framework-mapping.md...")
    fw_mapping_path = STATE_DIR / "framework-mapping.md"
    write_framework_mapping(
        fw_mapped, controls, ctrl_to_objs, coverage_gaps, threat_mitigation_map, fw_mapping_path
    )
    print()

    # Phase 7: Validate
    print("Phase 7: Validating outputs...")
    valid = validate(
        mapping_results, catalog_path, fw_mapping_path, threat_mitigation_map
    )
    print()

    # Summary
    print("=" * 60)
    print("Map (Assemble) complete:")
    print("  Inputs:")
    print(f"    map-framework-parsed.json: {num_objectives} CCMv4 objectives")
    print(f"    map-controls-generated.json: {num_controls} controls")
    print(
        f"    map-framework-mapped.json: "
        f"{sum(1 for f in fw_mapped['framework_mapping'] if f['status']=='MAPPED')} mapped, "
        f"{sum(1 for f in fw_mapped['framework_mapping'] if f['status']!='MAPPED')} N/A"
    )
    print(f"    validated.json: {num_mitigations} mitigations")
    print("  Outputs:")
    print(f"    mapping-results.json: {num_controls} controls, {len(threat_mitigation_map)} mitigations mapped")
    print(f"    controls-catalog.md: {catalog_path.stat().st_size:,} bytes")
    print(f"    framework-mapping.md: {fw_mapping_path.stat().st_size:,} bytes")
    print("  Traceability:")
    print(f"    Mitigation coverage: FULL={full}, PARTIAL={partial}, NONE={none_}")
    print(f"    Framework coverage: FULL={sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage')=='FULL')}, PARTIAL={sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage')=='PARTIAL')}, SUPPORTS={sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage')=='SUPPORTS')}")
    print(f"    Controls mapped to objectives: {mapped_ctrl_count}/{num_controls}")
    print(f"    Orphaned controls: {orphan_ctrl_count}")
    print(f"  Validation: {'PASS' if valid else 'FAIL'}")
    print("=" * 60)

    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
