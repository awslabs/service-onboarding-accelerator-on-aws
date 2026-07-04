#!/usr/bin/env python3
"""Phase 3d: Deterministic assembly of map sub-skill outputs into final mapping state files.

Updated for per-service-per-phase layout. Reads from:
  .service-approval/<slug>/04-map/map-framework-parsed.json
  .service-approval/<slug>/04-map/map-controls-generated.json
  .service-approval/<slug>/04-map/map-framework-mapped.json
  .service-approval/<slug>/03-validate/validated.json

Writes to:
  .service-approval/<slug>/04-map/mapping-results.json
  .service-approval/<slug>/04-map/controls-catalog.md
  .service-approval/<slug>/04-map/framework-mapping.md
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

# Framework coverage-level vocabulary emitted by map-framework-mapping. The
# "preferred" values are what current upstream output uses; the legacy aliases
# are accepted for backward compatibility with archived runs (see
# schemas/map-framework-mapped.schema.json coverage enum).
COVERAGE_FULL = {"Fully Covered", "FULL"}
COVERAGE_PARTIAL = {"Partially Covered", "PARTIAL"}
COVERAGE_SUPPORTIVE = {"Supportive Only", "SUPPORTS"}

# Add repo root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from tools import paths
    from tools.slug import SlugValidationError
except ImportError:
    print("ERROR: tools.paths module not found. Run from the repo root with the project venv.", file=sys.stderr)
    sys.exit(1)


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
# Phase 0: Semantic control de-duplication
# ---------------------------------------------------------------------------
# The control set carries near-identical controls that differ only by ID — the
# per-resource mitigation variants (CapacityProvider / EventSourceMapping /
# Layer / CodeSigningConfig twins of a Function control) produce structurally
# identical controls, inflating the count and the coverage numbers. We collapse
# them deterministically here, BEFORE the reverse index / threat map / framework
# crosswalk are built, so everything downstream sees the deduped set.
#
# Collapse policy (deliberate, risk-averse): two controls are the SAME control
# when they share the canonical identity below — same name + scope + category +
# mechanism + resource_types, plus actions + posture so two controls that merely
# share a name but gate different actions stay distinct. Survivor = the
# lexicographically smallest control id in
# the group; the traceability list fields are unioned onto it so nothing dangles.
# Numbering is NOT renumbered contiguously — every reference is consistently
# remapped to the survivor id instead, which keeps the rewrite total and avoids
# the larger blast radius of renumbering (the id pattern requires \d{3}, not a
# gapless sequence).

# Traceability list fields unioned from each collapsed duplicate onto the survivor.
_DEDUP_UNION_FIELDS = (
    "mitigation_ids",
    "parameters_controlled",
    "condition_keys",
    "assessment_gap_ids",
    "attack_techniques",
    "framework_keywords",
    "resource_types",
)

# Coverage-level strength order for collapsing an objective's control list when
# two now-merged ids both appear under one objective (keep the strongest).
_COVERAGE_LEVEL_RANK = {
    "Full Coverage": 3,
    "Partial Coverage": 2,
    "Supportive": 1,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def _norm_name(name: str) -> str:
    return " ".join((name or "").split()).lower()


def canonical_control_key(ctrl: dict) -> tuple:
    """Canonical identity of a control for de-duplication.

    Two controls sharing this key enforce the same thing and are collapsed.
    Keyed on name + scope + category + mechanism + resource_types plus actions +
    posture, so controls that merely share a name but gate different
    actions/postures remain distinct.
    """
    return (
        _norm_name(ctrl.get("name", "")),
        ctrl.get("scope", ""),
        ctrl.get("category", ""),
        ctrl.get("mechanism", ""),
        tuple(sorted(ctrl.get("resource_types", []))),
        tuple(sorted(ctrl.get("actions", []))),
        ctrl.get("posture", ""),
    )


def dedup_controls(controls: list[dict]) -> tuple[list[dict], dict[str, str]]:
    """Collapse controls that share a canonical identity into one survivor.

    Returns (deduped_controls, id_remap) where id_remap maps EVERY input control
    id (including survivors, mapped to themselves) to its survivor id. Survivor
    is the lexicographically smallest id in each group; the traceability list
    fields in _DEDUP_UNION_FIELDS are unioned (sorted) onto it. Deterministic:
    groups preserve first-seen order, survivors keep their original ids.
    """
    groups: dict[tuple, list[dict]] = {}
    order: list[tuple] = []
    for ctrl in controls:
        key = canonical_control_key(ctrl)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(ctrl)

    deduped: list[dict] = []
    id_remap: dict[str, str] = {}
    for key in order:
        group = sorted(groups[key], key=lambda c: c["id"])
        survivor = group[0]
        for dup in group[1:]:
            for field in _DEDUP_UNION_FIELDS:
                merged = list(survivor.get(field, []))
                for v in dup.get(field, []):
                    if v not in merged:
                        merged.append(v)
                if merged:
                    survivor[field] = sorted(merged)
            id_remap[dup["id"]] = survivor["id"]
        # Sort the survivor's own list fields too, so output is stable whether or
        # not the control had duplicates.
        for field in _DEDUP_UNION_FIELDS:
            if survivor.get(field):
                survivor[field] = sorted(survivor[field])
        id_remap[survivor["id"]] = survivor["id"]
        deduped.append(survivor)
    return deduped, id_remap


def remap_framework_mapping(fw_mapped: dict, id_remap: dict[str, str]) -> None:
    """Rewrite framework_mapping[].controls[].control_id to survivor ids (in place).

    When two now-merged ids both appear under one objective, collapse them to one
    entry keeping the strongest coverage_level (and its rationale). Also remaps
    quality_gate_results.orphaned_controls if present.
    """
    for f in fw_mapped.get("framework_mapping", []):
        seen: dict[str, dict] = {}
        ordered: list[str] = []
        for cm in f.get("controls", []):
            new_id = id_remap.get(cm.get("control_id"), cm.get("control_id"))
            cm["control_id"] = new_id
            if new_id in seen:
                # Keep the stronger coverage_level entry.
                prev = seen[new_id]
                prev_rank = _COVERAGE_LEVEL_RANK.get(prev.get("coverage_level", ""), 0)
                new_rank = _COVERAGE_LEVEL_RANK.get(cm.get("coverage_level", ""), 0)
                if new_rank > prev_rank:
                    seen[new_id] = cm
            else:
                seen[new_id] = cm
                ordered.append(new_id)
        f["controls"] = [seen[cid] for cid in ordered]

    qgr = fw_mapped.get("quality_gate_results", {})
    if isinstance(qgr, dict) and "orphaned_controls" in qgr:
        remapped = []
        for oid in qgr["orphaned_controls"]:
            new_id = id_remap.get(oid, oid)
            if new_id not in remapped:
                remapped.append(new_id)
        qgr["orphaned_controls"] = remapped


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
            residual.append("No responsive control")

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
                "responsive": sorted(
                    {c["id"] for c in associated_ctrls if c["category"] == "COR"}
                ),
            },
            "residual_gaps": residual,
        }
        threat_mitigation_map.append(entry)

    return threat_mitigation_map


def resolve_mitigations(validated: dict, controls: list[dict]) -> list[dict]:
    """Return the mitigation list that drives the threat_mitigation_map.

    Prefer customer-provided `existing_mitigations` from validated.json. When a
    run has no customer mitigation report (`existing_mitigations == []`, which is
    valid), derive synthetic mitigations from `assessment_gaps` so the map still
    traces threats → controls.

    map-generate-controls (Rule C1) anchors each control to one or more synthetic
    mitigation IDs of the form `M-GAP-NNN.x` — a single gap `GAP-NNN` can spawn
    several mitigations (`.0`, `.1`, …) when it is addressed by more than one
    posture/control. We therefore build one synthetic mitigation per *referenced
    synthetic ID*, resolving each back to its source gap `GAP-NNN` for the
    statement (`"{requirement}: {details}"`) and resource_type (gap `domain`).
    Only synthetic IDs actually referenced by a generated control are emitted, so
    no NONE-coverage mitigations are introduced (CHECK-S13 rejects those).
    """
    existing = validated.get("existing_mitigations") or []
    if existing:
        return existing

    # The synthetic IDs the controls actually reference (e.g. M-GAP-005.0).
    referenced = sorted(
        {mid for c in controls for mid in c.get("mitigation_ids", [])}
    )

    # Index gaps by id so each referenced synthetic ID can resolve its source.
    gaps_by_id = {
        g["id"]: g for g in validated.get("assessment_gaps", []) if g.get("id")
    }

    synthetic: list[dict] = []
    for mid in referenced:
        # Strip the leading "M-" and the trailing ".x" instance suffix to recover
        # the source gap id (M-GAP-005.0 -> GAP-005). IDs that don't follow the
        # synthetic scheme are kept with empty statement/resource_type rather than
        # dropped, so the control still traces to a mitigation entry.
        gap_id = mid[2:] if mid.startswith("M-") else mid
        gap_id = gap_id.rsplit(".", 1)[0]
        gap = gaps_by_id.get(gap_id, {})
        requirement = gap.get("requirement", "").strip()
        details = gap.get("details", "").strip()
        statement = f"{requirement}: {details}" if details else requirement
        synthetic.append(
            {
                "id": mid,
                "statement": statement,
                "resource_type": gap.get("domain", ""),
            }
        )
    return synthetic


# ---------------------------------------------------------------------------
# Phase 2b: Build ATT&CK Coverage Summary
# ---------------------------------------------------------------------------
def build_attack_coverage(validated: dict, controls: list[dict]) -> dict:
    """Build the ATT&CK coverage summary from validated.attack_surface.

    MITRE ATT&CK analysis is mandatory — validated.json always carries
    attack_surface.applicable_techniques[].
    """
    attack_surface = validated.get("attack_surface")
    if not attack_surface:
        raise ValueError(
            "attack_surface missing from validated.json — MITRE ATT&CK analysis "
            "is mandatory. Run research-attack-surface first."
        )

    techniques = attack_surface.get("applicable_techniques", [])

    # technique_id -> [control ids]
    tech_to_ctrls: dict[str, list[str]] = {}
    for ctrl in controls:
        for tid in ctrl.get("attack_techniques", []):
            tech_to_ctrls.setdefault(tid, []).append(ctrl["id"])

    covered = [t for t in techniques if t["technique_id"] in tech_to_ctrls]
    uncovered = [t for t in techniques if t["technique_id"] not in tech_to_ctrls]

    # tactic-level summary
    tactic_coverage: dict[str, dict] = {}
    for t in techniques:
        tid = t.get("tactic_id", "")
        if tid not in tactic_coverage:
            tactic_coverage[tid] = {
                "name": t.get("tactic_name", ""),
                "total": 0,
                "covered": 0,
                "uncovered": 0,
                "techniques_covered": [],
                "techniques_uncovered": [],
            }
        tactic_coverage[tid]["total"] += 1
        if t["technique_id"] in tech_to_ctrls:
            tactic_coverage[tid]["covered"] += 1
            tactic_coverage[tid]["techniques_covered"].append(t["technique_id"])
        else:
            tactic_coverage[tid]["uncovered"] += 1
            tactic_coverage[tid]["techniques_uncovered"].append(t["technique_id"])

    return {
        "total_techniques": len(techniques),
        "covered_by_controls": len(covered),
        "uncovered": len(uncovered),
        "uncovered_techniques": [
            {
                "technique_id": t["technique_id"],
                "technique_name": t.get("technique_name", ""),
                "applicability": t.get("applicability", ""),
            }
            for t in uncovered
        ],
        "tactic_coverage": tactic_coverage,
        "technique_to_controls": {tid: cids for tid, cids in tech_to_ctrls.items()},
    }


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

    # framework_gap: MAPPED objectives with only Supportive coverage
    framework_gap = [
        {
            "objective_id": f["objective_id"],
            "domain": f.get("domain", ""),
            "title": f.get("title", ""),
        }
        for f in fw_mapped["framework_mapping"]
        if f.get("status") == "MAPPED" and f.get("coverage") in COVERAGE_SUPPORTIVE
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
        "total_controls": len(controls),
        "by_scope": dict(sorted(by_scope.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_mechanism": dict(sorted(by_mechanism.items())),
    }


def build_framework_coverage_summary(fw_mapped: dict) -> dict:
    summary = dict(fw_mapped.get("framework_coverage_summary", {}))
    # Enrich with coverage breakdown, keyed by the canonical coverage labels.
    full = 0
    partial = 0
    supportive = 0
    for f in fw_mapped["framework_mapping"]:
        if f.get("status") != "MAPPED":
            continue
        cov = f.get("coverage")
        if cov in COVERAGE_FULL:
            full += 1
        elif cov in COVERAGE_PARTIAL:
            partial += 1
        elif cov in COVERAGE_SUPPORTIVE:
            supportive += 1
    summary["coverage_breakdown"] = {
        "Fully Covered": full,
        "Partially Covered": partial,
        "Supportive Only": supportive,
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
    attack_coverage: dict,
) -> dict:
    # NOTE: mapping-results.schema.json is additionalProperties:false at the top
    # level and does NOT allow a top-level `attack_coverage` key. The ATT&CK
    # coverage summary lives under `_metadata.attack_coverage` (which is the
    # permissive `_metadata` object).
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
        "_metadata": {
            "phase": "04-map",
            "assembled_by": "map-assemble",
            "attack_coverage": attack_coverage,
        },
    }


# ---------------------------------------------------------------------------
# Phase 5: Write controls-catalog.md
# ---------------------------------------------------------------------------
SCOPE_ORDER = {"ORG": 0, "ACC": 1, "RES": 2}
SCOPE_LABELS = {"ORG": "Organisation", "ACC": "Account", "RES": "Resource"}
CATEGORY_ORDER = {"PRO": 0, "PRV": 1, "DET": 2, "COR": 3}
CATEGORY_LABELS = {
    "PRO": "Proactive",
    "PRV": "Preventative",
    "DET": "Detective",
    "COR": "Responsive",
}

# --- Objective-level catalog authoring (Phase 5 authoring rule) --------------
# The customer-facing controls-catalog.md must stay broad: NO raw `$.` parameter
# paths, NO long verbatim action lists. It states what kind of setting each
# control governs in words and names the action family / one or two
# representative actions. The exact paths and full action lists live in
# mapping-results.json.
#
# The `Governs:` phrase is derived service-agnostically from the parameter-path
# *leaf tokens* (not a per-service lookup): a leaf like `kmsKeyArn` maps to "the
# resource's encryption-key setting", `subnets` to "the resource's network
# configuration", and so on. This keeps the catalog accurate for ANY AWS service
# without hardcoding a service's parameter vocabulary, and without leaking raw
# `$.` paths. Condition-key and mechanism themes are the fallbacks so every
# control still gets a meaningful, broad statement.

# Ordered (substring-matched against the lowercased param leaf token) so the
# first matching theme wins. Tokens are matched case-insensitively.
_LEAF_THEMES: tuple[tuple[str, str], ...] = (
    ("kmskey", "the resource's encryption-key setting"),
    ("encryptionkey", "the resource's encryption-key setting"),
    ("keytype", "the resource's encryption-key setting"),
    ("kmsconfiguration", "the resource's encryption-key setting"),
    ("subnet", "the resource's network configuration"),
    ("securitygroup", "the resource's network configuration"),
    ("networkmode", "the resource's network configuration"),
    ("vpcconfig", "the resource's network configuration"),
    ("privateendpoint", "the resource's private-endpoint network configuration"),
    ("executionrole", "the resource's execution-role assignment"),
    ("rolearn", "the resource's execution-role assignment"),
    ("policy", "the resource's resource-based access policy"),
    ("tagkeys", "the set of tag keys applied to the resource"),
    ("tags", "tags applied to the resource"),
    ("deliverydestination", "the resource's log-delivery configuration"),
    ("deliverysource", "the resource's log-delivery configuration"),
    ("logtype", "the resource's log-delivery configuration"),
    ("discoveryurl", "the inbound authorizer configuration"),
    ("authorizationendpoint", "the inbound authorizer configuration"),
    ("tokenendpoint", "the inbound authorizer configuration"),
    ("issuer", "the inbound authorizer configuration"),
    ("authorizertype", "the inbound authorizer configuration"),
    ("allowedaudience", "the inbound authorizer's accepted-token settings"),
    ("allowedclients", "the inbound authorizer's accepted-token settings"),
    ("allowedscopes", "the inbound authorizer's accepted-token settings"),
    ("clientid", "the inbound authorizer's accepted-token settings"),
    ("claim", "the inbound authorizer's token-claim matching rules"),
    ("inboundtoken", "the inbound authorizer's token-claim matching rules"),
    ("matchvalue", "the inbound authorizer's token-claim matching rules"),
    ("credentialprovider", "the outbound credential-provider configuration"),
    ("oauth2", "the outbound credential-provider configuration"),
)

_CK_GOVERNS: tuple[tuple[str, str], ...] = (
    ("sourcearn", "the calling source resource identity"),
    ("sourceaccount", "the calling source account identity"),
    ("principalorgid", "the calling principal's organization membership"),
    ("requesttag", "tags supplied on the request"),
    ("resourcetag", "tags present on the resource"),
    ("tagkeys", "the set of tag keys applied to the resource"),
    ("securitygroups", "the resource's network configuration"),
    ("subnets", "the resource's network configuration"),
    ("authorizertype", "the inbound authorizer configuration"),
)

_MECH_GOVERNS = {
    "CloudTrail": "logging of management and data-plane activity",
    "AWS Config Rule": "the configuration state of deployed resources",
    "CloudFormation Guard": "the resource configuration declared at deploy time",
    "SSM Automation": "remediation of the targeted resource setting",
    "Compensating Control Documentation": "the documented compensating procedure",
    "VPC Endpoint Policy": "access to the service through the VPC endpoint",
    "Resource Policy": "the resource's resource-based access policy",
    "KMS Key Policy": "the encryption key's key policy",
    "IAM Trust Policy": "which principals may assume the service role",
    "Tag Policy": "the set of tag keys applied to the resource",
    "SCP": "the organization-level guardrail on the targeted action",
}


def _citation_cell(cm: dict, ctrl: dict) -> str:
    """Render the citation cell for a mapped-control row in framework-mapping.md.

    Prefers the row-level citation (objective_requirement + source + mitigation
    alias). Falls back to the control's threaded Canopy alias so the rendered md
    still shows the Canopy source even for a citation-free legacy mapping.
    """
    cit = cm.get("citation") if isinstance(cm.get("citation"), dict) else {}
    bits: list[str] = []
    req = (cit.get("objective_requirement") or "").strip()
    if req:
        bits.append(req)
    alias = cit.get("mitigation_alias") or ctrl.get("mitigation_alias")
    if alias:
        bits.append(f"`{alias}`")
    source = (cit.get("source") or ctrl.get("trace_source") or "").strip()
    if source:
        bits.append(f"({source})")
    return " ".join(bits) if bits else "—"


def _mitre_cell(cm: dict, ctrl: dict) -> str:
    """Render the MITRE ATT&CK cell — techniques resolved from the Canopy source."""
    techniques: list[str] = []
    cit = cm.get("citation") if isinstance(cm.get("citation"), dict) else {}
    for src in (cit.get("mitre_techniques"), ctrl.get("mitre_techniques")):
        if isinstance(src, list):
            techniques.extend(t for t in src if isinstance(t, str))
    seen = sorted(set(techniques))
    return ", ".join(seen) if seen else "—"


def _governs_phrase(ctrl: dict) -> str:
    """Plain-language description of the kind of setting a control governs.

    Words only — never a raw `$.` parameter path (those stay in
    mapping-results.json). Service-agnostic: derives the theme from parameter
    leaf tokens, then condition keys, then mechanism, so every control gets a
    meaningful, broad statement regardless of which AWS service it targets.
    """
    seen: list[str] = []

    def _leaf(path: str) -> str:
        return path.replace("[*]", "").replace("{key}", "").split(".")[-1].lower()

    for p in ctrl.get("parameters_controlled", []):
        leaf = _leaf(p)
        for token, phrase in _LEAF_THEMES:
            if token in leaf and phrase not in seen:
                seen.append(phrase)
                break
    if not seen:
        for ck in ctrl.get("condition_keys", []):
            ckl = ck.lower()
            for token, phrase in _CK_GOVERNS:
                if token in ckl and phrase not in seen:
                    seen.append(phrase)
                    break
    if not seen:
        phrase = _MECH_GOVERNS.get(ctrl.get("mechanism", ""))
        if phrase:
            seen.append(phrase)
    return "; ".join(seen) if seen else "the targeted resource configuration"


def _action_family(ctrl: dict) -> str:
    """Name the action family / one or two representative actions.

    Never a long verbatim list — the full list stays in mapping-results.json.
    """
    actions = ctrl.get("actions", [])
    if not actions:
        return ""
    if len(actions) <= 2:
        return "`" + "`, `".join(actions) + "`"
    # Name the first action plus its service prefix family (e.g.
    # `bedrock-agentcore:`), service-agnostically — never a long verbatim list.
    prefix = actions[0].split(":")[0]
    return f"`{actions[0]}` and related `{prefix}:` actions"


def write_controls_catalog(
    controls: list[dict],
    threat_mitigation_map: list[dict],
    attack_coverage: dict,
    service: str,
    path: Path,
) -> None:
    # Resource list (union across all controls), mitigations addressed count.
    resources = sorted(
        {r for c in controls for r in c.get("resource_types", [])}
    )
    mitigations_addressed = len(
        {t["mitigation_id"] for t in threat_mitigation_map if t.get("control_ids")}
    )

    lines = []
    lines.append(f"# Security Controls Catalog — {service}\n")
    lines.append("")
    lines.append(f"**Service:** {service}  ")
    lines.append(f"**Date Generated:** {date.today().isoformat()}  ")
    lines.append(f"**Total Controls:** {len(controls)}  ")
    lines.append(f"**Resources:** {', '.join(resources)}  ")
    lines.append(f"**Mitigations Addressed:** {mitigations_addressed}  ")
    lines.append("")
    lines.append(
        "> The objective-level statements below describe each control broadly. "
        "The exact parameter paths and full action lists for each control are "
        "recorded in `mapping-results.json` (the machine-readable source the "
        "generate phase consumes); the catalog stays objective-level so it does "
        "not over-state specifics."
    )
    lines.append("")

    # Control categories reference table. Purpose + implementation primitives are
    # the canonical category definitions (kept in sync with the authoring skill).
    lines.append("## Control Categories\n")
    lines.append("")
    lines.append("| Category | Purpose | Implementation primitives |")
    lines.append("|----------|---------|---------------------------|")
    lines.append(
        "| **Proactive** | Validate resource configuration before creation and block "
        "non-compliant resources from being created | CloudFormation Hooks (via Control "
        "Tower), CloudFormation Guard (CI/CD), OPA rules (CI/CD) |"
    )
    lines.append(
        "| **Preventative** | Stop non-compliant actions — hard guardrails that deny API "
        "calls regardless of the caller's IAM permissions | SCPs (org), RCPs (resource), "
        "Declarative Policies (service), IAM permissions boundaries (entity), VPC endpoint "
        "policies |"
    )
    lines.append(
        "| **Detective** | Identify non-compliance after deployment | AWS Config rules, "
        "Security Hub controls, GuardDuty findings, CloudTrail, Amazon Inspector |"
    )
    lines.append(
        "| **Corrective (Responsive)** | Remediate after detection | SSM Automation "
        "runbooks, Config auto-remediation (→ SSM), Lambda remediation, Security Hub "
        "automated response, EventBridge → remediation workflows |"
    )
    lines.append("")

    # Control matrix summary table
    lines.append("## Control Matrix Summary\n")
    lines.append("")
    lines.append("|  | Proactive | Preventative | Detective | Responsive | Total |")
    lines.append("|---|---|---|---|---|---|")

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
            f"| **{SCOPE_LABELS[scope]}** | {row['PRO']} | {row['PRV']} | {row['DET']} | {row['COR']} | {total} |"
        )
    lines.append(
        f"| **Total** | **{sum(matrix[s]['PRO'] for s in matrix)}** | **{sum(matrix[s]['PRV'] for s in matrix)}** | **{sum(matrix[s]['DET'] for s in matrix)}** | **{sum(matrix[s]['COR'] for s in matrix)}** | **{grand_total}** |"
    )
    lines.append("")

    # ATT&CK technique coverage
    lines.append("## ATT&CK Technique Coverage\n")
    lines.append("")
    lines.append("| Tactic | Tactic Name | Techniques | Covered | Uncovered |")
    lines.append("|---|---|---|---|---|")
    for tactic_id in sorted(attack_coverage.get("tactic_coverage", {})):
        tc = attack_coverage["tactic_coverage"][tactic_id]
        lines.append(
            f"| {tactic_id} | {tc['name']} | {tc['total']} | {tc['covered']} | {tc['uncovered']} |"
        )
    lines.append("")

    # Group controls by scope then category
    grouped: dict[str, dict[str, list[dict]]] = {}
    for c in controls:
        grouped.setdefault(c["scope"], {}).setdefault(c["category"], []).append(c)

    for scope in sorted(grouped, key=lambda s: SCOPE_ORDER.get(s, 99)):
        lines.append(f"## {SCOPE_LABELS.get(scope, scope)}-Level Controls\n")
        lines.append("")
        categories = grouped[scope]
        for cat in sorted(categories, key=lambda c: CATEGORY_ORDER.get(c, 99)):
            lines.append(f"### {CATEGORY_LABELS.get(cat, cat)}\n")
            lines.append("")
            for ctrl in categories[cat]:
                # Objective-level entry. NO raw `$.` parameter paths, NO long
                # verbatim action lists — `Governs:` states the kind of setting in
                # words and `Implementation:` names the action family. The exact
                # data stays in mapping-results.json.
                lines.append(f"#### {ctrl['id']} — {ctrl['name']}\n")
                lines.append("")
                lines.append(
                    f"- **Resource:** {', '.join(ctrl.get('resource_types', []))}"
                )
                lines.append(f"- **Scope:** {SCOPE_LABELS.get(ctrl['scope'], ctrl['scope'])}")
                lines.append(f"- **Description:** {ctrl['description']}")
                lines.append(f"- **Enforcement Point:** {ctrl['mechanism']}")
                fam = _action_family(ctrl)
                if fam:
                    lines.append(f"- **Implementation:** {ctrl['mechanism']} applied to {fam}")
                else:
                    lines.append(f"- **Implementation:** {ctrl['mechanism']}")
                lines.append(f"- **Governs:** {_governs_phrase(ctrl)}")
                lines.append(
                    f"- **Mitigations:** {', '.join(ctrl.get('mitigation_ids', []))}"
                )
                if ctrl.get("framework_objectives"):
                    lines.append(
                        f"- **Framework Objectives:** {', '.join(ctrl['framework_objectives'])}"
                    )
                lines.append("")

    lines.append(
        "> The exact parameter paths and full action lists for each control are "
        "recorded in `mapping-results.json` (the machine-readable source generate "
        "consumes); the catalog stays objective-level so it does not over-state "
        "specifics."
    )
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
    framework: dict,
    service: str,
    path: Path,
) -> None:
    ctrl_index = {c["id"]: c for c in controls}
    framework_name = framework.get("name", "framework")
    framework_version = framework.get("version", "")
    source_file = framework.get("source_file", "")

    lines = []
    lines.append(f"# {framework_name} Control Mapping — {service}\n")
    lines.append("")

    # Framework coverage summary from the mapped file
    summary = fw_mapped.get("framework_coverage_summary", {})
    total_obj = summary.get("total_objectives", len(fw_mapped["framework_mapping"]))
    mapped_count = summary.get("mapped", 0)
    na_count = summary.get("not_applicable", 0)
    uncertain_count = summary.get(
        "uncertain",
        sum(1 for f in fw_mapped["framework_mapping"] if f.get("status") == "UNCERTAIN"),
    )

    domains_covered = sum(
        1 for d in summary.get("by_domain", {}).values() if d.get("mapped", 0) > 0
    )
    total_domains = len(summary.get("by_domain", {}))

    lines.append(f"**Framework:** {framework_name} v{framework_version}  ")
    lines.append(f"**Source:** {source_file}  ")
    lines.append(f"**Date Generated:** {date.today().isoformat()}  ")
    lines.append(f"**Total Service Controls:** {len(controls)}  ")
    lines.append(f"**Framework Objectives Total:** {total_obj}  ")
    lines.append(f"**Objectives Mapped:** {mapped_count}  ")
    lines.append(f"**Objectives Not Applicable:** {na_count}  ")
    if uncertain_count:
        lines.append(f"**Objectives Uncertain (review needed):** {uncertain_count}  ")
    lines.append(f"**Domains Covered:** {domains_covered} / {total_domains}  ")
    lines.append("")

    lines.append("## Coverage Summary\n")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Objectives | {total_obj} |")
    lines.append(f"| Mapped | {mapped_count} |")
    lines.append(f"| Not Applicable | {na_count} |")
    lines.append(f"| Uncertain (review needed) | {uncertain_count} |")
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

    # Detailed mappings — every objective, in framework order, under its domain.
    # The report lists ALL objectives sequentially (mapped, N/A, and uncertain)
    # as `<ID>: <title>` so a reviewer can scan top-to-bottom and see each one
    # with its content or its N/A reason. Domain sub-headings are retained;
    # objectives appear in the merged framework order within each domain.
    lines.append("## Detailed Mappings by Domain\n")
    lines.append("")

    # Group mappings by domain, preserving the framework (canonical) order in
    # which each domain first appears and the objective order within it.
    domain_mappings: dict[str, list[dict]] = {}
    for f in fw_mapped["framework_mapping"]:
        domain_mappings.setdefault(f["domain"], []).append(f)

    rendered_objective_ids: list[str] = []

    for domain, mappings in domain_mappings.items():
        mapped_objs = [m for m in mappings if m["status"] == "MAPPED"]
        uncertain_objs = [m for m in mappings if m["status"] == "UNCERTAIN"]
        na_objs = [m for m in mappings if m["status"] == "N/A"]

        lines.append(f"### {domain}\n")
        lines.append("")
        summary_bits = [f"{len(mapped_objs)} mapped", f"{len(na_objs)} not applicable"]
        if uncertain_objs:
            summary_bits.append(f"{len(uncertain_objs)} uncertain")
        lines.append(f"*{', '.join(summary_bits)}*\n")
        lines.append("")

        # Sequential: render every objective in this domain in order, whatever
        # its status. No objective is collapsed into a trailing ID list.
        for obj in mappings:
            rendered_objective_ids.append(obj["objective_id"])
            oid = obj["objective_id"]
            title = obj.get("title", "")
            status = obj.get("status")

            if status == "MAPPED":
                lines.append(f"**{oid}: {title}** — Coverage: {obj.get('coverage', '')}\n")
                lines.append("")
                if obj.get("controls"):
                    lines.append(
                        "| Control ID | Title | Category | Scope | Coverage Level | Rationale | Citation | MITRE |"
                    )
                    lines.append(
                        "|------------|-------|----------|-------|----------------|-----------|----------|-------|"
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
                        ctrl_title = ctrl.get("name", "?")
                        level = cm.get("coverage_level", "?")
                        rat = cm.get("rationale", "")
                        lines.append(
                            f"| {cid} | {ctrl_title} | {cat} | {scope} | {level} | {rat} "
                            f"| {_citation_cell(cm, ctrl)} | {_mitre_cell(cm, ctrl)} |"
                        )
                    lines.append("")
                lines.append(f"*Reason*: {obj.get('reason', '')}\n")
                lines.append("")

            elif status == "UNCERTAIN":
                rr = obj.get("review_reason") or obj.get("reason", "")
                cids = ", ".join(
                    c.get("control_id", "?") for c in obj.get("controls", [])
                ) or "—"
                lines.append(
                    f"**{oid}: {title}** — UNCERTAIN (review needed) — {rr}"
                )
                lines.append(f"*Candidate control(s)*: {cids}\n")
                lines.append("")

            else:  # N/A
                lines.append(f"**{oid}: {title}** — N/A — {obj.get('reason', '')}\n")
                lines.append("")

    # Render-time completeness assertion: every objective from the merged mapping
    # must appear exactly once, so a dropped objective is caught here rather than
    # discovered by a reader scanning the report.
    all_objective_ids = [f["objective_id"] for f in fw_mapped["framework_mapping"]]
    if sorted(rendered_objective_ids) != sorted(all_objective_ids):
        missing = set(all_objective_ids) - set(rendered_objective_ids)
        extra = set(rendered_objective_ids) - set(all_objective_ids)
        raise ValueError(
            "framework-mapping render dropped or duplicated objectives — "
            f"rendered {len(rendered_objective_ids)} of {len(all_objective_ids)} "
            f"(missing={sorted(missing)[:10]}, extra={sorted(extra)[:10]})"
        )

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

    # NOTE: the customer-facing report intentionally omits a "Coverage Gaps"
    # section and a "Mitigation Traceability" table. The underlying data still
    # lives in mapping-results.json (`coverage_gaps`, `threat_mitigation_map`)
    # for downstream consumers and internal gates; it is simply not rendered
    # here because every control now cites its Canopy mitigation directly in
    # the catalog, and the mitigation-level rollup is not actionable for the
    # customer reading this report.

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
    if cs.get("total_controls") != len(mapping_results.get("controls", [])):
        errors.append("control_summary.total_controls does not match controls count")

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
# Service slug detection
# ---------------------------------------------------------------------------
def detect_single_service() -> str | None:
    """Auto-detect service slug if exactly one exists under .service-approval/."""
    try:
        root = paths.repo_root() / ".service-approval"
        if not root.exists():
            return None

        candidates = [
            d.name for d in root.iterdir()
            if d.is_dir() and d.name not in ("_staging", "plans")
        ]

        if len(candidates) == 1:
            return candidates[0]
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 3d: Deterministic assembly of map sub-skill outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # `--service` and `--slug` are accepted as synonyms — the orchestrator
    # prose elsewhere in this repo uses both names interchangeably, and
    # historical scripts have varied. argparse lets us register the flags
    # against the same `dest=service` so callers can use whichever they
    # remember.
    parser.add_argument(
        "--service",
        "--slug",
        dest="service",
        help="Service slug (e.g., 'awslambda', 's3'). `--slug` is an "
             "accepted alias. Auto-detected if only one service exists.",
    )

    args = parser.parse_args()

    # Resolve service slug
    slug = args.service
    if not slug:
        slug = detect_single_service()
        if not slug:
            print("ERROR: --service / --slug argument required (no single service detected)", file=sys.stderr)
            print("", file=sys.stderr)
            print("Detected services:", file=sys.stderr)
            try:
                root = paths.repo_root() / ".service-approval"
                candidates = [
                    d.name for d in root.iterdir()
                    if d.is_dir() and d.name not in ("_staging", "plans")
                ]
                if candidates:
                    for c in sorted(candidates):
                        print(f"  - {c}", file=sys.stderr)
                else:
                    print("  (none)", file=sys.stderr)
            except Exception:
                pass
            print("", file=sys.stderr)
            print("Usage: python3 scripts/map-assemble.py --service <slug>", file=sys.stderr)
            return 2

    # Validate paths exist
    try:
        service_root = paths.service_root(slug)
        if not service_root.exists():
            print(f"ERROR: Service directory does not exist: {service_root}", file=sys.stderr)
            print("", file=sys.stderr)
            print("Did you mean to use the old layout? The new layout is:", file=sys.stderr)
            print(f"  .service-approval/{slug}/04-map/", file=sys.stderr)
            print(f"  .service-approval/{slug}/03-validate/validated.json", file=sys.stderr)
            print("", file=sys.stderr)
            return 1

        map_dir = paths.phase_dir(slug, "map")
        validate_dir = paths.phase_dir(slug, "validate")

        if not map_dir.exists():
            print(f"ERROR: Map phase directory not found: {map_dir}", file=sys.stderr)
            return 1

        if not validate_dir.exists():
            print(f"ERROR: Validate phase directory not found: {validate_dir}", file=sys.stderr)
            return 1

    except (paths.PathResolutionError, SlugValidationError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print("Map (Assemble) starting...\n")
    print(f"  Service: {slug}")
    print(f"  Map dir: {map_dir}")
    print(f"  Validate dir: {validate_dir}")
    print("")

    # Load inputs from new paths
    fw_parsed = load_json(map_dir / "map-framework-parsed.json")
    cg = load_json(map_dir / "map-controls-generated.json")
    fw_mapped = load_json(map_dir / "map-framework-mapped.json")
    validated = load_json(validate_dir / "validated.json")

    controls = cg["controls"]

    # Phase 0: Semantic de-duplication. Collapse controls that share a canonical
    # identity (name + scope + category + mechanism + resource_types + actions +
    # posture) into one survivor, BEFORE the reverse index / threat map are built
    # and BEFORE framework-mapping references are resolved, so the whole pipeline
    # downstream sees the deduped set and the count is honest.
    print("Phase 0: De-duplicating controls...")
    pre_dedup_count = len(controls)
    controls, id_remap = dedup_controls(controls)
    remap_framework_mapping(fw_mapped, id_remap)
    collapsed = pre_dedup_count - len(controls)
    print(
        f"  {pre_dedup_count} controls -> {len(controls)} distinct "
        f"({collapsed} duplicate{'s' if collapsed != 1 else ''} collapsed)"
    )
    print()

    # existing_mitigations may be [] (valid — no customer mitigation report);
    # resolve_mitigations derives synthetic ones from assessment_gaps in that case.
    mitigations = resolve_mitigations(validated, controls)

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

    # Phase 2b: Build ATT&CK coverage summary (mandatory)
    print("Phase 2b: Building ATT&CK coverage summary...")
    attack_coverage = build_attack_coverage(validated, controls)
    print(
        f"  Techniques: {attack_coverage['covered_by_controls']}/"
        f"{attack_coverage['total_techniques']} covered, "
        f"{attack_coverage['uncovered']} uncovered"
    )
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
    print(f"  Framework supportive-only: {len(coverage_gaps['framework_gap'])}")
    print(f"  Control orphans: {len(coverage_gaps['control_orphan'])}")
    print(f"  Posture gaps (Rule C1 infeasibility): {len(coverage_gaps['posture_gap'])}")
    print()

    # Service + framework names — read from input, never hardcoded.
    service = cg.get("service") or validated.get("service") or "unknown"
    framework = fw_parsed.get("framework", {}) or {}
    framework_name = framework.get("name", "framework")

    # Phase 4: Assemble mapping-results.json
    print("Phase 4: Assembling mapping-results.json...")
    mapping_results = assemble_mapping_results(
        controls, threat_mitigation_map, fw_parsed, fw_mapped, coverage_gaps,
        service, attack_coverage,
    )
    mapping_results_path = map_dir / "mapping-results.json"
    write_json(mapping_results_path, mapping_results)
    print()

    # Phase 5: Write controls-catalog.md
    print("Phase 5: Writing controls-catalog.md...")
    catalog_path = map_dir / "controls-catalog.md"
    write_controls_catalog(controls, threat_mitigation_map, attack_coverage, service, catalog_path)
    print()

    # Phase 6: Write framework-mapping.md
    print("Phase 6: Writing framework-mapping.md...")
    fw_mapping_path = map_dir / "framework-mapping.md"
    write_framework_mapping(
        fw_mapped, controls, ctrl_to_objs, coverage_gaps, threat_mitigation_map,
        framework, service, fw_mapping_path,
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
    print(f"    map-framework-parsed.json: {num_objectives} {framework_name} objectives")
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
    fw_full = sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage') in COVERAGE_FULL)
    fw_partial = sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage') in COVERAGE_PARTIAL)
    fw_supportive = sum(1 for f in fw_mapped['framework_mapping'] if f.get('coverage') in COVERAGE_SUPPORTIVE)
    print(f"    Framework coverage: Fully Covered={fw_full}, Partially Covered={fw_partial}, Supportive Only={fw_supportive}")
    print(f"    Controls mapped to objectives: {mapped_ctrl_count}/{num_controls}")
    print(f"    Orphaned controls: {orphan_ctrl_count}")
    print(f"  Validation: {'PASS' if valid else 'FAIL'}")
    print("=" * 60)

    return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
