---
name: map-assemble
description: >
  Deterministic assembly of map sub-skill outputs into final mapping-results.json,
  controls-catalog.md, and framework-mapping.md. Builds traceability, identifies coverage
  gaps, and runs comprehensive validation. No LLM reasoning required — pure data assembly.
disable-model-invocation: false
argument-hint: "[--service=<name>]"
---

# Service Approval — Map: Assemble

Deterministic assembly of the 3 map sub-skill outputs into the final mapping state files.
This step builds traceability links, identifies coverage gaps, and produces the markdown
reports. It is largely mechanical — no LLM reasoning about control-objective alignment.

**Inputs:**
- `.service-approval/state/map-framework-parsed.json` — framework objectives
- `.service-approval/state/map-controls-generated.json` — controls with metadata
- `.service-approval/state/map-framework-mapped.json` — framework mappings with quality gates
- `.service-approval/state/validated.json` — mitigations and capabilities (for traceability)

**Outputs:**
- `.service-approval/state/mapping-results.json` — machine-readable mapping state (final)
- `.service-approval/state/controls-catalog.md` — controls inventory by Category x Scope
- `.service-approval/state/framework-mapping.md` — framework objective crosswalk

---

## Prerequisites

```bash
test -f .service-approval/state/map-framework-parsed.json && echo "framework-parsed: OK" || echo "ERROR"
test -f .service-approval/state/map-controls-generated.json && echo "controls-generated: OK" || echo "ERROR"
test -f .service-approval/state/map-framework-mapped.json && echo "framework-mapped: OK" || echo "ERROR"
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR"
```

All 4 files must exist before assembly.

---

## Phase 1: Build Reverse Index (controls -> framework objectives)

For each control, collect all framework objectives it maps to:

```python
import json

fw_mapped = json.load(open('.service-approval/state/map-framework-mapped.json'))
cg = json.load(open('.service-approval/state/map-controls-generated.json'))

# Build reverse index: control_id -> [objective_ids]
ctrl_to_objs = {}
for f in fw_mapped['framework_mapping']:
    if f.get('status') != 'MAPPED':
        continue
    for c in f.get('controls', []):
        ctrl_to_objs.setdefault(c['control_id'], []).append(f['objective_id'])

# Enrich controls with framework_objectives. Posture + source fields (from Rule C1
# in map-generate-controls) flow through unchanged — they're already on each control
# and will be propagated verbatim into mapping-results.json.controls[]. Every downstream
# generate sub-skill reads ctrl['posture'] to populate _metadata.posture in the
# generated artifact, which CHECK-15 enforces at hook time.
for ctrl in cg['controls']:
    ctrl['framework_objectives'] = sorted(set(ctrl_to_objs.get(ctrl['id'], [])))
    # posture + source: carry forward if present; absence is tolerated for legacy state
    # files generated before Phase C (CHECK-15 only fires when _metadata.posture exists).
```

---

## Phase 2: Build Threat-Mitigation-Control Map

For each mitigation in `validated.json`, build full traceability:

```python
vj = json.load(open('.service-approval/state/validated.json'))
controls = cg['controls']

# Index controls by mitigation_id
mit_to_ctrls = {}
for ctrl in controls:
    for mid in ctrl.get('mitigation_ids', []):
        mit_to_ctrls.setdefault(mid, []).append(ctrl['id'])

threat_mitigation_map = []
for mit in vj.get('existing_mitigations', []):
    mid = mit['id']
    ctrl_ids = mit_to_ctrls.get(mid, [])

    # Derive framework objectives from mapped controls
    fw_objs = set()
    for cid in ctrl_ids:
        fw_objs.update(ctrl_to_objs.get(cid, []))

    # Determine coverage and residual gaps
    has_preventive = False
    has_detective = False
    params = set(mit.get('request_parameters', []))
    controlled_params = set()

    if not ctrl_ids:
        coverage = "NONE"
    else:
        # Check if both preventive AND detective layers exist
        categories = set()
        for ctrl in controls:
            if ctrl['id'] in ctrl_ids:
                categories.add(ctrl['category'])
        has_preventive = 'PRV' in categories or 'PRO' in categories
        has_detective = 'DET' in categories or 'COR' in categories
        # Check parameter coverage
        for ctrl in controls:
            if ctrl['id'] in ctrl_ids:
                controlled_params.update(ctrl.get('parameters_controlled', []))
        params_covered = params.issubset(controlled_params) if params else True
        if has_preventive and has_detective and params_covered:
            coverage = "FULL"
        else:
            coverage = "PARTIAL"

    # Identify residual gaps
    residual_gaps = []
    if coverage == "NONE":
        residual_gaps.append("No controls address this mitigation")
    else:
        if not has_preventive:
            residual_gaps.append("No preventive layer — only detective controls")
        if not has_detective:
            residual_gaps.append("No detective layer — only preventive controls")
        uncovered_params = params - controlled_params if params else set()
        if uncovered_params:
            residual_gaps.append(f"Parameters not controlled: {sorted(uncovered_params)}")

    threat_mitigation_map.append({
        "mitigation_id": mid,
        "statement": mit.get('statement', ''),
        "mitigation_goal": mit.get('mitigation_goal', ''),
        "resource_type": mit.get('resource_type', ''),
        "controls": sorted(ctrl_ids),
        "framework_objectives": sorted(fw_objs),
        "coverage": coverage,
        "residual_gaps": residual_gaps
    })
```

---

## Phase 2b: Build ATT&CK Coverage Summary (optional)

Run only if `validated.json` contains `attack_surface`. If absent, skip — backward compatible.

```python
attack_surface = vj.get('attack_surface')
attack_coverage = None

if attack_surface:
    techniques = attack_surface.get('applicable_techniques', [])
    technique_ids = {t['technique_id'] for t in techniques}

    # Build technique -> controls mapping
    tech_to_ctrls = {}
    for ctrl in controls:
        for tid in ctrl.get('attack_techniques', []):
            tech_to_ctrls.setdefault(tid, []).append(ctrl['id'])

    # Calculate coverage
    covered_techniques = [t for t in techniques if t['technique_id'] in tech_to_ctrls]
    uncovered_techniques = [t for t in techniques if t['technique_id'] not in tech_to_ctrls]

    # Build tactic-level summary
    tactic_coverage = {}
    for t in techniques:
        tid = t['tactic_id']
        if tid not in tactic_coverage:
            tactic_coverage[tid] = {
                'name': t['tactic_name'],
                'total': 0, 'covered': 0, 'uncovered': 0,
                'techniques_covered': [], 'techniques_uncovered': []
            }
        tactic_coverage[tid]['total'] += 1
        if t['technique_id'] in tech_to_ctrls:
            tactic_coverage[tid]['covered'] += 1
            tactic_coverage[tid]['techniques_covered'].append(t['technique_id'])
        else:
            tactic_coverage[tid]['uncovered'] += 1
            tactic_coverage[tid]['techniques_uncovered'].append(t['technique_id'])

    attack_coverage = {
        'total_techniques': len(techniques),
        'covered_by_controls': len(covered_techniques),
        'uncovered': len(uncovered_techniques),
        'uncovered_techniques': [
            {'technique_id': t['technique_id'], 'technique_name': t['technique_name'],
             'applicability': t['applicability']}
            for t in uncovered_techniques
        ],
        'tactic_coverage': tactic_coverage,
        'technique_to_controls': {tid: cids for tid, cids in tech_to_ctrls.items()}
    }
```

---

## Phase 3: Identify Coverage Gaps

Detect and classify ALL gap types:

```python
coverage_gaps = []

# 0. posture_gap: forward any (mitigation, posture) gaps produced by Rule C1's
# feasibility filter in map-generate-controls. These are structural gaps — a mitigation
# was intended to produce a preventative-request or reactive-corrective control but the
# parameter's gateable_by / mutability precluded it.
for g in cg.get('coverage_gaps', []):
    coverage_gaps.append({
        "type": "posture_gap",
        "id": g.get('mitigation_id'),
        "description": (
            f"Posture {g.get('posture')!r} not feasible for mitigation "
            f"{g.get('mitigation_id')}: {g.get('reason')}"
        ),
        "recommendation": (
            "Either accept the posture gap (documented), or pick a compensating "
            "mechanism at a different posture (e.g., reactive-detective)."
        ),
        "posture": g.get('posture'),
        "reason": g.get('reason'),
    })

# 1. mitigation_gap: mitigations with NONE coverage
for t in threat_mitigation_map:
    if t['coverage'] == 'NONE':
        coverage_gaps.append({
            "type": "mitigation_gap",
            "id": t['mitigation_id'],
            "description": f"No controls address mitigation {t['mitigation_id']}",
            "recommendation": f"Generate controls for: {t['mitigation_goal'][:100]}"
        })

# 2. single_layer: mitigations with only one control category
for t in threat_mitigation_map:
    if t['coverage'] == 'NONE':
        continue
    ctrl_cats = set()
    for ctrl in controls:
        if ctrl['id'] in t['controls']:
            ctrl_cats.add(ctrl['category'])
    preventive_cats = ctrl_cats & {'PRV', 'PRO'}
    detective_cats = ctrl_cats & {'DET', 'COR'}
    if preventive_cats and not detective_cats:
        coverage_gaps.append({
            "type": "single_layer",
            "id": t['mitigation_id'],
            "description": f"Mitigation {t['mitigation_id']} has only preventive controls, no detective",
            "recommendation": "Add detective control (Config rule or CloudWatch alarm)"
        })
    elif detective_cats and not preventive_cats:
        coverage_gaps.append({
            "type": "single_layer",
            "id": t['mitigation_id'],
            "description": f"Mitigation {t['mitigation_id']} has only detective controls, no preventive",
            "recommendation": "Add preventive control (SCP, IAM policy, or resource policy)"
        })

# 3. partial_parameter_coverage: mitigations where some params uncovered
for t in threat_mitigation_map:
    if t['residual_gaps']:
        for gap in t['residual_gaps']:
            if 'Parameters not controlled' in gap:
                coverage_gaps.append({
                    "type": "partial_parameter_coverage",
                    "id": t['mitigation_id'],
                    "description": gap,
                    "recommendation": "Add controls for uncovered parameters"
                })

# 4. framework_gap: MAPPED objectives with only SUPPORTS coverage
for f in fw_mapped['framework_mapping']:
    if f.get('status') == 'MAPPED' and f.get('coverage') == 'SUPPORTS':
        coverage_gaps.append({
            "type": "framework_gap",
            "id": f['objective_id'],
            "description": f"Objective {f['objective_id']} has only Low confidence controls",
            "recommendation": "Implement stronger controls directly addressing this objective"
        })

# 5. control_orphan: controls not mapped to any objective
orphaned = fw_mapped.get('quality_gate_results', {}).get('orphaned_controls', [])
for oid in orphaned:
    coverage_gaps.append({
        "type": "control_orphan",
        "id": oid,
        "description": f"Control {oid} does not map to any framework objective",
        "recommendation": "Review if this control addresses any framework requirement"
    })

# 6. attack_technique_gap: HIGH applicability techniques with no controls (optional)
if attack_coverage:
    for t in attack_coverage.get('uncovered_techniques', []):
        if t['applicability'] == 'HIGH':
            coverage_gaps.append({
                "type": "attack_technique_gap",
                "id": t['technique_id'],
                "description": f"HIGH applicability technique {t['technique_id']} ({t['technique_name']}) has no covering controls",
                "recommendation": "Generate controls targeting this attack technique"
            })
```

---

## Phase 4: Assemble mapping-results.json

Combine all data into the final `mapping-results.json`:

```python
fw_parsed = json.load(open('.service-approval/state/map-framework-parsed.json'))

# Build control_summary
from collections import Counter
scope_counts = Counter(c['scope'] for c in controls)
cat_counts = Counter(c['category'] for c in controls)
mech_counts = Counter(c['mechanism'] for c in controls)

mapping_results = {
    "schema_version": "1.0",
    "service": cg.get('service', vj.get('service', '')),
    "framework": fw_parsed['framework'],
    "controls": controls,  # enriched with framework_objectives
    "threat_mitigation_map": threat_mitigation_map,
    "framework_mapping": fw_mapped['framework_mapping'],
    "framework_coverage_summary": fw_mapped['framework_coverage_summary'],
    "coverage_gaps": coverage_gaps,
    "control_summary": {
        "total_controls": len(controls),
        "by_scope": dict(scope_counts),
        "by_category": dict(cat_counts),
        "by_mechanism": dict(mech_counts)
    }
}

# Add ATT&CK coverage if available (optional — backward compatible)
if attack_coverage:
    mapping_results['attack_coverage'] = attack_coverage

with open('.service-approval/state/mapping-results.json', 'w') as f:
    json.dump(mapping_results, f, indent=2)
```

---

## Phase 5: Write controls-catalog.md

Write `.service-approval/state/controls-catalog.md`:

```markdown
# Security Controls Catalog — {service-name}

**Service:** {service-name}
**Date Generated:** {date}
**Total Controls:** {count}
**Resources:** {resource-list}
**Mitigations Addressed:** {count}

## Control Matrix Summary

|  | Proactive | Preventive | Detective | Corrective | Total |
|---|---|---|---|---|---|
| **Organisation** | N | N | N | N | N |
| **Account** | N | N | N | N | N |
| **Resource** | N | N | N | N | N |
| **Total** | N | N | N | N | N |

## Organisation-Level Controls

### Proactive

#### {CTRL-ORG-PRO-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control does}
- **Enforcement Point:** {mechanism}
- **Implementation:** {how to implement}
- **Parameters Controlled:** {API parameters}
- **Mitigations:** {M-xxx IDs}
- **AWS Doc Reference:** {URL}

[repeat for each control, organized by Scope > Category]

### Preventive
### Detective
### Corrective

## Account-Level Controls
## Resource-Level Controls
```

Each control entry MUST include a `Mitigations:` line referencing the mitigation IDs it addresses.

If `attack_coverage` is available, add after the Control Matrix Summary:

```markdown
## ATT&CK Technique Coverage

| Tactic | Tactic Name | Techniques | Covered | Uncovered |
|---|---|---|---|---|
| TA0001 | Initial Access | 3 | 2 | 1 |
[repeat for each tactic]

### Uncovered HIGH Techniques

| Technique | Name | Applicability | Recommendation |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | HIGH | Add VPC endpoint controls |
```

---

## Phase 6: Write framework-mapping.md

Write `.service-approval/state/framework-mapping.md`.

**CRITICAL REQUIREMENT:** The framework-mapping.md MUST be organized so that EVERY individual
control objective from the parsed framework has its own entry showing which service controls
satisfy it. This is the primary deliverable for compliance reviewers — they need to look up
any framework objective and immediately see which controls address it.

Do NOT group controls by domain and then list objectives as a flat bullet list. Do NOT
produce a document organized by service control categories. The document MUST be organized
by framework objective.

The document MUST be service-agnostic and framework-agnostic in its structure — it works for
any AWS service and any compliance framework provided as input.
Use the framework name, domain names, and objective IDs from `map-framework-parsed.json`.
Use the service name from `map-controls-generated.json`. Never hardcode a specific framework
or service name in the template logic.

```markdown
# {Framework Name} Control Mapping — {service-name}

**Framework:** {name} v{version}
**Source:** {source_file}
**Date Generated:** {date}
**Total Service Controls:** {count}
**Framework Objectives Total:** {total}
**Objectives Mapped:** {mapped}
**Objectives N/A:** {na}
**Domains Covered:** {domains_covered} / {total_domains}

## Domain Coverage Summary

| Domain | Objectives in Domain | Mapped | N/A | Coverage % | Notes |
|---|---|---|---|---|---|
| {domain} | N | N | N | N% | {note} |

---

## Objective-to-Controls Mapping

For EVERY framework objective, list the service controls that satisfy it. This section is
the core of the document. Each objective gets its own subsection regardless of whether it
has mapped controls or is N/A.

### {Domain Name}

#### {Objective-ID}: {Objective Title}

**Status:** {MAPPED | N/A}
**Coverage:** {FULL | PARTIAL | SUPPORTS | N/A}
**Reason:** {1-sentence summary of why this coverage level was assigned, or why N/A}

| Control ID | Control Name | Category | Confidence | Rationale |
|---|---|---|---|---|
| {CTRL-ID} | {name} | {PRV/PRO/DET/COR} | {High/Medium/Low} | {1-sentence specific rationale connecting this control's mechanism to this objective's requirement} |

If status is N/A, the table is omitted and only the Reason line appears. Example:
> **Status:** N/A
> **Reason:** Physical datacenter security is managed by AWS under the shared responsibility model.

[Repeat for EVERY objective in the domain, then repeat for EVERY domain]

---

## Unmapped Service Controls

Controls that were generated but do not map to any framework objective.

| Control ID | Control Name | Category | Reason |
|---|---|---|---|
| {CTRL-ID} | {name} | {category} | {reason why no framework objective applies} |

---

## Coverage Gaps

Framework objectives where coverage is PARTIAL, SUPPORTS, or where no HIGH-confidence
controls exist.

| Objective ID | Domain | Gap Description | Recommendation |
|---|---|---|---|
| {obj-id} | {domain} | {what is missing} | {what to implement} |

---

## Threat-to-Framework Traceability

Shows the full chain: Threat Mitigation → Service Controls → Framework Objectives.

| Mitigation ID | Threat Description | Service Controls | Framework Objectives | Coverage |
|---|---|---|---|---|
| {MIT-ID} | {threat summary} | {CTRL-1, CTRL-2, ...} | {OBJ-1, OBJ-2, ...} | {FULL/PARTIAL/NONE} |
```

**Assembly rules for this phase:**

1. Iterate over `map-framework-mapped.json` `framework_mapping[]` array. Each entry has
   `objective_id`, `domain`, `title`, `status`, `coverage`, `reason`, and `controls[]`.

2. Group objectives by domain. Within each domain, sort by objective_id.

3. For each objective, write the subsection header and controls table. The `controls[]` array
   from `map-framework-mapped.json` contains `{control_id, confidence, rationale}`. Look up
   the control's `name` and `category` from `map-controls-generated.json`.

4. For the Unmapped Service Controls section, use `quality_gate_results.orphaned_controls`
   from `map-framework-mapped.json`.

5. For Coverage Gaps, use `coverage_gaps` assembled in Phase 3 of this skill, filtered to
   `framework_gap` type entries.

6. For Threat-to-Framework Traceability, use `threat_mitigation_map` assembled in Phase 2
   of this skill.

---

## Phase 7: Final Validation

Output validation runs automatically via PostToolUse hook (validate_state.py Check S13).


---

## Print Summary

```
Map (Assemble) complete:
  Inputs:
    - map-framework-parsed.json ({N} objectives)
    - map-controls-generated.json ({N} controls)
    - map-framework-mapped.json ({N} mappings)
  Outputs:
    - mapping-results.json (final state)
    - controls-catalog.md (matrix: {O} org, {A} acc, {R} res x {P} pro, {V} prv, {D} det, {C} cor)
    - framework-mapping.md ({mapped} mapped, {na} N/A)
  Traceability:
    - Mitigations: {N}/{total} ({pct}%)
    - Framework objectives: {mapped}/{total} mapped, {na} N/A
    - Coverage gaps: {N}
  Validation: PASS
```
