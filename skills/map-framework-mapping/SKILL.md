---
name: map-framework-mapping
description: Map generated controls to framework objectives with per-objective analysis, coverage-level scoring, and strict quality gates. Produces map-framework-mapped.json consumed by map-assemble. The hardest sub-skill — requires careful per-objective reasoning, not batch keyword matching.
disable-model-invocation: false
argument-hint: '[--service=<name>]'
---

# Service Approval — Map: Framework Mapping

Map each generated control to framework objectives individually. This is the most reasoning-heavy
sub-skill in the map pipeline. It produces quality-gated framework mappings with rationale.

**Inputs:**
- `.service-approval/<slug>/04-map/map-framework-parsed.json` — normalized framework objectives
- `.service-approval/<slug>/04-map/map-controls-generated.json` — controls with rich metadata
- `data/domain-mapping-guidance/<framework>.json` — per-domain mapping guidance (CCMv4 today)

**Output:** `.service-approval/<slug>/04-map/map-framework-mapped.json`
**Schema:** `schemas/map-framework-mapped.schema.json` — encodes the status enum (`MAPPED`, `N/A`, or `UNCERTAIN`), coverage enum, `control_id` pattern matching map-controls-generated, and per-mapping required fields. See also the "Schema rules" section below.

This is one of 4 focused map sub-skills. Each writes to a separate intermediate state file.

## Execution model: per-domain specialization (CCMv4) vs single-pass (others)

Mapping ~197 objectives in one pass produces keyword-driven mis-maps: a control
gets attached to an objective whose *words* overlap but whose *intent* differs.
To cut that, CCMv4 is mapped **per domain** — each domain is handled in a focused
context loaded with only that domain's objectives plus curated guidance on what
each objective actually means and which mechanisms legitimately satisfy it. The
17 per-domain partials are then merged deterministically into the single
`map-framework-mapped.json`.

- **CCMv4 (guidance file present):** run the per-domain fan-out (the
  service-approval orchestrator dispatches one mapping subagent per domain — see
  Step 3c there) and merge with `scripts/merge-domain-mappings.py`. The
  per-objective reasoning rules in Phase 1 and the guidance in Phase 0 apply
  **per domain**.
- **Non-CCMv4 (no `data/domain-mapping-guidance/<framework>.json` for the active
  framework):** fall back to the **single-pass** behavior — map all objectives in
  one pass using Phases 0–4 below. NIST 800-53 / CIS / ISO have no guidance file
  yet, so they take this path; advanced-operator `--framework` flags keep working.
  **If a `custom_to_ccmv4_anchor.json` is present** (written by map-parse-framework
  Step 5 for a custom framework), reason with the anchored CCMv4 objective's
  guidance: for a custom objective with `status:"anchored"`, look up its
  `ccmv4_ids[]` in `data/domain-mapping-guidance/ccmv4.json` and apply that
  objective's allow/deny classes and coverage ceilings, and record the anchor in
  the citation (`"anchored_to": "CCMv4 <id>"`, plus the `anchor_score`). For a
  custom objective with `status:"uncertain"` (best anchor below threshold), map it
  `UNCERTAIN` with a `review_reason` naming the weak anchor — never force-fit weak
  guidance. When several `ccmv4_ids` are returned, prefer the first (best-scoring)
  and only borrow a second's guidance when both clearly apply.

Pick the path by checking for the guidance file:

```bash
FW=ccmv4   # active framework slug (lowercased); from --framework or auto-detect
test -f data/domain-mapping-guidance/${FW}.json \
  && echo "per-domain fan-out (guidance found)" \
  || echo "single-pass fallback (no guidance for ${FW})"
```

Whichever path runs, the **output contract is identical** — `framework_mapping[]`,
`framework_coverage_summary` (incl. `by_domain`), and `quality_gate_results` in
`map-framework-mapped.json`, consumed unchanged by `map-assemble.py`,
`validate_state.py::check_framework_mapped`, and the schema.

---

## Prerequisites

```bash
test -f .service-approval/<slug>/04-map/map-framework-parsed.json && echo "framework: OK" || echo "ERROR"
test -f .service-approval/<slug>/04-map/map-controls-generated.json && echo "controls: OK" || echo "ERROR"
test -f .service-approval/<slug>/04-map/applicability-matrix.json && echo "applicability: OK" || echo "WARN: no matrix — all objectives assumed applicable"
```

Load all inputs:
```bash
python3 -c "
import json
fw = json.load(open('.service-approval/<slug>/04-map/map-framework-parsed.json'))
cg = json.load(open('.service-approval/<slug>/04-map/map-controls-generated.json'))
print(f'Framework: {fw[\"framework\"][\"name\"]} — {len(fw[\"framework_objectives\"])} objectives')
print(f'Controls: {len(cg[\"controls\"])}')
# Load applicability matrix if present
import os
matrix_path = '.service-approval/<slug>/04-map/applicability-matrix.json'
if os.path.exists(matrix_path):
    mx = json.load(open(matrix_path))
    na_count = sum(1 for v in mx['objective_applicability'].values() if not v['applicable'])
    print(f'Applicability matrix: {na_count} objectives pre-screened as N/A')
else:
    print('Applicability matrix: not present — all objectives assumed applicable')
"
```

---

## Context Available to This Skill

For each control, you have access to:
- `description` — what the control does
- `mechanism` — the AWS enforcement mechanism
- `security_rationale` — 2-3 sentence reasoning chain from mitigation goal to enforcement
- `framework_keywords` — domain/mechanism keywords for candidate matching
- `mitigation_intent` — canonical intent classification (e.g., `cmk_encryption`, `vpc_placement`)
- `security_domain` — security concern category (e.g., `data_protection_at_rest`, `network_isolation`)
- `condition_keys`, `actions`, `resource_types` — technical details
- `mitigation_ids`, `parameters_controlled` — traceability

**The objective's `allow_mechanisms` / `deny_mechanisms` (from the guidance KB) are the
authoritative eligibility gate — one vocabulary, the mechanism classes.** A control is
classified into mechanism classes from its `mechanism` + keywords (the same
`classify_control` the accuracy validator uses); it may map to an objective only if one
of its classes is in that objective's `allow_mechanisms` and none is in `deny_mechanisms`.
The `mitigation_intent` and `security_domain` tags are a **supporting hint** in the same
spirit (a control tagged `cmk_encryption` should not land on an IAM or network objective),
but they do not override the mechanism-class gate — where they disagree, the KB
allow/deny wins. Use the tags to build candidates fast, then confirm against the
allow/deny classes.

**The `security_rationale` field is your SECONDARY context.** It explains why this control exists
and what security goal it achieves. Use it to write the mapping rationale — but do NOT use it
to override the eligibility constraint from `mitigation_intent`.

---

## Pre-Phase: Applicability Matrix Screen (BEFORE per-objective mapping)

If `.service-approval/<slug>/04-map/applicability-matrix.json` exists, load it and
apply it as a hard pre-filter. The matrix lists **only** objectives with a
positive structural decision (an N/A, or a capability-unlocked applicable) plus
the service's `service_categories`; an objective **absent** from the matrix
defers to the KB default — never force it N/A.

1. For each entry in `objective_applicability` where `applicable: false`:
   - Set `status: "N/A"` immediately
   - Use the entry's `reason` (and `derived_from`) as the objective's N/A reason
   - Do NOT attempt to map any controls to it
2. For entries where `max_coverage` is set (e.g., `"Partial Coverage"`):
   - The objective IS mappable, but no control may exceed that coverage ceiling
3. Read `service_categories` from the matrix and carry it forward: when an
   objective's guidance carries a `by_service_category` block for one of the
   service's categories, that block's `mappable` / `allow_mechanisms` /
   `deny_mechanisms` / `coverage_ceilings` override the objective-level defaults
   for this run (e.g. LOG-02/LOG-09 are `default_na` for `serverless_compute`).
4. For objectives not in the matrix: apply the KB default (backward compatibility).

This screen runs BEFORE Phase 0 (domain-applicability guidance). Where both the matrix
and the Phase 0 guidance agree an objective is N/A, use the matrix reason. Where they
disagree, the **more restrictive** rule wins (i.e., if either says N/A, it's N/A).

---

## Mechanism Coverage Ceilings (HARD RULE — applies to ALL objectives)

**Full Coverage is opt-in, not the default.** Most controls partially satisfy an
objective; a control may claim `Full Coverage` only when its mechanism class
*fully implements the mechanism the objective names*. The ceilings are data in the
CCMv4 guidance file (`data/domain-mapping-guidance/ccmv4.json`), resolved per
mechanism class:

- Per-objective `coverage_ceilings[class]` (the tightest — e.g. CEK-03 caps
  `at_rest_encryption` at Partial because it needs classification-driven
  encryption, not merely CMK existence), else
- KB-level `mechanism_class_ceilings[class]` (e.g. `misconfig_detection` and
  `change_control` cap at Partial; `tagging_classification` caps at Supportive;
  preventive classes such as `access_control` / `network_isolation` /
  `at_rest_encryption` may reach Full), else
- `default_coverage_ceiling` (`Partial Coverage`).

A control that matches several *allowed* classes is judged by its strongest
legitimate class. The category override (Pre-Phase step 3) may tighten a ceiling
for the service's category.

**Key insight:** a detective Config rule cannot be `Full Coverage` for an
enforcement objective — it detects drift but does not prevent the non-compliant
state. `tools/validate/validate_domain_mapping_accuracy.py` reads these KB
ceilings and FAILs any MAPPED control that exceeds its effective ceiling, so
assign coverage from the KB, not from optimism.

---

## Phase 0: Domain Applicability Screen (run BEFORE per-objective mapping)

Before mapping any control, screen each objective for applicability to the
**target service class**. Several objectives describe controls a customer literally
cannot act on for a serverless / managed / infrastructure service — mapping any
control to them over-claims coverage. Mark these **N/A by default**; an override
requires an explicit `applicability_justification` plus a `reference_url`.

### 0.0 CCMv4: consult the per-objective guidance file (authoritative)

For CCMv4 the screen is driven **per objective** from
`data/domain-mapping-guidance/ccmv4.json`, NOT by a blunt domain-wide N/A list.
Each objective carries a `mappable` field and `allow_mechanisms` /
`deny_mechanisms` mechanism classes:

- `mappable` → the objective is legitimately satisfiable by a platform/infra
  config control for this service class. Map controls whose mechanism is in
  `allow_mechanisms`; never map a control whose mechanism is in `deny_mechanisms`.
- `default_na` → leave the objective **N/A** with the guidance `na_reason`, unless
  the service genuinely supports it — then override to `MAPPED` with both an
  `applicability_justification` and a `reference_url`.
- `conditional` → mappable **only** when a genuine service capability backs it;
  treat like `default_na` (provide the override fields) and map only
  `allow_mechanisms`-class controls.

`deny_mechanisms` is the discriminator that prevents keyword mis-maps — e.g.
**IVS-07** (secure migration *process*) denies `transit_encryption`, so a TLS
control never maps there; **LOG-12** (access-event logging) denies
`misconfig_detection`; **STA-12** (supply-chain agreements) denies
`access_control` (layer sharing). Because this is per-objective, a domain that was
once blanket-N/A can still have a genuinely-mappable objective — e.g. **BCR-04**
(business-continuity planning) is `mappable` to multi-AZ resilience controls even
though the rest of BCR (backup, DR exercises) stays `default_na`.

`tools/validate/validate_domain_mapping_accuracy.py` enforces this: a control
whose mechanism class is in an objective's `deny_mechanisms` (and not in
`allow_mechanisms`), or a `default_na` objective mapped without the override
fields, is a finding. The blunt mechanism→domain matrix and N/A-by-default list
in 0.1–0.3 below remain the **non-CCMv4 fallback** and a human-readable summary of
the same intent.

### 0.1 Mechanism is not the same as application code

The controls this pipeline generates are **platform / infrastructure config**
mechanisms: SCP, RCP, IAM policy, AWS Config rule, CloudFormation Guard, CloudFormation
Hook, OPA / Checkov, tag policy, KMS key policy, resource-based policy. None of them
inspect a workload's **application source code, dependencies, business logic, or
runtime behavior** — they evaluate IAM requests, resource configuration, or IaC
template properties.

**CloudFormation Guard, Config rules, SCPs, RCPs, and tag policies MAY satisfy** CCC
(change control), IVS (infrastructure security), CEK (encryption), LOG, IAM, and GRC
objectives. They may **NEVER** satisfy an **application-code** objective.

### 0.2 Mechanism → domain deny matrix (CCMv4)

This matrix is **framework-specific** (CCMv4) and lives in this sub-skill — it is not a
generic, service-agnostic rule. Consult it during candidate building: if a control's
`mechanism` is in the denied set for an objective, do NOT map it.

| Mechanism (platform/infra config) | Denied objectives | Why |
|---|---|---|
| CloudFormation Guard, AWS Config Rule, SCP, RCP, Tag Policy, OPA Policy, IAM policy | **AIS-02** (secure development), **AIS-04** (secure deployment/testing), **AIS-05** (application security testing), and any AIS objective about **application code, logic, dependencies, runtime behavior, or security testing** | These mechanisms inspect IAM requests, resource configuration, or IaC template properties — never the function's source code, dependencies, or runtime behavior. |

For an infrastructure / platform service, AIS code/testing objectives MUST be **N/A**
unless a control *directly* tests application code (none exist for a managed compute
service today). Use reason: `"Application-code security testing is the customer's
responsibility; <service> provides no control that inspects function/application
code."` (Note: AIS objectives about *interface*/API authentication that a request-time
control genuinely governs — e.g. an authorizer-config control — remain mappable; the
deny is specific to the application-**code**/testing objectives.)

### 0.3 N/A-by-default domains for serverless / managed / infrastructure services

Classify these domains as **N/A by default**. An objective in one of them may only be
`MAPPED` if the entry carries BOTH an `applicability_justification` (one sentence on
why the service genuinely supports it) AND a `reference_url` (a public AWS doc backing
the justification):

- **DCS** (Datacenter Security) — physical/datacenter controls are AWS-managed under
  the shared-responsibility model; the customer cannot act on them for a managed service.
- **UEM** (Universal Endpoint Management) — endpoint/device management does not apply
  to a serverless/managed service.
- **BCR** (Business Continuity & Operational Resilience) — backup/DR-exercise/continuity
  processes; only map where the service exposes a genuine backup/replication/DR API
  (multi-AZ is NOT backup, NOT a DR exercise).
- **IPY** (Interoperability & Portability) — cross-cloud data-portability objectives
  (e.g. IPY-03) do not apply unless the service provides a portability capability.
- **TVM vulnerability-metric objectives** (TVM-10-class: CVE counts, vuln metrics, mean
  time to remediate) — a managed/serverless service does not itself produce vulnerability
  metrics. **Keep TVM-05-style "works-with-Inspector" objectives mappable** — pairing the
  service with Amazon Inspector is legitimate and is NOT screened out.

Existing Rule 4 guidance for `HRS`, `STA`, and the organizational `GRC` objectives still
applies; this screen makes the DCS/UEM/BCR/IPY/TVM-metric set an **enforced** list rather
than soft guidance.

### 0.4 Recording the screen

For every N/A-by-default objective you leave N/A, write the `reason` explaining
non-applicability. For any you override to `MAPPED`, add the two extra fields on the
objective entry:

```json
{
  "objective_id": "BCR-01",
  "status": "MAPPED",
  "coverage": "Partially Covered",
  "reason": "...",
  "applicability_justification": "Lambda exposes versioned function code and alias routing that support a documented recovery procedure.",
  "reference_url": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html",
  "controls": [ ... ]
}
```

`tools/validate/validate_domain_applicability.py` reads `map-framework-mapped.json` and
flags (a) any platform-config control mapped to a denied application-code objective, and
(b) any N/A-by-default domain objective that is `MAPPED` without both fields.

---

## Phase 1: Map Controls to Framework Objectives

Iterate over EVERY `framework_objectives[]` entry. For each objective:

### 1.1 Per-objective analysis (REQUIRED)

**CRITICAL — Do NOT batch-map controls to entire domains.** Each individual objective MUST be
evaluated separately, even when objectives share a domain. The rationale for mapping CTRL-X to
IAM-01 must be different from IAM-02, because the objectives ask different things.

**Step 1: Read the objective specification.** For each framework objective, read its full title
AND specification text. Understand what the objective actually requires — not just which domain
it's in.

**Step 2: Build candidate control list.** Use `framework_keywords` from each control to build
an initial candidate list. Then read each candidate's `security_rationale` to assess fit.

**Step 3: Evaluate each candidate individually.** For each candidate control:
- Does this control's specific mechanism directly address what the objective is asking for?
- Read the `security_rationale` — does the reasoning chain connect to the objective's requirement?
- Write a 1-sentence `rationale` explaining the SPECIFIC connection.

**Authoring rule — state only what is verified.** The rationale must
describe the *mechanism* of the mapped control and the objective it
serves. Do NOT make causal claims ("ensures", "guarantees", "prevents
all", "completely blocks", "fully mitigates") — those exceed what a
single control can be verified to do. If you cannot honestly write a
verified mechanism-to-objective sentence, omit the mapping or hedge to a
broader objective-level statement and lower the coverage_level
accordingly.

**Rationale quality rules:**
- GOOD: "SCP denies CreateMemory without KmsKeyArn at request time —
  supports the encryption-key generation objective."
- BAD: "Addresses Encryption and Key Management Policy and Procedures"
  (just restates the objective title)
- BAD: "Addresses Key Generation" (too vague, no mechanism)
- BAD: "Guarantees no resource is created without encryption" (causal
  overreach — a single SCP can be bypassed by exempted principals or by
  service-internal calls)
- The rationale MUST mention the control's mechanism (SCP deny, Config
  rule check, KMS key policy, etc.)
- The rationale MUST NOT be the objective title or a rephrasing of it
- Keep it to one short sentence; broader, verified statements beat
  speculative specifics.

**Step 4: Assign coverage level based on how directly the control addresses the objective:**
- **Full Coverage**: The control's mechanism directly implements what the objective requires
  (e.g., KMS key policy -> CEK-10 "Key Generation")
- **Partial Coverage**: The control contributes to the objective but doesn't fully implement it
  (e.g., Config CMK check -> CEK-09 "Encryption Audit" — detects but doesn't enforce)
- **Supportive**: The control is tangentially related through shared domain only
  (e.g., tag policy -> IAM-03 "Identity Inventory" — tags support inventory but aren't identity management)

**Step 5: If no controls have a specific rationale**, mark the objective as:
- **N/A** with a reason (e.g., "Managed by AWS under shared responsibility",
  "Organisational HR control", "No backup/DR API for this service")

**Step 6: Map defense-in-depth twins — do NOT stop at one control per objective.**
Multiple control IDs legitimately mapping to one objective is **expected**, not spray:
a single mitigation is commonly implemented as a preventive/proactive twin (SCP, RCP,
CloudFormation Guard) plus a detective twin (AWS Config rule) plus a responsive twin (SSM
Automation), and each is a distinct layer of defense. When an AWS Threat Model control shares one of
its `mitigation_ids` with a control you already mapped to an objective, evaluate that
control for the **same** objective too:
- Map it as its **own row** with its own `rationale` describing *its* mechanism (the Config
  rule detects drift; the SSM automation remediates it) and the **same** `citation` — copy
  the shared mitigation's `mitigation_alias` / `mitigation_uuid` / `mitigation_statement`
  (verbatim) and `mitre_techniques[]` exactly as on the twin's citation.
- Its `coverage_level` is set from **its own** mechanism class and the KB ceiling, not the
  twin's — a detective Config rule or responsive SSM automation is `Partial Coverage` or
  `Supportive`, never `Full Coverage`, so a defense-in-depth twin rarely trips Rule 6
  (≤5 Full Coverage per objective). It maps only if its mechanism class is in the
  objective's `allow_mechanisms` and none is in `deny_mechanisms` (same eligibility gate as
  any other control).
- Do NOT banish a redundant twin to an "uncited" / suggestions list just because a sibling
  already maps. **Every AWS Threat Model-sourced control must appear as a MAPPED row under an
  objective its mechanism class legitimately satisfies** (or, only if genuinely no objective
  fits its mechanism, be left unmapped — never dumped to the non-AWS Threat Model suggestions
  section). The assemble step lists ONLY non-AWS Threat Model (`trace_source != "threat_model"`) controls in
  "Suggestions for Review"; an AWS Threat Model control that reaches no objective is a mapping gap to
  fix here, not a suggestion.

### 1.2 Objective coverage rollup (coverage-level consistency)

After mapping controls to an objective, assign the objective's overall coverage using these HARD RULES:

| Highest coverage_level among mapped controls | Objective coverage |
|----------------------------------------------|-------------------|
| Full Coverage                                 | Fully Covered     |
| Partial Coverage (no Full Coverage)           | Partially Covered |
| Supportive (no Partial or Full)               | Supportive Only   |
| No controls                                   | N/A               |

- `Fully Covered` requires at least one `Full Coverage` control
- `Partially Covered` requires at least one `Partial Coverage` control
- `Supportive Only` is the maximum for objectives with only `Supportive` controls
- Never assign `Fully Covered` when all controls are `Supportive`

### 1.3 Citation-as-gate (REQUIRED for every MAPPED row)

Every `MAPPED` control row MUST carry a `citation` object that shows its work —
the specific evidence that this control satisfies this objective. This is what
converts "silently wrong" into "explicitly uncertain."

```json
"citation": {
  "control_id": "CTRL-RES-PRV-001",
  "mechanism_class": "at_rest_encryption",
  "objective_requirement": "<the specific sub-requirement of THIS objective the control satisfies>",
  "mitigation_alias": "Mitigation.LAMBDA.Function.3",
  "mitigation_uuid": "…",
  "mitigation_statement": "<the mitigation's AWS Threat Model statement, VERBATIM — copy from the control's threaded mitigation_statement, do not paraphrase>",
  "mitre_techniques": ["T1530"],
  "source": "threat_model"           // threat_model | assessment_gap | aws_doc
}
```

When `source == "threat_model"`, copy `mitigation_statement` **verbatim** from the
control's threaded `mitigation_statement` field (resolved deterministically from
the AWS Threat Model export by map-generate-controls). A deterministic validator confirms
this text appears verbatim in the AWS Threat Model export's `mitigations[].statement`; a
paraphrased or invented statement FAILs the map gate. If you cannot copy the
statement verbatim, omit the `mitigation_statement` field rather than paraphrase.

Decide per row (the row's `status` is the signal — there is no separate
confidence score field):

- **You can name the concrete linkage** (this control's mechanism ↔ this
  objective's named sub-requirement, backed by an AWS Threat Model mitigation or an AWS
  doc): emit `status:"MAPPED"` with the full citation
  (`objective_requirement` + `source` are what make it concrete).
- **You believe there is a relationship but cannot produce that concrete
  linkage**: DO NOT assert it as MAPPED and DO NOT silently drop it. Emit the row
  with `status:"UNCERTAIN"` and a `review_reason` naming what linkage is missing.
  UNCERTAIN rows are surfaced in a "review needed" section, excluded from
  coverage %, and never block the phase — they are the honest middle between a
  confident map and an N/A.

`validate_domain_mapping_accuracy.py` FAILs a `MAPPED` row that carries no
concrete citation (`objective_requirement` + `source`): fix the citation or
demote the row to `UNCERTAIN`. It does NOT fail an `UNCERTAIN` row.

### 1.4 Traceability (attach the AWS Threat Model source + MITRE)

Each control was threaded with `mitigation_alias`, `mitigation_uuid`,
`mitigation_statement`, and `mitre_techniques[]` in map-generate-controls (Phase
3c, resolved deterministically from the AWS Threat Model source). Copy those onto the
citation so the rendered `framework-mapping.md` can cite the exact AWS Threat Model
mitigation and MITRE techniques behind the mapping, and so the citation can be
provenance-checked against the export. A control with `trace_source:"assessment_gap"`
has no AWS Threat Model alias — set `source:"assessment_gap"` and leave the
mitigation/MITRE fields empty.

---

## Phase 2: Quality Gates (MANDATORY)

All rules below are HARD RULES — violations are validation failures that MUST be fixed before
writing output.

### Rule 1 — Coverage-level consistency
Already enforced in Phase 1 Step 5. Verify with validation script.

### Rule 2 — No domain-level spray mapping
If **any** two consecutive objectives in the same domain have the EXACT same set of control IDs
mapped, this is a spray signal requiring review. If **three or more** consecutive objectives in
the same domain share identical control sets, this is a hard validation failure.

Each objective within a domain asks a different question — the control set SHOULD differ. When
objectives share controls, each mapping MUST have a distinct rationale referencing the specific
objective requirement. Iteration 15 had 13 spray clusters (e.g., AIS-01 through AIS-06 all
mapping to the same 2 controls, BCR-01 through BCR-11 all mapping to 1 control).

**How to fix:** For each spray cluster:
1. Read each objective's specification — they ask different things
2. For objectives where the controls genuinely apply, write unique rationales
3. For objectives where controls DON'T apply, remove the mapping and mark N/A if no other controls fit
4. For domains like BCR (backup/DR) where the service has no relevant API, mark most objectives N/A
   rather than mapping a single weak control to every objective in the domain

### Rule 3 — No single control mapped to >15 objectives
If a control appears in more than 15 framework_mapping entries, review every mapping individually.
Most controls are specific enough that they should map to 3-8 objectives. >15 indicates keyword
spray, not genuine alignment.

**How to fix:** For each mapping where this control appears:
1. Re-read the objective specification
2. Re-read the control's `security_rationale`
3. If you cannot write a specific rationale connecting them, REMOVE the mapping
4. Prioritize: keep the mapping where the control's mechanism most directly addresses the objective
5. Target: each control should map to 3-12 objectives

### Rule 4 — Organizational process domains
Framework objectives about organizational processes MUST NOT be mapped to purely technical controls:

- **BCR domain** (BCR-01 to BCR-11): Cover backup plans, DR exercises, communication plans.
  Only map to controls that DIRECTLY implement backup, replication, or DR capabilities —
  NOT generic infrastructure controls. Multi-AZ != backup. Multi-AZ != DR exercise.
- **HRS, DCS, UEM, STA domains**: Almost always N/A for cloud service technical controls.
  DCS/UEM are enforced as N/A-by-default in the Phase 0 screen.
- **GRC domain**: Only map to controls implementing governance automation (Config rules for
  compliance, tag policies for classification) — not operational controls.
- **AIS domain (application/interface security):** AIS objectives about application
  code, logic, dependencies, runtime behavior, or security testing (e.g. AIS-02,
  AIS-04, AIS-05) MUST be **N/A** for an infrastructure/platform service unless a
  control *directly* tests application code. CloudFormation Guard, AWS Config rules,
  SCPs, RCPs, and tag policies are **platform/infrastructure config** mechanisms — they
  MAY satisfy CCC (change control), IVS (infra security), CEK (encryption), LOG, IAM
  objectives, but they may **never** satisfy an application-code AIS objective (they do
  not inspect function source, dependencies, or runtime behavior). Map AIS code/testing
  objectives to N/A with reason "Application-code security testing is the customer's
  responsibility; <service> provides no control that inspects function/application
  code." See the Phase 0 mechanism→domain deny matrix.

### Rule 5 — Rationale required and mechanism-consistent
Every control-to-objective mapping MUST include a `rationale` string. Additionally:

**5a — Rationale-control consistency:** The rationale MUST describe the mechanism of the
MAPPED control, not a different control. After writing each mapping:
1. Look up the mapped `control_id` in the controls
2. Confirm the rationale describes THAT control's specific mechanism
3. If the rationale describes a different control's mechanism, fix the rationale or the control_id
4. Common error: mapping CTRL-RES-PRV-004 (VPC endpoint policy) but writing a rationale about
   aws:SecureTransport (which is CTRL-RES-PRV-003)

### Rule 6 — Max controls per objective at Full Coverage
If more than 5 controls map to a single objective at `Full Coverage`, review each individually.
Bulk full-coverage mapping indicates overly broad keyword matching.

### Rule 7 — Orphaned control review
After building the initial mapping, check for controls not mapped to any objective. For each:
1. Read the control's mechanism and `security_rationale`
2. Search framework objectives for alignment by mechanism (not just domain keyword)
3. If a genuine match exists, add the mapping with a specific rationale
4. An AWS Threat Model-sourced control (`trace_source == "threat_model"`) that shares a mitigation with an
   already-mapped control is a **defense-in-depth twin**, not an orphan — map it to the
   same objective per Phase 1 Step 6 rather than leaving it orphaned.
5. Only leave a control orphaned if it truly has no framework objective match its mechanism
   class satisfies. A leftover AWS Threat Model orphan is a signal to re-check Step 6 — it must not be
   silently dropped or pushed to the non-AWS Threat Model "Suggestions for Review" section (that
   section is `trace_source != "threat_model"` controls only).
6. You MUST record each genuinely unmatched control in `unmapped_control_reviews[]`:
   `control_id`, `status: "no_framework_match"`, a control-specific `rationale`,
   and non-empty `reviewed_objective_ids` naming the closest objectives reviewed.
   Explain why the mechanism does not satisfy those objectives. A valid threat-model
   mitigation need not fit the customer's selected framework; retain the control
   without claiming framework coverage. Do not invent a mapping to clear Rule 7.
   Unexplained omissions, duplicate reviews, and reviews for unknown or already
   referenced controls fail validation.

---

## Phase 3: Domain Keyword Guide

Use as a STARTING POINT for candidate controls, then apply per-objective evaluation:

| Keywords in objective | Primary domain | Candidate control types |
|----------------------|---------------|----------------------|
| Access/Identity/Role/Principal/Auth | IAM | IAM policies, SCPs, permission boundaries |
| Encryption/KMS/CMK/TLS/Certificate | CEK | KMS key policies, encryption configs |
| Network/VPC/Subnet/Endpoint/Firewall | IVS | VPC endpoints, SGs, network policies |
| Logging/CloudTrail/CloudWatch/Audit | LOG | CloudTrail, CloudWatch, logging configs |
| Tagging/Owner/Classification/Governance | GRC | Tag policies, Config rules |
| Config Rule/Compliance | A&A | Config rules, conformance packs |
| Backup/Recovery/Resilience/Multi-AZ | BCR | Only if service has backup/DR API |
| Change/Configuration/Baseline/Drift | CCC | Config rules, Guard rules, drift detection |
| Vulnerability/Patch/Scan | TVM | Vulnerability scanning, patching automation |
| Incident/Forensics/Response | SEF | CloudTrail, alarms, runbooks |
| Data/Privacy/PII/Classification | DSP | Encryption, data lifecycle (see DSP note below) |
| AI/ML/Model/Guardrail/Prompt | AIS | Only secure deployment pattern controls |

**DSP data-classification note (DSP-03, DSP-04).** These objectives concern the
**sensitivity of data** (PII, confidential, public) — classifying *data*, not resources.
A tag-policy / `aws:RequestTag` / resource-ownership-tag control (e.g. "tag resources as
security-owned vs platform-owned") classifies the **resource**, not the data inside it,
and does **NOT** satisfy DSP-03/04. Mark DSP-03/04 **N/A** unless the service provides a
genuine data-sensitivity classification capability (e.g. Macie-style content
classification) — a managed compute service such as Lambda does not. Do not map a tag /
SCP / Config control to DSP-03/04 on a keyword match for "classification."

---

## Phase 4: Write Output

**Per-domain fan-out (CCMv4):** each per-domain mapping subagent writes a
**partial** for its domain to
`.service-approval/<slug>/04-map/_domains/<DOMAIN>.json` containing only that
domain's objective entries — same per-objective entry shape as `framework_mapping[]`
below (a bare list, or an object with a `framework_mapping` key; both are
accepted). It does NOT write `map-framework-mapped.json` directly. After all
domains complete, the orchestrator runs the deterministic merge:

```bash
python3 scripts/merge-domain-mappings.py --slug <slug>
```

The merge concatenates the partials in canonical CCMv4 domain order, recomputes
`framework_coverage_summary` (incl. `by_domain`) and the cross-domain quality
gates (Rule 2 spray / Rule 3 ≤15-per-control / Rule 5 rationale / Rule 6 / Rule 7
orphans), verifies every parsed objective appears exactly once, and writes
`map-framework-mapped.json`. The cross-domain gates run here, not in the
per-domain subagents (a single subagent cannot see another domain's controls).
The merged file is byte-shape identical to the single-pass output below.

The merge writes diagnostic output and exits nonzero when a quality gate fails.
If Rule 7 fails, you MUST complete the review above, repair genuine mappings in
the domain partials, and write the remaining reviews as a JSON array to
`04-map/unmapped-control-reviews.json`. Re-run the merge (it reads that file
automatically), then `validate_state.py` on `map-framework-mapped.json`.
Do not proceed to assembly until both pass. Single-pass mapping includes the
same array directly as `unmapped_control_reviews` in its output.

**Single-pass (non-CCMv4):** write
`.service-approval/<slug>/04-map/map-framework-mapped.json` directly, in this exact
shape:

```json
{
  "schema_version": "1.0",
  "framework_mapping": [
    {
      "objective_id": "IAM-01",
      "domain": "Identity & Access Management",
      "title": "Identity and Access Management Policy and Procedures",
      "status": "MAPPED",
      "coverage": "Fully Covered",
      "reason": "Multiple preventive and detective controls enforce IAM policies for this service",
      "controls": [
        {
          "control_id": "CTRL-ACC-PRV-001",
          "coverage_level": "Full Coverage",
          "rationale": "Permission boundary restricts service actions to approved set, directly implementing least-privilege access provisioning",
          "citation": {
            "mechanism_class": "access_control",
            "objective_requirement": "provisioning identities with least privilege",
            "mitigation_alias": "Mitigation.LAMBDA.Function.6",
            "mitigation_uuid": "…",
            "mitre_techniques": ["T1078"],
            "source": "threat_model"
          }
        }
      ]
    },
    {
      "objective_id": "IAM-13",
      "domain": "Identity & Access Management",
      "title": "...",
      "status": "UNCERTAIN",
      "coverage": "N/A",
      "reason": "Candidate control relates to authorization but the specific sub-requirement linkage could not be evidenced.",
      "review_reason": "No AWS Threat Model mitigation or AWS doc concretely ties this control's mechanism to the objective's uniquely-identified-user requirement.",
      "controls": [
        {
          "control_id": "CTRL-ACC-PRV-002",
          "coverage_level": "Supportive",
          "rationale": "Resource policy scopes principals — may support user identification but the linkage is not concrete.",
          "review_reason": "cannot cite the specific sub-requirement satisfied"
        }
      ]
    },
    {
      "objective_id": "DCS-01",
      "domain": "Datacenter Security",
      "title": "...",
      "status": "N/A",
      "coverage": "N/A",
      "reason": "Physical datacenter security is managed by AWS under the shared responsibility model",
      "controls": []
    }
  ],
  "framework_coverage_summary": {
    "total_objectives": 197,
    "mapped": 135,
    "not_applicable": 60,
    "uncertain": 2,
    "by_domain": {
      "IAM": { "total": 16, "mapped": 13, "not_applicable": 2, "uncertain": 1, "coverage_percentage": 81.3 },
      "CEK": { "total": 21, "mapped": 19, "not_applicable": 2, "uncertain": 0, "coverage_percentage": 90.5 }
    }
  },
  "quality_gate_results": {
    "rule_1_coverage_level_consistency": "PASS",
    "rule_2_no_spray": "PASS",
    "rule_3_max_15_per_control": "PASS",
    "rule_4_org_process_domains": "PASS",
    "rule_5_rationale_present": "PASS",
    "rule_6_max_5_full_per_objective": "PASS",
    "rule_7_orphan_review": "PASS",
    "orphaned_controls": []
  }
}
```

**Schema rules:**
- `framework_mapping` MUST include ALL objectives (mapped + N/A + uncertain) — every one from map-framework-parsed.json
- Each entry MUST have: `objective_id`, `domain`, `title`, `status`, `coverage`, `reason`, `controls`
- `status` MUST be EXACTLY `"MAPPED"`, `"N/A"`, or `"UNCERTAIN"` — case-sensitive, no
  substitutes. Do NOT use `"UNMAPPED"`, `"NOT_APPLICABLE"`, `"n/a"`, or any other variant.
  `MAPPED` = a confident, cited mapping; `N/A` = not applicable; `UNCERTAIN` = a
  believed-but-uncitable relationship, surfaced for review, excluded from coverage %,
  never blocking. An `UNCERTAIN` row MUST carry a `review_reason`.
- `coverage` MUST be one of `"Fully Covered"`, `"Partially Covered"`, `"Supportive Only"`, `"N/A"` (use `"N/A"` for UNCERTAIN rows — they do not count toward coverage)
- `controls[]` MUST be array of `{control_id, coverage_level, rationale}` objects; a `MAPPED` row's controls MUST additionally carry a concrete `citation` (`objective_requirement` + `source`; see Phase 1.3) — otherwise the row must be `UNCERTAIN`
- `coverage_level` MUST be EXACTLY one of `"Full Coverage"`, `"Partial Coverage"`, `"Supportive"`
  — these are the only valid values. Do NOT emit `"High"`, `"Medium"`, `"Low"` or any other variant.
- `rationale` is REQUIRED on every control mapping; `citation` is REQUIRED on every confident MAPPED control (else the row must be UNCERTAIN)
- `framework_coverage_summary` MUST be populated with per-domain breakdown (incl. `uncertain`)
- `quality_gate_results` MUST report PASS/FAIL for each rule
- `orphaned_controls` lists control IDs not mapped to any objective

---

## Framework-Agnostic Design

This skill works with ANY control framework, not just CCMv4. The framework objectives
come from `map-framework-parsed.json` which is produced by the `map-parse-framework`
sub-skill. Supported formats:
- CCMv4 (Cloud Controls Matrix v4)
- NIST 800-53 rev5
- CIS Benchmarks
- ISO 27001:2022
- Custom frameworks (any Excel/JSON/Markdown with objective IDs + descriptions)

The mapping logic uses the objective's `description` and `control_specification` text
to match against control `rationale` and `description`. No framework-specific keywords
are hardcoded — the same coverage-level scoring works across all frameworks.

**Quality cap:** No control may map to more than 5 objectives. If a control matches >5,
keep only the 5 highest-coverage-level matches. This prevents spray-mapping where generic
controls (like tagging) map to every objective.

## Validate Output

Output validation runs automatically via PostToolUse hook. The JSON Schema (see Schema above) hard-fails on status / coverage / control_id drift per the enum details at "Schema rules". `validate_state.py::check_framework_mapped` retains the 7 quality-gate rules (Rule 1 coverage-level consistency, Rule 2 domain spray, Rule 3 ≤15 objectives per control, Rule 5 rationale required, Rule 6 ≤5 Full Coverage per objective, Rule 7 orphaned controls) plus cross-file lookups against map-controls-generated and map-framework-parsed.

The Phase 0 domain-applicability screen is checked by two CCMv4-specific
validators, both run in the map review gate (Step 3e of `service-approval`):

- `tools/validate/validate_domain_applicability.py` flags platform/infra-config
  controls mapped to application-code AIS objectives (AIS-02/04/05), N/A-by-default
  domain objectives (DCS/UEM/BCR/IPY, TVM-10-class) mapped without an
  `applicability_justification` + `reference_url` override, and resource-tag
  controls mapped to data-sensitivity objectives (DSP-03/04). N/A-by-default within
  that scope is read per-objective from `data/domain-mapping-guidance/ccmv4.json`
  (so a guidance-`mappable` objective such as BCR-04 is no longer blanket-flagged).
- `tools/validate/validate_domain_mapping_accuracy.py` reads the guidance file and
  the sibling `applicability-matrix.json` and flags, for **every** objective: a
  control whose mechanism class is in the objective's `deny_mechanisms` (and not in
  `allow_mechanisms`); a `default_na` objective mapped without the override fields;
  a row MAPPED for an objective the matrix marked not-applicable for the service's
  category; a control whose `coverage_level` exceeds the KB ceiling for its class;
  and a confident `MAPPED` control that carries no concrete `citation` (which must
  be `UNCERTAIN` instead). `UNCERTAIN` rows are advisory — surfaced, never failed.

## Print Summary

```
Map (Framework Mapping) complete:
  Framework: {name} — {total} objectives
  Mapped: {mapped} ({mapped_pct}%)
  N/A: {na}
  Uncertain (review needed): {uncertain}
  Quality gates: all PASS
  Orphaned controls: {count}
  Output: .service-approval/<slug>/04-map/map-framework-mapped.json
```
