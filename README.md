# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates a pipeline (Intake → Assess → Research → Validate → Map → Recommended Guidance → Summarize) and maps everything to CCMv4. Other frameworks (NIST 800-53, CIS, ISO 27001) remain available behind the `--framework=<type>` CLI flag for advanced operators; the interactive intake narrows to CCMv4. It recommends the controls + IaC; you deploy them yourself.

---

## Mapping accuracy: a deterministic, citation-gated layer

The framework-mapping phase constrains what each control may claim, so a control
is only mapped to an objective it genuinely satisfies — and every confident
mapping shows its evidence. The controls that drive it:

### Service applicability screen

Before mapping begins, the tool derives the service's capabilities and category
from the Canopy threat model and screens objectives for applicability:

- **`data/service-capability-rules.json`** — capability flags derived from Canopy
  mitigation *statements only* (never entity description prose, which describes
  the resource but asserts no customer capability). Each flag is three-valued —
  present / absent / unknown — with a required polarity so "AWS manages patching"
  cannot assert a customer capability.
- **`data/service-category-rules.json`** — the service's category label(s)
  (serverless_compute, storage, database, networking, …) derived from those
  flags; a service may hold several.
- **`data/objective-applicability-rules.json`** — marks an objective N/A only for
  a positive structural reason (an organizational objective, or a category fact
  such as "serverless compute has no customer-managed OS to patch"). An unknown
  capability never forces N/A — it defers to the guidance-KB default.
- **`scripts/compute-applicability-matrix.py`** — takes a Canopy JSON and writes
  an applicability matrix in which every N/A cites the rule and evidence
  (`derived_from`) that drove it.

Datacenter (DCS), endpoint (UEM), HR (HRS), and patching (TVM) objectives are
automatically N/A for serverless services; backup objectives (BCR-08) are N/A for
serverless unless a backup/replication API is definitively present. No capability
is ever inferred from descriptive prose.

### Canopy traceability (alias + UUID + statement + MITRE)

**`scripts/canopy_trace.py`** resolves, per Canopy mitigation, its alias, UUID,
verbatim statement, and MITRE ATT&CK techniques — walking `mitigation → THREAT
mapping → threat → FRAMEWORK mapping` entirely inside the golden-source file (no
external lookup). map-generate-controls threads these onto each control so the
final mapping can cite the exact Canopy mitigation and MITRE technique behind
every row. The **control catalog** then prints, under each control, its Canopy
alias, UUID, and verbatim statement (control IDs are minted by the tool because
Canopy carries none); a control derived from an assessment gap rather than a
Canopy mitigation is labelled a recommendation.

### Citation verification against Canopy

**`tools/validate/validate_canopy_facts.py`** confirms every Canopy-cited row is
factual against the provided Canopy export: the cited alias exists, its governed
operations are consistent with the control's actions, and any quoted mitigation
statement appears **verbatim** (normalized for case/whitespace/punctuation) in
the export's `mitigations[].statement`. It runs `--strict` in the map and
post-generate gates, so a fabricated alias, drifted operation, or invented
statement blocks the phase. `MAPPED` rows are checked; `UNCERTAIN` rows and
assessment-gap citations are exempt.

### Per-domain guidance with coverage ceilings

**`data/domain-mapping-guidance/ccmv4.json`** records, per objective, which
mechanism classes may (`allow_mechanisms`) or must never (`deny_mechanisms`)
satisfy it, plus coverage ceilings. Full Coverage is opt-in: a class that only
partially implements an objective's named mechanism (a detective Config rule, or
CMK-existence for classification-driven encryption) is capped at Partial.
Per-service-category overrides (`by_service_category`) let one objective behave
differently for, say, a serverless vs a storage service.

### Citation-as-gate + UNCERTAIN status

Every confident `MAPPED` row carries a `citation` (the specific objective
sub-requirement satisfied + its source — Canopy mitigation, reference example, or
AWS doc). A relationship the mapper believes but cannot cite concretely is emitted
as **`UNCERTAIN`** with a `review_reason` — surfaced for review, excluded from
coverage %, never silently asserted or dropped.

**`tools/validate/validate_domain_mapping_accuracy.py`** is the deterministic
backstop: it FAILs (1) a row mapped to a not-applicable objective, (2) a coverage
level over the mechanism-class ceiling, (3) a denied-class mis-map, and (4) a
confident `MAPPED` row with no concrete citation (which must be `UNCERTAIN`).

### Report format

`framework-mapping.md` lists **every** framework objective sequentially by
`ID: Title` under its domain — mapped objectives with their control table, N/A
objectives with their reason, and UNCERTAIN objectives flagged for review — so a
reader can scan top-to-bottom and see each objective's disposition (a render-time
check asserts no objective is dropped). The coverage summary shows only Total /
Mapped / Not Applicable / Uncertain. Controls that could not be cited to an
objective are surfaced as **potential recommendations** with a deterministic
"why not yet cited" rationale (covered by a sibling control, candidate objectives
ruled out, or assessment-gap recommendation) rather than reported as lost.
Mitigation-level rollups (coverage-gap and mitigation-traceability tables) live in
`mapping-results.json` for downstream tooling and are not rendered in the
customer reports.

### Custom / non-CCMv4 frameworks

**`scripts/anchor-custom-framework.py`** anchors a custom framework's objectives to
their nearest CCMv4 objective(s) by description (a deterministic TF-IDF cosine), so
the CCMv4 guidance can be reused. A weak anchor yields an `UNCERTAIN` mapping rather
than a confident wrong one.

### Verify

```bash
# Compute the applicability matrix from a Canopy JSON
python3 scripts/compute-applicability-matrix.py <canopy-json> --output /tmp/matrix.json

# Validate a mapping against ceilings + citations + applicability
python3 tools/validate/validate_domain_mapping_accuracy.py <map-framework-mapped.json> \
  --controls <map-controls-generated.json> --matrix <applicability-matrix.json>
```

---

## What it produces

- **Control mapping** - Maps threats and controls to security and compliance frameworks (e.g CCMv4, MITRE)
- **Proactive controls** — CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies
- **Preventive controls** — SCPs, RCPs, permission boundaries, IAM/resource policies, **anchored to published AWS sample policies** (see "Preventive controls are reference-anchored" below)
- **Detective controls** — Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer
- **Auto-remediation** — Lambda remediators, SSM runbooks, Step Functions workflows
- **Compliant IaC** — CDK (TypeScript), Terraform (modular), CloudFormation, CDK for Terraform
- **Validation** — Tier 1 static checks + Tier 2 AWS API policy validation (automatic via hooks)
- **Summary Report** - Summarizes the overall service onboarding accelerator output on AWS


Output lands in `.service-approval/<service-slug>/` (per-service layout) in your working directory:
```
.service-approval/<service-slug>/
  00-intake/              ← intake manifest
  01-assess/              ← SAR facts, checkpoints, assessment summary
  02-research/            ← research.json (merged from 4 sub-skills)
  03-validate/            ← validated.json
  04-map/                 ← mapping-results.json, controls-catalog.md, framework-mapping.md
  05-recommended-guidance/ ← all generated control artifacts (preventive, proactive, detective, responsive, IaC)
  06-summarize/           ← SUMMARY-REPORT.md
  mcp-calls.log           ← MCP call audit log
```

---


### Key Features

The pipeline runs as 24 discrete skills under [`skills/`](skills/). Each one is a standalone [Agent Skills](https://agentskills.io) folder with its own `SKILL.md` — so the same skills work across Claude Code, Kiro, GitHub Copilot, and any other agentskills.io-compatible client.

### Preventive controls are reference-anchored

Preventive controls are anchored to existing AWS sample policies and reference
repositories; where no reference covers an objective, the tool does not invent a
preventive control — it points to the reference or recommends a detective/proactive
control instead. Every emitted policy is an example to be verified against the
service authorization guide before deployment.

Concretely, preventive generation runs as a gated sub-pipeline: a recommender
decides each objective's enforcement mechanism (SCP / RCP / IAM, or "not
preventable → detective"), anchors each decision to a published example, the
authors adapt that example to the target service, and a root-cause critic proves
every emitted policy both resolves to a reference and actually enforces its
control (a real condition key gates the action). The reference library is curated
from public AWS repositories, including:

- [`aws-samples/service-control-policy-examples`](https://github.com/aws-samples/service-control-policy-examples)
- [`aws-samples/resource-control-policy-examples`](https://github.com/aws-samples/resource-control-policy-examples)
- [`aws-samples/data-perimeter-policy-examples`](https://github.com/aws-samples/data-perimeter-policy-examples)
- [`aws-samples/example-permissions-boundary`](https://github.com/aws-samples/example-permissions-boundary)
- [`aws-samples/iam-access-analyzer-custom-policy-check-samples`](https://github.com/aws-samples/iam-access-analyzer-custom-policy-check-samples)

The sourcing for each generated preventive policy is recorded in the artifact's
`_metadata.reference` (repo + example id + source URL), so the basis for every
control is visible and auditable.

Some preventive mechanisms are **referred rather than authored** by design,
because no vetted example library exists to anchor them to:

- **Trust policies** are refer-only. A role's trust policy and the cross-service
  confused-deputy prevention it implements (`aws:SourceArn` / `aws:SourceAccount`
  on `sts:AssumeRole`) are documented per-service, so the tool points to that
  documented pattern rather than synthesizing a policy body.
- **Permission boundaries** are refer-by-default. A boundary only takes effect
  when the organization attaches one to its principals, so the tool refers to the
  published boundary scaffold unless the run explicitly opts in.

This is an intentional stance: the tool refers rather than authors wherever a
vetted reference library is absent, instead of inventing a policy that looks
plausible but is unanchored.

### Source priority

When the tool needs an external fact or citation, it consults sources in one
fixed priority order and cites the highest-priority source that supports the
claim — the same order everywhere facts are pulled (research, validation,
mapping, and preventive recommendation):

1. **Canopy** — the customer-provided mitigation/threat export, when present. It
   is the authoritative source of *what* matters for the service (control intent)
   and the top citation.
2. **AWS Control Catalog API** — the control→objective authority for controls the
   catalog covers.
3. **Service-specific AWS documentation** — the target service's own pages only;
   never general blog posts or third-party write-ups.

The reference-repo library above supplies the *vetted policy body* for a
preventive control, adapted under the Canopy (or catalog/doc) intent — Canopy
sets what to enforce and is the top citation; the reference repo supplies how.
Each mapping row and each preventive decision records a typed `citation` whose
`type` (`canopy` / `reference` / `catalog` / `service-doc`) reflects the
highest-priority source that backs it.

### How the tool builds confidence

The pipeline does not issue an approve/deny verdict; instead, every run takes the
same concrete, verifiable steps so a reviewer can see exactly what was checked.
These steps are the same on every run, so they are documented here once rather
than repeated in each Summary Report:

- **Capability verification** — every service capability, API parameter, IAM
  action, and condition key is verified against authoritative AWS sources before
  any control is generated; unverified items are reported, not silently dropped.
- **Validators run** — integrity, reference-anchor, preventability/root-cause, and
  control-mapping cross-checks run at the map and generate review gates and again
  in the Stop hook; their pass/fail is recorded in `pipeline.log`.
- **Reference anchoring** — every preventive control either resolves to a public
  AWS reference example or is explicitly marked not-anchored with a stated reason.

Each Summary Report does **not** repeat this generic list. Instead it carries only
the **run-specific** data a reviewer needs:

- A **Preventive Coverage** accounting: a file-backed
  (`preventive-coverage.json`) count of how many preventive objectives have a
  policy authored from a reference example, how many point to a reference the
  customer applies, and how many are covered by detective controls instead — each
  count traceable to its control id and citation, plus the concrete apply/adapt
  guidance for each authored or referred policy.

### Validation efforts

Validation runs at several layers:

- **Two review gates.** A post-map gate checks the mapping is citable and its
  prose stays objective-level (the prose lint scans both the JSON and the
  rendered `.md` files for over-claims and upward re-wording), runs the
  deterministic semantic checks (every referenced control resolves, every mapped
  objective exists, no control claims an unverified action/condition key), and
  the Canopy-factual check. A post-generate gate proves every preventive artifact
  is reference-anchored and actually enforcing.
- **Root-cause critic.** The last step of preventive generation proves each
  emitted policy both resolves to a reference and enforces its control's root
  cause (a real condition key gates the target action); non-enforcing objectives
  are routed to detective rather than shipped.
- **Reference-anchor enforcement** plus **preventability / enforcement /
  action-scope** checks ensure no policy ships unanchored, no Deny is a silent
  no-op, and no Deny widens beyond the reviewed action set.
- **Canopy-factual check.** Any control citing a Canopy mitigation must name a
  mitigation that actually exists in the provided export, with consistent gated
  operations — fabricated or drifted citations are flagged.
- **Conflict detection.** A deterministic pre-filter surfaces control pairs that
  contradict each other (a Deny on an action another control allows, or two
  Denies with incompatible conditions), and a clean reviewer confirms each.
- **Per-domain mapping accuracy (CCMv4).** Framework mapping is specialized by
  domain: each CCMv4 domain is mapped in a focused context loaded with only that
  domain's objectives plus curated guidance on what each objective requires and
  which control mechanisms legitimately satisfy it (and which must never), cutting
  the keyword-driven mis-maps a single 197-objective pass produces. Two
  deterministic validators back the guidance — one screens objectives that are
  not applicable to a managed/serverless service, the other flags any control
  whose mechanism class is denied for the objective it was mapped to.

### Artifact flow

Each phase consumes the previous phase's output — the pipeline is a strict DAG:

```
Input Files ──► Assess ──► Research ──► Validate ──► Map ──► Recommended Guidance ──► Summarize
                  │           │            │          │              │                    │
              sar-facts   research.json  validated  mapping     controls/            SUMMARY-
              checkpoints  (merged from  .json      results     (per-svc)            REPORT.md
              assessment    4 sub-skills)           .json                            artifact-
                                                                                     flow-matrix
```

**Phase 1 (Research)** runs 4 parallel sub-skills — mitigations, capabilities, API surface,
and ATT&CK attack surface — then merges into `research.json` (schema v3.0).

**Phase 3 (Map)** produces the richest state — `mapping-results.json` contains:
- 60 controls organized by Category×Scope matrix (PRV:27, PRO:5, DET:22, COR:6)
- Threat-mitigation-control traceability (37 mitigations → controls → framework objectives)
- CCMv4 framework mapping (71 mapped / 126 N/A out of 197 objectives)
- ATT&CK technique coverage (17/21 techniques covered)
- Coverage gap analysis

**Phase 4 (Recommended Guidance)** produces deployable artifacts across 5 categories. Exact file
counts vary by service surface area (resource type count, API operation count, org-policy
applicability). The ranges below reflect observed output across validated services:

| Category | Files | Key Artifacts |
|----------|-------|---------------|
| Preventive | 9-12 | SCPs (split), resource policies, KMS key policy, permission boundary, VPC endpoint, RCP, tag policies |
| Proactive | 12-15 | CFN Guard rules, OPA policies (per resource type), Checkov config + custom policies, CFN hooks |
| Detective | 34-47 | Config rules + Lambda handlers (+ requirements.txt), EventBridge, CloudWatch, Access Analyzer, compensating controls |
| Responsive | 6 | Lambda remediator + SAM template + deps, SSM runbooks (org + account), Step Functions workflow |
| IaC | 17-31 | CDK TypeScript, CloudFormation YAML, CDKTF, modular Terraform (per-resource modules + shared + root) |

A detailed per-artifact input/output matrix with dependency tracking is generated in
`.service-approval/<slug>/06-summarize/ARTIFACT-FLOW-MATRIX.md` (per-service).

---

## Installation

Pick the install path that matches your client.

**Claude Code only (recommended for Claude Code users)** — uses `manifest.yaml` as the source of truth, skips the multi-client detection, fastest:

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install-claude.sh
```

**All clients (Claude Code + Kiro + Copilot)** — auto-detects what's installed, wires up everything:

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install.sh        # macOS / Linux
# or Windows PowerShell:
.\install.ps1
```

Update with `git pull`. To make every `git pull` auto-sync .kiro/ and regenerate per-client manifests, run once:

```bash
make enable-auto-sync
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for per-client notes. Windows needs Developer Mode ON for symlink installs (one-time toggle).

### Prerequisites per client

| Client | Prerequisite | Why |
|--------|--------------|-----|
| Claude Code / Copilot | none beyond the client itself | auto-discover from repo files |
| Kiro IDE | Kiro.app | manual Power install via the IDE Powers panel |
| Any client using `aws-documentation` / `awsiac` MCP | [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH | MCP servers run via `uvx awslabs.*@latest` |
| Any client using `terraform` MCP | Docker Desktop running | stdio MCP runs in a container |

## Usage guidelines

| Guide | |
|-------|-|
| [Claude Code](docs/USAGE-CLAUDE-CODE.md) | Scripted install, marketplace registration, slash command |
| [Kiro IDE](docs/USAGE-KIRO.md) | Power install via IDE, keyword invocation |
| [GitHub Copilot](docs/USAGE-COPILOT.md) | Zero-install auto-discovery, Agent mode |
| [Install reference](docs/INSTALL.md) | All clients, troubleshooting, uninstall |

---

## Flags

Note: if you do not provide any values, or custom threat models / frameworks in the input folder, the tool will default to CCMv4 and MITRE for the frameworks. 

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`, `s3`, `kms`) | Required if no folder |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` (asked at intake; flag bypasses the prompt) |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect from input |
| `--include-unverified` | Include unverified findings in generation | false |
| `--clean` | Delete existing `.service-approval/` state before run | false |

---

## Validation

Validation happens in two complementary places. The **review gates and
correctness checks** that run during the pipeline — the two review gates, the
root-cause critic, reference-anchor enforcement, the Canopy-factual check, and
conflict detection — are described under [Validation efforts](#validation-efforts)
above. The **deployability checks** below confirm the generated artifacts are
syntactically valid and policy-sound, and run automatically at session end:

**Tier 1 — Static (no credentials)**
- JSON/YAML parse, Terraform validate/fmt, CDK/CDKTF TypeScript compile
- Python handler compilation, cfn-lint, CFN Guard syntax, OPA check

**Tier 2 — AWS API (credentials required)**
- CloudFormation `validate-template`
- IAM Access Analyzer `validate-policy` for SCPs, identity policies, resource policies

Run manually:
```bash
# Tier 1 only
python3 tools/validate/validate_deployable.py --tier1-only .service-approval/<slug>/05-recommended-guidance/

# Tier 1 + Tier 2
python3 tools/validate/validate_deployable.py --profile delegated-admin .service-approval/<slug>/05-recommended-guidance/
```


---

## Security
For information about contributing and reporting security issues, see [`CONTRIBUTING`](CONTRIBUTING.md).

---

## License
This project is licensed under the Apache-2.0 License.