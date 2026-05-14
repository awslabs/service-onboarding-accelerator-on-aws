# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates an 8-phase pipeline (Intake → Assess → Research → Validate → Map → Generate → Test → Summarize) and maps everything to your control framework (CCMv4, NIST 800-53, CIS, ISO 27001).

## What it produces

- **Proactive controls** — CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies
- **Preventive controls** — SCPs, RCPs, declarative policies, permission boundaries, tag policies, resource policies
- **Detective controls** — Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer
- **Auto-remediation** — Lambda remediators, SSM runbooks, Step Functions workflows
- **Compliant IaC** — CDK (TypeScript), Terraform (modular), CloudFormation, CDK for Terraform
- **Validation** — Tier 1 static checks + Tier 2 AWS API policy validation (automatic via hooks)

Output lands in `.service-approval/` in your working directory:
```
.service-approval/
  APPROVAL-REPORT.md   ← final verdict + framework coverage matrix
  controls/            ← all generated control artifacts
  state/               ← pipeline state files (research.json, validated.json, etc.)
```

---

## Pipeline

```
Intake (precursor)           → intake-manifest.json (service, inputs, framework, testing intent)
Phase 0: Assess              → sar-facts.json, checkpoint-results.json, assessment-summary.md, iac-support.json
Phase 1: Research (4 parallel sub-skills + merge)
  1a: research-mitigations   → research-mitigations.json
  1b: research-capabilities  → research-capabilities.json
  1c: research-api-surface   → research-api-surface.json
  1d: research-attack-surface→ research-attack-surface.json (optional, MITRE ATT&CK)
  1e: merge                  → research.json
Phase 2: Validate            → validated.json
Phase 3: Map (4 sub-skills)
  3a: map-parse-framework    → map-framework-parsed.json
  3b: map-generate-controls  → map-controls-generated.json (parallel with 3a)
  3c: map-framework-mapping  → map-framework-mapped.json (after 3a+3b)
  3d: map-assemble           → mapping-results.json, controls-catalog.md, framework-mapping.md
Phase 4: Generate (3 parallel sub-skills)
  4a: generate-preventive    → controls/preventive/, controls/proactive/
  4b: generate-detective     → controls/detective/, controls/responsive/
  4c: generate-iac           → controls/iac/ (4 formats + TF modules)
Phase 5: Test                → test-results.json (mode comes from
                                intake-manifest.json.testing.mode:
                                full-deploy | dry-run | skip | manual-cli)
Phase 6: Summarize           → APPROVAL-REPORT.md, ARTIFACT-FLOW-MATRIX.md
```

### Key Features

The pipeline runs as 20 discrete skills under [`skills/`](skills/). Each one is a standalone [Agent Skills](https://agentskills.io) folder with its own `SKILL.md` — so the same skills work across Claude Code, Kiro, GitHub Copilot, and any other agentskills.io-compatible client.

<!-- SKILLS-TABLE-START -->
| Skill | Description |
|-------|-------------|
| [`assess`](skills/assess/SKILL.md) | Run a 5-domain CAF security posture assessment for an AWS service. Produces (1) assessment-summary.md — CAF-structured findings with GAPS tables, (2) sar-facts.json — extracted SAR data, (3) checkpoint-results.json — factual checkpoint verification. These feed into the research, validate, and generate phases. |
| [`generate-detective`](skills/generate-detective/SKILL.md) | Generate detective and responsive security control artifacts — Config rules with Lambda handlers, EventBridge rules, CloudWatch alarms, SSM runbooks, Step Functions workflows, CloudTrail configuration. Reads from mapping-results.json and validated.json. |
| [`generate-iac`](skills/generate-iac/SKILL.md) | Generate compliant IaC templates in all 4 formats — modular Terraform, CDK TypeScript, CloudFormation YAML, and CDK for Terraform. Uses parameter coverage matrix from mapping-results.json and API surface from validated.json. |
| [`generate-preventive`](skills/generate-preventive/SKILL.md) | Generate preventive and proactive security control artifacts — SCPs, resource policies, KMS key policies, permission boundaries, tag policies, OPA policies, and CloudFormation Guard rules. Reads from mapping-results.json and validated.json. |
| [`generate`](skills/generate/SKILL.md) | Generate all security control artifacts and compliant IaC templates from mapping-results.json and validated.json. Split into 3 focused sub-skills for better accuracy; this skill orchestrates them. |
| [`map-assemble`](skills/map-assemble/SKILL.md) | Deterministic assembly of map sub-skill outputs into final mapping-results.json, controls-catalog.md, and framework-mapping.md. Builds traceability, identifies coverage gaps, and runs comprehensive validation. No LLM reasoning required — pure data assembly. |
| [`map-framework-mapping`](skills/map-framework-mapping/SKILL.md) | Map generated controls to framework objectives with per-objective analysis, confidence scoring, and strict quality gates. Produces map-framework-mapped.json consumed by map-assemble. The hardest sub-skill — requires careful per-objective reasoning, not batch keyword matching. |
| [`map-generate-controls`](skills/map-generate-controls/SKILL.md) | Generate security controls from mitigations x capabilities, organized by Category x Scope matrix. Produces map-controls-generated.json with rich metadata for downstream framework mapping. Consumes validated.json. |
| [`map-parse-framework`](skills/map-parse-framework/SKILL.md) | Parse a customer-provided control framework file (xlsx/json/md) into normalized framework_objectives[]. Produces map-framework-parsed.json consumed by map-assemble. Supports CCMv4, NIST 800-53, CIS Benchmarks, ISO 27001. |
| [`map`](skills/map/SKILL.md) | Map verified service capabilities against customer-provided control framework and threat model. Produces mapping-results.json, controls-catalog.md, and framework-mapping.md. Supports pluggable frameworks: CCMv4, NIST 800-53, CIS Benchmarks, ISO 27001, etc. Split into 4 focused sub-skills for better accuracy; this skill orchestrates them. |
| [`research-api-surface`](skills/research-api-surface/SKILL.md) | Discover the complete API surface for an AWS service — all operations (control-plane AND data-plane), parameters, and cross-reference validation against SAR condition keys. Produces research-api-surface.json consumed by the research merge step. |
| [`research-attack-surface`](skills/research-attack-surface/SKILL.md) | Identify applicable MITRE ATT&CK Cloud techniques for the target service based on API surface analysis and customer STRIDE-based threat model. Produces research-attack-surface.json consumed by the research merge step. |
| [`research-capabilities`](skills/research-capabilities/SKILL.md) | Discover AWS service security capabilities (IAM, encryption, network, logging, org-policies) using MCP servers and assessment artifacts. Produces research-capabilities.json consumed by the research merge step. |
| [`research-mitigations`](skills/research-mitigations/SKILL.md) | Parse input files to extract existing mitigations, build initial asset inventory, and collect assessment gaps. Produces research-mitigations.json consumed by the research merge step. |
| [`research`](skills/research/SKILL.md) | AWS service capability discovery producing research.json with structured capabilities, API surface, and existing mitigations. Uses MCP servers for AWS documentation, service authorization, and best practices. Downstream skills (Validate, Map) consume this output. Split into 3 focused sub-skills for better accuracy; this skill orchestrates and merges. |
| [`service-approval`](skills/service-approval/SKILL.md) | Orchestrate all 8 service-approval agents (Intake → Assess → Research → Validate → Map → Generate → Test → Summarize) to generate AWS security controls and compliant resource templates for any AWS service |
| [`summarize`](skills/summarize/SKILL.md) | Produce final APPROVAL-REPORT.md with framework coverage matrix, mitigation traceability, control inventory, test evidence, and verdic |
| [`test`](skills/test/SKILL.md) | Deploy compliant resource template and validate zero Config rule findings. Requires AWS credentials. |
| [`validate`](skills/validate/SKILL.md) | Verify research.json v3.0 findings via MCP — confirm capabilities, API parameters, condition keys, SCP/RCP expressibility, and mitigation feasibility. Produce validated.json. |
<!-- SKILLS-TABLE-END -->

Run `python3 tools/sync-ide-configs.py` or `./install.sh --sync` if you add a new skill — the hook regenerates this table from `SKILL.md` frontmatter.

### Artifact flow

Each phase consumes the previous phase's output — the pipeline is a strict DAG:

```
Input Files ──► Assess ──► Research ──► Validate ──► Map ──► Generate ──► Test ──► Summarize
                  │           │            │          │         │           │          │
              sar-facts   research.json  validated  mapping  controls/  test-      APPROVAL-
              checkpoints  (merged from  .json      results  (85 files) results    REPORT.md
              assessment    4 sub-skills)           .json                          ARTIFACT-
                                                                                  FLOW-MATRIX
```

**Phase 1 (Research)** runs 4 parallel sub-skills — mitigations, capabilities, API surface,
and ATT&CK attack surface — then merges into `research.json` (schema v3.0).

**Phase 3 (Map)** produces the richest state — `mapping-results.json` contains:
- 60 controls organized by Category×Scope matrix (PRV:27, PRO:5, DET:22, COR:6)
- Threat-mitigation-control traceability (37 mitigations → controls → framework objectives)
- CCMv4 framework mapping (71 mapped / 126 N/A out of 197 objectives)
- ATT&CK technique coverage (17/21 techniques covered)
- Coverage gap analysis

**Phase 4 (Generate)** produces deployable artifacts across 5 categories. Exact file
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
`.service-approval/ARTIFACT-FLOW-MATRIX.md`.

---

## Installation & usage

One install script detects every installed client and wires it up. Clone and run:

```bash
git clone https://gitlab.aws.dev/lightninglane/service-onboarding.git [TO BE REPLACED WITH PUBLIC URL]
cd service-onboarding
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
| Kiro CLI / IDE | `kiro-cli` or Kiro.app | installer wires both |
| Any client using `aws-documentation` / `awsiac` MCP | [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH | MCP servers run via `uvx awslabs.*@latest` |
| Any client using `terraform` MCP | Docker Desktop running | stdio MCP runs in a container |

### Testing and troubleshooting

- **Kiro IDE + CLI 2.0**: [`docs/TESTING-KIRO.md`](docs/TESTING-KIRO.md) — step-by-step install verification, MCP errors, hook-fire checks, keyword activation
- **All clients**: [`docs/INSTALL.md`](docs/INSTALL.md) — per-client install flow + common errors

Invocation after install:

| Client | How to invoke |
|--------|---------------|
| Claude Code | `/service-approval ./input --service=s3` |
| GitHub Copilot (Agent mode) | `@service-approval ./input --service=s3` |
| Kiro (CLI or IDE) | "run service approval for s3" (keyword match) |

Examples:
```
/service-approval ./input --service=bedrock-agentcore
/service-approval ./input --service=s3 --env=delegated-admin
/service-approval ./input --service=kms --dry-run
```

---

## Flags

Note: if you do not provide any values, or custom threat models / frameworks in the input folder, the tool will default to CCMv4 and MITRE for the frameworks. 

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`, `s3`, `kms`) | Required if no folder |
| `--env=<profile>` | AWS CLI profile for Tester and Tier 2 validation | None (skips) |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | Auto-detect |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect from input |
| `--skip-test` | Skip deployment validation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--timeout=<minutes>` | Config evaluation timeout | 30 |
| `--keep` | Keep deployed test resources after run | false |
| `--include-unverified` | Include unverified findings in generation | false |
| `--clean` | Delete existing `.service-approval/` state before run | false |

---

## Validation

The plugin includes automatic validation hooks that run at session end:

**Tier 1 — Static (no credentials)**
- JSON/YAML parse, Terraform validate/fmt, CDK/CDKTF TypeScript compile
- Python handler compilation, cfn-lint, CFN Guard syntax, OPA check

**Tier 2 — AWS API (credentials required)**
- CloudFormation `validate-template`
- IAM Access Analyzer `validate-policy` for SCPs, identity policies, resource policies

Run manually:
```bash
# Tier 1 only
python3 tools/validate/validate_deployable.py --tier1-only .service-approval/controls/

# Tier 1 + Tier 2
python3 tools/validate/validate_deployable.py --profile delegated-admin .service-approval/controls/
```

---

## Repository layout

```
.
├── manifest.yaml                  ← single source of truth (metadata + MCP servers)
├── install.sh / install.ps1       ← cross-client installer with --sync / --update
├── Makefile                       ← make install / sync / update / check / verify
├── .githooks/post-merge           ← enable via `make enable-auto-sync`
├── .gitlab-ci.yml                 ← pytest + sync-drift + install-check + schema-validity
│
├── skills/                        ← 19 Agent Skills (agentskills.io format, shared across clients)
├── tools/
│   ├── validate/                  ← validators + hooks (hook_stop.py, hook_post_tool_use.py)
│   ├── kb-search-mcp/             ← Bedrock KB MCP server
│   ├── post-process/              ← deterministic output post-processing
│   ├── sync-ide-configs.py        ← regenerates per-client manifests from manifest.yaml
│   └── generate-kiro-agents.py    ← emits IDE .md + CLI 2.0 .json from agents-src/*.yaml
├── schemas/                       ← 11 JSON Schemas for pipeline state files
├── data/                          ← SAR slugs, ATT&CK matrix, KMS consumers
├── rules/                         ← safety rules
├── commands/                      ← Claude Code /service-approval slash command
├── hooks/                         ← Claude Code PostToolUse + Stop hooks
├── schemas/                       ← JSON schemas for state files
├── plugin-docs/                   ← plugin quick-start reference
│
├── .claude-plugin/                ← Claude Code plugin manifest (generated)
├── .agents/skills -> ../skills    ← agentskills.io cross-tool alias
├── .mcp.json                      ← Claude Code workspace MCP (generated)
├── .vscode/mcp.json               ← VS Code Copilot MCP (generated)
├── .github/                       ← Copilot: agents, prompts, hooks, plugin bundle
│
├── powers/service-approval/       ← Kiro Power (IDE + CLI 2.0 dual-format from agents-src/)
│   ├── POWER.md                   ← frontmatter (generated) + body
│   ├── mcp.json                   ← Kiro MCP (generated)
│   ├── steering/                  ← always-on + phase-specific steering
│   ├── agents-src/sa-*.yaml       ← SOURCE OF TRUTH for agents
│   ├── ide/agents/*.md            ← generated: Kiro IDE format
│   ├── ide/hooks/*.kiro.hook      ← generated: Kiro IDE hook format
│   └── cli/agents/sa-*.json       ← generated: Kiro CLI 2.0 format with embedded hooks
```

**Update propagation:** every client config is regenerated by `tools/sync-ide-configs.py` from `manifest.yaml`. Edit the manifest, run `./install.sh --sync`, and all 4 client manifests + 4 MCP configs update in lockstep. CI blocks drift via `.gitlab-ci.yml`.


---

## Security
For information about contributing and reporting security issues, see [`CONTRIBUTING`](CONTRIBUTING.md).

---

## License
This project is licensed under the Apache-2.0 License.