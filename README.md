# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates a 7-phase pipeline (Assess → Research → Validate → Map → Generate → Test → Summarize) and maps everything to your control framework (CCMv4, NIST 800-53, CIS, ISO 27001).

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
Phase 0: Assess              → sar-facts.json, checkpoint-results.json, assessment-summary.md
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
  4b: generate-detective     → controls/detective/, controls/remediation/
  4c: generate-iac           → controls/iac/ (4 formats + TF modules)
Phase 5: Test                → test-results.json (dry-run or full deployment)
Phase 6: Summarize           → APPROVAL-REPORT.md, ARTIFACT-FLOW-MATRIX.md
```

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
| Corrective | 6 | Lambda remediator + SAM template + deps, SSM runbooks (org + account), Step Functions workflow |
| IaC | 17-31 | CDK TypeScript, CloudFormation YAML, CDKTF, modular Terraform (per-resource modules + shared + root) |

A detailed per-artifact input/output matrix with dependency tracking is generated in
`.service-approval/ARTIFACT-FLOW-MATRIX.md`.

---

## Installation & usage

### Claude Code

Install the plugin:

```bash
claude plugin install ./service-approval-plugin
```

Then invoke from any project with an `input/` folder containing your service documentation:

```
/service-approval ./input --service=<name> [flags]
```

Examples:
```
/service-approval ./input --service=bedrock-agentcore
/service-approval ./input --service=s3 --env=delegated-admin
/service-approval ./input --service=kms --dry-run
```

### Kiro IDE

```bash
cp -r service-approval-plugin/kiro ~/.kiro/agents/service-approval
cp service-approval-plugin/kiro/steering/service-approval.md ~/.kiro/steering/
```

### GitHub Copilot

```bash
cp service-approval-plugin/github/copilot-instructions.md .github/copilot-instructions.md
cp service-approval-plugin/github/copilot/skill-manifest.json .github/copilot/skill-manifest.json
```

### Amazon Q Developer

```bash
cp service-approval-plugin/amazonq/instructions.md .amazonq/instructions.md
```

---

## Flags

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
python3 service-approval-plugin/tools/validate/validate_deployable.py --tier1-only .service-approval/controls/

# Tier 1 + Tier 2
python3 service-approval-plugin/tools/validate/validate_deployable.py --profile delegated-admin .service-approval/controls/
```

---

## Repository layout

```
input/                              ← input files (mitigation reports, frameworks, sar-slugs.json)
service-approval-plugin/
  plugin.json                       ← plugin manifest
  .mcp.json                         ← MCP server config (awsknowledge, terraform, kb-search)
  hooks/hooks.json                  ← validation hooks (PostToolUse, Stop)
  skills/
    service-approval/SKILL.md       ← orchestrator
    assess/SKILL.md                 ← Phase 0: CAF security assessment
    research*/SKILL.md              ← Phase 1: 3 parallel research sub-skills
    validate/SKILL.md               ← Phase 2: MCP-based verification
    map*/SKILL.md                   ← Phase 3: 4 map sub-skills
    generate*/SKILL.md              ← Phase 4: 3 parallel generate sub-skills
    test/SKILL.md                   ← Phase 5: deployment validation
    summarize/SKILL.md              ← Phase 6: final report
  rules/
    service-approval-safety.md      ← safety guardrails
  tools/
    validate/                       ← validation scripts (controls, cross, deployable, state)
    kb-search-mcp/                  ← Bedrock KB search MCP server
    post-process/                   ← deterministic output post-processing
  data/sar-slugs.json               ← SAR URL slug mapping (467 services)
  kiro/                             ← Kiro IDE agent config
  github/                           ← GitHub Copilot config
  amazonq/                          ← Amazon Q Developer config
  gemini/                           ← Gemini config
  cloudparty/                       ← CloudParty facilitation
  docs/README.md                    ← plugin quick-start reference
```

---

## Authors

GFS PACE — fsi-pace@amazon.com
