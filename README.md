# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates a 9-phase pipeline (Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence) and maps everything to CCMv4. Other frameworks (NIST 800-53, CIS, ISO 27001) remain available behind the `--framework=<type>` CLI flag for advanced operators; the interactive intake narrows to CCMv4.

## What it produces

- **Control mapping** - Maps threats and controls to security and compliance frameworks (e.g CCMv4, MITRE)
- **Proactive controls** — CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies
- **Preventive controls** — SCPs, RCPs, declarative policies, permission boundaries, tag policies, resource policies
- **Detective controls** — Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer
- **Auto-remediation** — Lambda remediators, SSM runbooks, Step Functions workflows
- **Compliant IaC** — CDK (TypeScript), Terraform (modular), CloudFormation, CDK for Terraform
- **Validation** — Tier 1 static checks + Tier 2 AWS API policy validation (automatic via hooks)
- **Approval report** - Summaries the overall service onboarding accelerator on AWS


Output lands in `.service-approval/<service-slug>/` (per-service layout) in your working directory:
```
.service-approval/<service-slug>/
  00-intake/              ← intake manifest
  01-assess/              ← SAR facts, checkpoints, assessment summary
  02-research/            ← research.json (merged from 4 sub-skills)
  03-validate/            ← validated.json
  04-map/                 ← mapping-results.json, controls-catalog.md, framework-mapping.md
  05-generate/            ← all generated control artifacts (preventive, proactive, detective, responsive, IaC)
  06-test/                ← test-results.json, deploy logs
  07-summarize/           ← APPROVAL-REPORT.md
  08-evidence/            ← attestation-report.md, CLI probe outputs, attestation-results.json
  attestation.md          ← reviewer's audit guide
  mcp-calls.log           ← MCP call audit log
```

---


### Key Features

The pipeline runs as 21 discrete skills under [`skills/`](skills/). Each one is a standalone [Agent Skills](https://agentskills.io) folder with its own `SKILL.md` — so the same skills work across Claude Code, Kiro, GitHub Copilot, and any other agentskills.io-compatible client.


### Artifact flow

Each phase consumes the previous phase's output — the pipeline is a strict DAG:

```
Input Files ──► Assess ──► Research ──► Validate ──► Map ──► Generate ──► Test ──► Summarize ──► Evidence
                  │           │            │          │         │           │          │              │
              sar-facts   research.json  validated  mapping  controls/  test-      approval-   attestation-
              checkpoints  (merged from  .json      results  (per-svc)  results    report.md   report.md
              assessment    4 sub-skills)           .json                          artifact-   attestation-
                                                                                  flow-matrix  results.json
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
`.service-approval/<slug>/07-summarize/ARTIFACT-FLOW-MATRIX.md` (per-service).

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
| `--env=<profile>` | AWS CLI profile for Tester and Tier 2 validation | None (skips) |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` (asked at intake; flag bypasses the prompt) |
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
python3 tools/validate/validate_deployable.py --tier1-only .service-approval/<slug>/05-generate/

# Tier 1 + Tier 2
python3 tools/validate/validate_deployable.py --profile delegated-admin .service-approval/<slug>/05-generate/
```


---

## Security
For information about contributing and reporting security issues, see [`CONTRIBUTING`](CONTRIBUTING.md).

---

## License
This project is licensed under the Apache-2.0 License.