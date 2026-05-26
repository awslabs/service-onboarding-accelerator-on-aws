# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates a 9-phase pipeline (Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence) and maps everything to CCMv4. Other frameworks (NIST 800-53, CIS, ISO 27001) remain available behind the `--framework=<type>` CLI flag for advanced operators; the interactive intake narrows to CCMv4.

## What it produces

- **Proactive controls** — CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies
- **Preventive controls** — SCPs, RCPs, declarative policies, permission boundaries, tag policies, resource policies
- **Detective controls** — Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer
- **Auto-remediation** — Lambda remediators, SSM runbooks, Step Functions workflows
- **Compliant IaC** — CDK (TypeScript), Terraform (modular), CloudFormation, CDK for Terraform
- **Validation** — Tier 1 static checks + Tier 2 AWS API policy validation (automatic via hooks)

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

## Pipeline

```
Intake (precursor)           → _staging/<ts>/00-intake/intake-manifest.json (service, inputs, framework, testing intent)
Phase 0: Assess              → <slug>/01-assess/{sar-facts.json, checkpoint-results.json, assessment-summary.md, iac-support.json}
Phase 1: Research (4 parallel sub-skills + merge)
  1a: research-mitigations   → <slug>/02-research/research-mitigations.json
  1b: research-capabilities  → <slug>/02-research/research-capabilities.json
  1c: research-api-surface   → <slug>/02-research/research-api-surface.json
  1d: research-attack-surface→ <slug>/02-research/research-attack-surface.json (MITRE ATT&CK, always runs)
  1e: merge                  → <slug>/02-research/research.json
Phase 2: Validate            → <slug>/03-validate/validated.json
Phase 3: Map (4 sub-skills)
  3a: map-parse-framework    → <slug>/04-map/map-framework-parsed.json
  3b: map-generate-controls  → <slug>/04-map/map-controls-generated.json (parallel with 3a)
  3c: map-framework-mapping  → <slug>/04-map/map-framework-mapped.json (after 3a+3b)
  3d: map-assemble           → <slug>/04-map/mapping-results.json, controls-catalog.md, framework-mapping.md
Phase 4: Generate (3 parallel sub-skills)
  4a: generate-preventive    → <slug>/05-generate/preventive/, proactive/
  4b: generate-detective     → <slug>/05-generate/detective/, responsive/
  4c: generate-iac           → <slug>/05-generate/iac/ (4 formats + TF modules)
Phase 5: Test                → <slug>/06-test/test-results.json (mode comes from
                                intake-manifest.json.testing.mode:
                                full-deploy | dry-run | skip | manual-cli)
Phase 6: Summarize           → <slug>/07-summarize/APPROVAL-REPORT.md, ARTIFACT-FLOW-MATRIX.md
Phase 7: Evidence            → <slug>/08-evidence/attestation-report.md, attestation-results.json, CLI outputs
```

### Key Features

The pipeline runs as 21 discrete skills under [`skills/`](skills/). Each one is a standalone [Agent Skills](https://agentskills.io) folder with its own `SKILL.md` — so the same skills work across Claude Code, Kiro, GitHub Copilot, and any other agentskills.io-compatible client.

<!-- SKILLS-TABLE-START -->
| Skill | Description |
|-------|-------------|
| [`assess`](skills/assess/SKILL.md) | Run a 5-domain CAF security posture assessment for an AWS service. Produces (1) assessment-summary.md — CAF-structured findings with GAPS tables, (2) sar-facts.json — extracted SAR data, (3) checkpoint-results.json — factual checkpoint verification. These feed into the research, validate, and generate phases. |
| [`evidence`](skills/evidence/SKILL.md) | Phase 7. Run service-agnostic AWS CLI probes against deployed compliant resources to produce a control × verdict matrix proving each mapped control is actually enforced at runtime. Reads from 06-test/deployed-resources.json; writes attestation-results.json + attestation-report.md + audit guide. |
| [`generate-detective`](skills/generate-detective/SKILL.md) | Generate detective and responsive security control artifacts — Config rules with Lambda handlers, EventBridge rules, CloudWatch alarms, SSM runbooks, Step Functions workflows, CloudTrail configuration. Reads from mapping-results.json and validated.json. |
| [`generate-iac`](skills/generate-iac/SKILL.md) | Generate compliant IaC templates in all 4 formats — modular Terraform, CDK TypeScript, CloudFormation YAML, and CDK for Terraform. Uses parameter coverage matrix from mapping-results.json and API surface from validated.json. |
| [`generate-preventive`](skills/generate-preventive/SKILL.md) | Generate preventive and proactive security control artifacts — SCPs, resource policies, KMS key policies, permission boundaries, tag policies, OPA policies, and CloudFormation Guard rules. Reads from mapping-results.json and validated.json. |
| [`generate`](skills/generate/SKILL.md) | Generate all security control artifacts and compliant IaC templates from mapping-results.json and validated.json. Split into 3 focused sub-skills for better accuracy; this skill orchestrates them. |
| [`intake`](skills/intake/SKILL.md) | Precursor phase. Collect service name, input type, framework, and testing preferences from the user (or pre-filled `service-approval-intake.yaml`). Produces intake-manifest.json consumed by every downstream phase. |
| [`map-assemble`](skills/map-assemble/SKILL.md) | Deterministic assembly of map sub-skill outputs into final mapping-results.json, controls-catalog.md, and framework-mapping.md. Builds traceability, identifies coverage gaps, and runs comprehensive validation. No LLM reasoning required — pure data assembly. |
| [`map-framework-mapping`](skills/map-framework-mapping/SKILL.md) | Map generated controls to framework objectives with per-objective analysis, confidence scoring, and strict quality gates. Produces map-framework-mapped.json consumed by map-assemble. The hardest sub-skill — requires careful per-objective reasoning, not batch keyword matching. |
| [`map-generate-controls`](skills/map-generate-controls/SKILL.md) | Generate security controls from mitigations x capabilities, organized by Category x Scope matrix. Produces map-controls-generated.json with rich metadata for downstream framework mapping. Consumes validated.json. |
| [`map-parse-framework`](skills/map-parse-framework/SKILL.md) | Parse a customer-provided control framework file (xlsx/json/md) into normalized framework_objectives[]. Produces map-framework-parsed.json consumed by map-assemble. Supports CCMv4, NIST 800-53, CIS Benchmarks, ISO 27001 (interactive intake is CCMv4-only; `--framework=<type>` CLI bypass for advanced operators). |
| [`map`](skills/map/SKILL.md) | Map verified service capabilities against customer-provided control framework and threat model. Produces mapping-results.json, controls-catalog.md, and framework-mapping.md. Supports pluggable frameworks: CCMv4, NIST 800-53, CIS Benchmarks, ISO 27001, etc. (interactive intake is CCMv4-only; `--framework=<type>` CLI bypass for advanced operators). Split into 4 focused sub-skills for better accuracy; this skill orchestrates them. |
| [`research-api-surface`](skills/research-api-surface/SKILL.md) | Discover the complete API surface for an AWS service — all operations (control-plane AND data-plane), parameters, and cross-reference validation against SAR condition keys. Produces research-api-surface.json consumed by the research merge step. |
| [`research-attack-surface`](skills/research-attack-surface/SKILL.md) | Identify applicable MITRE ATT&CK Cloud techniques for the target service based on API surface analysis and customer STRIDE-based threat model. Produces research-attack-surface.json consumed by the research merge step. |
| [`research-capabilities`](skills/research-capabilities/SKILL.md) | Discover AWS service security capabilities (IAM, encryption, network, logging, org-policies) using MCP servers and assessment artifacts. Produces research-capabilities.json consumed by the research merge step. |
| [`research-mitigations`](skills/research-mitigations/SKILL.md) | Parse input files to extract existing mitigations, build initial asset inventory, and collect assessment gaps. Produces research-mitigations.json consumed by the research merge step. |
| [`research`](skills/research/SKILL.md) | AWS service capability discovery producing research.json with structured capabilities, API surface, and existing mitigations. Uses MCP servers for AWS documentation, service authorization, and best practices. Downstream skills (Validate, Map) consume this output. Split into 3 focused sub-skills for better accuracy; this skill orchestrates and merges. |
| [`service-approval`](skills/service-approval/SKILL.md) | Orchestrate all 9 service-approval agents (Intake → Assess → Research → Validate → Map → Generate → Test → Summarize → Evidence) to generate AWS security controls and compliant resource templates for any AWS service |
| [`summarize`](skills/summarize/SKILL.md) | Produce final APPROVAL-REPORT.md with framework coverage matrix, mitigation traceability, control inventory, test evidence, and verdic |
| [`test`](skills/test/SKILL.md) | Deploy compliant resource template and validate zero Config rule findings. Requires AWS credentials. |
| [`validate`](skills/validate/SKILL.md) | Verify research.json v3.0 findings via MCP — confirm capabilities, API parameters, condition keys, SCP/RCP expressibility, and mitigation feasibility. Produce validated.json. |
<!-- SKILLS-TABLE-END -->

The table is hand-maintained — when you add a skill, edit this block AND update the count in the paragraph above + the tree diagram below. (Auto-regeneration from `SKILL.md` frontmatter is planned but not yet wired into `tools/sync-ide-configs.py`.)

### Artifact flow

Each phase consumes the previous phase's output — the pipeline is a strict DAG:

```
Input Files ──► Assess ──► Research ──► Validate ──► Map ──► Generate ──► Test ──► Summarize ──► Evidence
                  │           │            │          │         │           │          │              │
              sar-facts   research.json  validated  mapping  controls/  test-      APPROVAL-   attestation-
              checkpoints  (merged from  .json      results  (per-svc)  results    REPORT.md   report.md
              assessment    4 sub-skills)           .json                          ARTIFACT-   attestation-
                                                                                  FLOW-MATRIX  results.json
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

## Installation & usage

Pick the install path that matches your client.

**Claude Code only (recommended for Claude Code users)** — uses `manifest.yaml` as the source of truth, skips the multi-client detection, fastest:

```bash
git clone git@ssh.gitlab.aws.dev:lightninglane/service-onboarding.git
cd service-onboarding
./install-claude.sh
```

**All clients (Claude Code + Kiro + Copilot)** — auto-detects what's installed, wires up everything:

```bash
git clone git@ssh.gitlab.aws.dev:lightninglane/service-onboarding.git
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
| Kiro IDE | Kiro.app | manual Power install via the IDE Powers panel |
| Any client using `aws-documentation` / `awsiac` MCP | [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH | MCP servers run via `uvx awslabs.*@latest` |
| Any client using `terraform` MCP | Docker Desktop running | stdio MCP runs in a container |

### Testing and troubleshooting

- **Kiro IDE + CLI 2.0**: [`docs/TESTING-KIRO.md`](docs/TESTING-KIRO.md) — step-by-step install verification, MCP errors, hook-fire checks, keyword activation
- **All clients**: [`docs/INSTALL.md`](docs/INSTALL.md) — per-client install flow + common errors

### Running the plugin

After installation, start the plugin from **your own working directory** — not
the cloned repo. This can be an empty folder or one containing your custom input
files (threat models, framework spreadsheets, etc.):

```bash
mkdir ~/my-service-approval && cd ~/my-service-approval

# Optionally add your own input files:
# cp /path/to/threat-model.xlsx ./input/
# cp /path/to/ccmv4-framework.json ./input/
```

Then invoke from your AI client:

| Client | How to invoke |
|--------|---------------|
| Claude Code | `/service-approval ./input --service=s3` |
| GitHub Copilot (Agent mode) | `@service-approval ./input --service=s3` |
| Kiro (IDE) | "run service approval for s3" (keyword match) |

If you have no custom input files, the plugin uses built-in defaults (CCMv4 +
MITRE ATT&CK). Output lands in `.service-approval/<service-slug>/` within your
working directory.

Examples:
```
/service-approval --service=bedrock-agentcore
/service-approval ./input --service=s3 --env=delegated-admin
/service-approval --service=kms --dry-run
```

### Running without an input folder

If you don't have customer-specific inputs (mitigation reports, threat models, framework
files), the **Intake** phase detects the missing `./input/` folder, creates an empty one
in your cwd, and offers a seed menu:

```
[1] Skip — run in MCP-only mode (research everything from scratch)
[2] Leave empty — I'll add files myself before continuing
[3] Seed bundled CCMv4 framework  (recommended)
[4] Auto-download latest CCMv4 from CSA
[5] Both — copy bundled CCMv4 AND try CSA download
```

- **Bundled CCMv4** is `input/CCMv4_LightningLane.xlsx` from the plugin — copied as-is
  into your `./input/`. Good for offline / first-run usage.
- **CSA auto-download** tries `https://cloudsecurityalliance.org/download/artifacts/cloud-controls-matrix-v4-1`.
  CSA may require sign-in; if the response is HTML instead of an xlsx, the skill falls
  back to opening your browser and waits for you to drop the file into `./input/`.
- The bundled mitigation report is **never** auto-copied — it's customer-specific and
  would mislead downstream skills. Drop your own mitigation report in `./input/` if you
  have one.

For non-interactive runs, set the choice in your intake YAML:

```yaml
input:
  bootstrap:
    seed_from_plugin: true        # ≡ choice [3]
    auto_download_ccmv4: false
```

### MITRE ATT&CK threat modeling

Phase 1d (`research-attack-surface`) maps the service's API surface to ATT&CK techniques
and tactics. By default it queries the
[`mitre-attack` MCP](https://github.com/stoyky/mitre-attack-mcp) for live MITRE data;
if the MCP fails to spawn, it falls back to the bundled snapshot at
`data/attack-cloud-matrix.json` (ATT&CK 16.1) — so the phase keeps working offline.

The MCP is registered in `manifest.yaml` and propagated to every client by
`tools/sync-ide-configs.py`. Like the other `uvx`-based MCPs, it requires
[`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH.

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

## Repository layout

```
.
├── manifest.yaml                  ← single source of truth (metadata + MCP servers)
├── install.sh / install.ps1       ← cross-client installer with --sync / --update
├── Makefile                       ← make install / sync / update / check / verify
├── .githooks/post-merge           ← enable via `make enable-auto-sync`
├── .gitlab-ci.yml                 ← pytest + sync-drift + install-check + schema-validity
│
├── skills/                        ← 21 Agent Skills (agentskills.io format, shared across clients)
├── tools/
│   ├── validate/                  ← validators + hooks (hook_stop.py, hook_post_tool_use.py)
│   ├── kb-search-mcp/             ← Bedrock KB MCP server
│   ├── post-process/              ← deterministic output post-processing
│   ├── sync-ide-configs.py        ← regenerates per-client manifests from manifest.yaml
│   └── generate-kiro-agents.py    ← emits IDE .md + CLI 2.0 .json from agents-src/*.yaml
├── schemas/                       ← one *.schema.json per pipeline state file
├── data/                          ← SAR slugs, ATT&CK matrix, KMS consumers
├── rules/                         ← safety rules
├── commands/                      ← Claude Code /service-approval slash command
├── hooks/                         ← Claude Code PostToolUse + Stop hooks
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