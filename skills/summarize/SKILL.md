---
name: summarize-v3
description: Produce final APPROVAL-REPORT.md with framework coverage matrix, mitigation traceability, control inventory, test evidence, and verdict
disable-model-invocation: false
---

# Service Approval — Summarizer v3

Read all state files and generate the final approval report at `.service-approval/APPROVAL-REPORT.md`.

## Prerequisites

- [ ] Check required inputs:
  ```bash
  test -f .service-approval/state/validated.json && echo "validated: OK" || echo "validated: MISSING"
  test -f .service-approval/state/mapping-results.json && echo "mapping-results: OK" || echo "mapping-results: MISSING"
  test -d .service-approval/controls && echo "controls: OK" || echo "controls: MISSING"
  test -f .service-approval/state/assessment-summary.md && echo "assessment: OK" || echo "assessment: not found (optional)"
  test -f .service-approval/state/checkpoint-results.json && echo "checkpoints: OK" || echo "checkpoints: not found (optional)"
  ```
  Proceed even if `test-results.json` is absent (mark test as NOT RUN in the report).
  Assessment artifacts are optional — if present, they enrich the report.

## Step 1: Determine verdict

Read `validated.json` for `unverified_count`. Read `test-results.json` if it exists.

| Condition | Verdict |
|-----------|---------|
| `test_results.passed = true` AND `unverified_count = 0` | APPROVED |
| `test_results.passed = true` AND `unverified_count > 0` | APPROVED WITH EXCEPTIONS |
| `test_results.skipped = true` AND `unverified_count = 0` | APPROVED (test not run) |
| `test_results.passed = false` | REQUIRES REMEDIATION |
| `test-results.json` absent | APPROVED (test not run) |

Note: `passed: null` (dry-run) is treated the same as `skipped: true`.

## Step 2: Build framework coverage matrix

Read `mapping-results.json` `framework_mapping[]`. Build a table:

| {Framework} Objective ID | Title | Domain | Satisfied By | Coverage |

Where "Satisfied By" = comma-separated control IDs that map to this framework objective.
Use the framework name dynamically from `mapping-results.json.framework.name`.

## Step 3: Build mitigation traceability matrix

Read `mapping-results.json` `threat_mitigation_map[]`. Build a table:

| Mitigation ID | Statement | Resource Type | Controls | Framework Objectives | Coverage |

Where "Statement" = `statement` field.
Where "Controls" = `control_ids[]` from the mitigation entry (joined, comma-separated).
Where "Framework Objectives" = `framework_objectives[]` from the mitigation entry. If this field
is absent, derive it: for each control id in the mitigation's `control_ids[]`, look up that control
in the top-level `controls[]` and collect its `framework_objectives[]`. Deduplicate and sort.

This shows end-to-end traceability from customer mitigations through controls to framework objectives.

## Step 4: Build control inventory

For each file in `.service-approval/controls/`, read its `_metadata` or header comments
(lines starting with `# SCOPE:`, `# LAYER:`, `# CONTROLS:`, `# FRAMEWORK:`).

Build a table per layer:
| Layer | Scope | Artifact | Controls | Framework Objectives |

## Step 5: Build artifact manifest

```bash
find .service-approval/controls -type f | sort
```

## Step 6: Write APPROVAL-REPORT.md

**CRITICAL — Terminology rules for the report:**
The APPROVAL-REPORT.md is a customer-facing document. NEVER use internal/pipeline terms:
- NO: "service approval pipeline", "pipeline generated" → YES: "47 security controls were generated"
- NO: "--skip-test flag", "--clean flag" → YES: "Testing was deferred for this assessment"
- NO: "deployment pipeline" → YES: "deployment process"
- NO: MCP tool names, skill names, agent names
- NO: internal file names ("validated.json", "mapping-results.json", "research.json") → YES: "all capabilities were verified"
- NO: "unverified_count = 0" → YES: "all items verified"
- Apply all terminology rules from CLAUDE.md (see Terminology Rules section)

Write `.service-approval/APPROVAL-REPORT.md` with these sections:

### Verdict
[Verdict string with date, service name, resource count]

### Executive Summary
[Coverage numbers: N controls generated, N framework objectives covered, N mitigations addressed, test result]

### Security Posture Assessment
**Include this section only if `assessment-summary.md` exists.**
- Extract GAPS Summary from assessment-summary.md (total gaps, total customer actions)
- List each domain's gap count: IAM ({N}), LOGGING ({N}), INFRA ({N}), DATA ({N}), INCIDENT ({N})
- For each REQUIREMENT GAP: show whether a control was generated to address it
  (from mapping-results.json controls with `assessment_gap_ids[]`)
- Include checkpoint verification summary from checkpoint-results.json (if available):
  RCP: {Yes/No}, FIPS: {Yes/No}, Declarative Policies: {Yes/No}, RAM: {Yes/No}

### Framework Coverage Matrix ({framework-name})
[Full table from Step 2 — all framework objectives, mapped or N/A]
Use the framework name dynamically from `mapping-results.json.framework.name`:
- Default (no input): "CSA CCMv4 Coverage Matrix"
- Customer NIST file: "NIST 800-53 Coverage Matrix"
- Customer CIS file: "CIS Benchmarks Coverage Matrix"
- Customer ISO file: "ISO 27001 Coverage Matrix"
- Customer custom file: "Custom Framework Coverage Matrix"

### Mitigation Traceability
[Full table from Step 3 — all customer mitigations with control and framework mappings]
Include coverage summary: N/N mitigations fully covered, N partially covered, N uncovered.

### Threat Model Coverage
**Include this section only if `mapping-results.json` contains `attack_coverage`.**

This section renders threat model coverage regardless of which threat model was used as input
(MITRE ATT&CK, custom STRIDE model, organizational threat catalog, etc.). The section title
and content adapt based on the `attack_coverage` data:

- Read `attack_coverage.attack_matrix_version` for the threat model version
- Read `attack_coverage.attack_matrix_source` for the source file name (if present)
- Use the threat model name from the source file or default to "Threat Model"

**Section title:** Use the threat model name dynamically (mirrors the 5-case
naming-rules table in `skills/research-attack-surface/SKILL.md`):
- If source contains "MITRE" or "ATT&CK" (or is the default `data/attack-cloud-matrix.json`) → "MITRE ATT&CK Threat Coverage (v{version})"
- If source contains "STRIDE" → "STRIDE Threat Coverage"
- If hybrid (multiple sources merged, e.g. MITRE + STRIDE) → "{combined_name} Threat Coverage" (e.g. "MITRE ATT&CK + STRIDE Threat Coverage")
- If source is a custom file → "Threat Model Coverage ({source_filename})"
- If no threat model source can be identified → "Threat Model Coverage"

Build a tactic/category heat map showing control coverage:

```
| Tactic / Category | Techniques | Covered | Coverage |
|-------------------|-----------|---------|----------|
| Initial Access (TA0001) | 3 | 2 | ██████░░ 67% |
| Execution (TA0002) | 2 | 2 | ████████ 100% |
| Persistence (TA0003) | 3 | 1 | ██░░░░░░ 33% |
[repeat for each tactic/category with applicable techniques]
```

Include a "Threat Gaps" sub-section listing uncovered HIGH-applicability techniques/threats:
- Technique/threat ID, name, and which categories it maps to
- Recommended control type to address the gap
- Priority (based on applicability: HIGH = immediate, MEDIUM = short-term)

**If `customer_stride_profile` exists in `research-attack-surface.json`**, also include a
STRIDE coverage summary showing which STRIDE categories have controls addressing them:

```
| STRIDE Category | Mitigations Referenced | Techniques Mapped | Controls Covering |
|-----------------|----------------------|-------------------|-------------------|
| Spoofing | M-AgentRuntime.0, ... | T1078.004, T1199 | CTRL-005, CTRL-006 |
[repeat for each STRIDE category]
```

### Control Inventory
[Per-layer table from Step 4, organized by Controls Matrix cell]

### Test Evidence
[Config rule finding count, Config compliance status, mitigation coverage %, framework coverage % — or "Test not run" if skipped]

### UNVERIFIED Items
[List with reasons, or "None — all items verified" if unverified_count = 0]

### Artifact Manifest
[Full file list from Step 5]

### Next Steps
Deployment order:
1. **Org level**: Apply SCPs, RCPs, tag policies via AWS Organizations
2. **Account level**: Deploy Config conformance pack, Config rules, Access Analyzer
3. **Service level**: Deploy CloudFormation Hooks, Config org rules
4. **Resource level**: Deploy detective controls (EventBridge, CloudWatch alarms, Lambda remediator), then create the compliant resource using the IaC template in `controls/iac/`

### Manual Deploy Commands

**Render this section only when `intake-manifest.json.testing.mode == "manual-cli"`.**

The user opted out of automated Phase 5 testing and asked for per-format deploy
commands. Inspect `.service-approval/controls/iac/` and emit only the commands that
match formats actually present. Always use placeholders (`<STACK_NAME>`,
`<AWS_PROFILE>`, `<AWS_REGION>`) — never substitute a real profile name.

```bash
python3 - <<'PY'
import json
from pathlib import Path

manifest = Path(".service-approval/state/intake-manifest.json")
if not manifest.exists():
    raise SystemExit(0)
mode = json.loads(manifest.read_text()).get("testing", {}).get("mode")
if mode != "manual-cli":
    raise SystemExit(0)

iac = Path(".service-approval/controls/iac")
has_cfn       = any(iac.glob("*.cfn.yaml")) or any(iac.glob("*.yaml"))
has_terraform = (iac / "modules").exists()
has_cdk       = any(iac.rglob("*.ts")) and not (iac / "cdktf").exists()
has_cdktf     = (iac / "cdktf").exists() or any(iac.rglob("cdktf.json"))

blocks = []
if has_cfn:
    blocks.append("""**CloudFormation:**
```bash
aws cloudformation deploy \\
  --template-file .service-approval/controls/iac/compliant-resource.cfn.yaml \\
  --stack-name <STACK_NAME> \\
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \\
  --profile <AWS_PROFILE>
```""")
if has_terraform:
    blocks.append("""**Terraform:**
```bash
cd .service-approval/controls/iac
terraform init
terraform plan -out tfplan
terraform apply tfplan
```""")
if has_cdk:
    blocks.append("""**CDK TypeScript:**
```bash
cd .service-approval/controls/iac
npm install
npx cdk bootstrap --profile <AWS_PROFILE>
npx cdk deploy --profile <AWS_PROFILE>
```""")
if has_cdktf:
    blocks.append("""**CDK for Terraform:**
```bash
cd .service-approval/controls/iac/cdktf
npm install
npx cdktf deploy
```""")
if (Path(".service-approval/controls/responsive/lambda-remediator/template.yaml")).exists():
    blocks.append("""**Detective controls stack (deploy after compliant resource):**
```bash
aws cloudformation deploy \\
  --template-file .service-approval/controls/responsive/lambda-remediator/template.yaml \\
  --stack-name <STACK_NAME>-detective \\
  --capabilities CAPABILITY_IAM \\
  --profile <AWS_PROFILE>
```""")

print("\n\n".join(blocks) if blocks else "No deployable IaC artifacts found.")
PY
```

Append the rendered blocks to `APPROVAL-REPORT.md` under this heading. Skip the
entire section when `testing.mode` is anything other than `manual-cli`.

Print:
```
Report written: .service-approval/APPROVAL-REPORT.md
Verdict: <APPROVED|APPROVED WITH EXCEPTIONS|REQUIRES REMEDIATION>
Framework: {name} — {mapped} / {total} objectives covered
Mitigations: {covered} / {total} addressed
Threat model: {threat_model_name} — {covered} / {total} techniques covered (if attack_coverage present)
Total control artifacts: N
```
