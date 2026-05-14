---
name: intake
description: >
  Precursor intake phase for the Service Approval pipeline. Collects service name, input type,
  and testing preferences. Produces intake-manifest.json consumed by all downstream phases.
  Supports file-based input (intake YAML) for repeatable, batch-friendly execution.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--from-intake=<file>] [--interactive]"
---

# Service Approval — Intake

Collect and validate inputs before the pipeline begins. This phase runs before Phase 0
(Assess) and produces a manifest that configures the downstream pipeline.

**IaC format selection is NOT part of intake.** The Assess phase (Phase 0) discovers which
IaC providers support the target service and presents the available options to the user.
This ensures format decisions are based on facts, not guesses.

---

## Background — What This Tool Does

The **Service Approval Pipeline** generates a complete set of AWS security controls for any
AWS service. It produces:

| Category | What you get |
|----------|--------------|
| **Proactive controls** | CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies |
| **Preventive controls** | SCPs, RCPs, declarative policies, permission boundaries, tag policies, resource policies, KMS key policies |
| **Detective controls** | AWS Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer configurations |
| **Responsive controls** | Lambda auto-remediators, SSM runbooks, Step Functions remediation workflows |
| **Compliant IaC templates** | Automatically determined based on provider support (CloudFormation, Terraform, CDK, CDKTF) |
| **Framework mapping** | Controls mapped to CCMv4, NIST 800-53, CIS Benchmarks, or ISO 27001 objectives |
| **Threat model** | MITRE ATT&CK technique mapping with tactic coverage analysis (optional) |

The pipeline verifies every claim via MCP servers (no hardcoded training data), maps controls
to your chosen compliance framework, and produces deployable artifacts — not just documentation.

**Typical output:** 85+ files across 5 control categories, a framework coverage matrix, and a
final approval report with verdict.

---

## Input Modes

### Mode 1: Explicit intake file

```bash
service-approval --from-intake=path/to/my-service.yaml
```

Reads the YAML at the given path. No interactive prompts unless required fields
are missing. CLI flag wins over auto-discovery.

### Mode 2: Auto-discovered project intake (recommended for repeated runs)

If `./service-approval-intake.yaml` exists in the user's current working
directory, it is loaded automatically. The user is shown a summary and given
two choices: **[U]se as-is** or **[E]dit a field** (see "Existing Intake Flow"
below). This is the path most users hit on their second and subsequent runs.

### Mode 3: Interactive (first-time path)

When no intake YAML is found and no flags are provided, present the full intake
form. After the user confirms, **offer to save** the answers to
`./service-approval-intake.yaml` so the next run can auto-discover them.

### Mode 4: CLI flags

```bash
service-approval --service=s3 ./input --env=my-profile --framework=ccmv4
```

All required fields provided via flags — no prompts needed. `--interactive`
forces the full prompt flow even when a YAML or manifest exists (escape hatch).

---

## Discovery Rules

Resolution order, highest priority first:

1. **`--from-intake=<path>` flag** — explicit, always honored.
2. **`./service-approval-intake.yaml` in CWD** — auto-discovered. Show summary,
   prompt `[U]se as-is / [E]dit`.
3. **None found** — fall through to the interactive form (first-time path).

**Plugin-repo guard:** Files inside the installed plugin directory
(`skills/intake/intake-template.yaml`, `skills/intake/defaults.yaml`, anything
under the plugin root) are **never** auto-loaded as user intake. They are
templates and org defaults, not user data. Reject any auto-discovery path that
resolves inside the plugin install dir; if `--from-intake` explicitly points
there, warn and refuse.

`--interactive` short-circuits steps 1 and 2 — always run the full prompt flow.

---

## Existing Intake Flow

When `./service-approval-intake.yaml` is found (and `--interactive` was not
passed), render a digestible summary and prompt:

```
┌─ Existing intake found: ./service-approval-intake.yaml ─┐
│  Service:        {friendly_name} ({service-id})         │
│  Framework:      {framework_type}                       │
│  Testing mode:   {full-deploy | dry-run | skip | manual-cli} │
│  AWS profile:    {profile or n/a}                       │
│  Region:         {region}                               │
│  ATT&CK Mapping: {Yes | No}                             │
└─────────────────────────────────────────────────────────┘

[U]se as-is   [E]dit a field   (default: U)
```

- **Use as-is** (default): proceed with the loaded values, write the manifest,
  continue to Phase 0.
- **Edit a field**: walk the user through the intake fields one at a time with
  current values pre-filled. The user accepts each (Enter) or overrides. After
  edits, write the updated YAML back to `./service-approval-intake.yaml` and
  continue.

There is no "fresh start" option in this prompt. To start over, the user
deletes `./service-approval-intake.yaml` or passes `--interactive`.

---

## First-Time Save Prompt

After the interactive form completes (Mode 3), before writing the runtime
manifest, ask:

```
Save these answers to ./service-approval-intake.yaml so future runs skip
the prompts? (Y/n)
```

If yes, serialize the collected fields into the YAML schema from
`intake-template.yaml` and write to the user's CWD. Do **not** write into the
plugin repo.

---

## Intake Form Fields

Present this form when running interactively. Fields marked **(required)** must be answered.

### 1. Service Name (required)

```
What AWS service should we generate security controls for?
Examples: s3, lambda, bedrock-agentcore-control, kms, ecs, dynamodb
```

- Accept any valid AWS service identifier (lowercase, hyphenated)
- If the user provides a friendly name (e.g., "Amazon S3"), normalize to the service ID (`s3`)
- Validate the service exists by checking `data/sar-slugs.json` for a matching entry

### 2. Input Type (optional)

```
Are you providing any of the following? (select all that apply)
  [ ] Custom threat model (.md, .json, .pdf, .docx)
  [ ] Custom control framework (.xlsx, .json — CCMv4, NIST, CIS, ISO)
  [ ] Existing mitigation report (.md, .json)
  [ ] None — use MCP-only mode (research everything from scratch)
```

- If custom inputs are provided, record the input folder path
- If a custom control framework is provided, detect the framework type:
  - Filename contains "CCMv4" or "ccm" → `ccmv4`
  - Filename contains "NIST" or "800-53" → `nist`
  - Filename contains "CIS" → `cis`
  - Filename contains "ISO" or "27001" → `iso`
- If no framework file is provided, default to `ccmv4`

### 3. Testing Requirements (required — default: `skip`)

This is the single point where the user declares how Phase 5 (Test) should run.
There is no later human-in-the-loop gate — whatever is chosen here is what the
pipeline does.

```
How do you want to validate the generated controls?

  A. Full deploy + validate  (mode: full-deploy)
     Deploys the compliant resource template into an AWS account, waits for
     Config rule evaluations, checks CloudWatch alarms, then tears down.
     Requires an AWS CLI profile.

  B. Dry-run validation only  (mode: dry-run)
     Runs static checks (terraform validate, cfn-lint, CDK tsc, CFN Guard
     syntax, py_compile). Optionally CloudFormation validate-template + IAM
     Access Analyzer if a profile is provided. No deployment.

  C. Skip testing  (mode: skip)
     Stop after generation. Artifacts remain on disk for manual review.

  D. Manual CLI — show commands  (mode: manual-cli)
     Skip Phase 5. The Summarize phase appends per-format deploy commands
     (terraform apply, cdk deploy, aws cloudformation deploy) to the final
     approval report so you can run them yourself later.
```

Validation rules:
- `full-deploy` requires `aws_profile`; if missing, re-prompt. If the profile
  is not configured in `~/.aws/credentials` or `~/.aws/config`, warn and
  downgrade to `mode: skip`.
- `dry-run` accepts a profile (enables Tier 2 static checks) but does not
  require one.
- `manual-cli` does not require a profile — the cheat-sheet uses
  `<AWS_PROFILE>` placeholders.
- Default when the user declines to choose: `skip`.

### 4. Additional Options (optional)

```
Additional options:
  [ ] Include MITRE ATT&CK threat mapping (adds ~15 min to pipeline)
  [ ] Generate artifact dependency matrix (ARTIFACT-FLOW-MATRIX.md)
```

---

## Output

**CRITICAL:** Intake runs BEFORE the canonical service slug is known (slug is derived by Phase 0 Assess from the SAR `service_prefix`). Therefore, intake writes to a staging directory indexed by timestamp.

Compute the staging timestamp:

```bash
STAGING_TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")
STAGING_DIR=".service-approval/_staging/${STAGING_TS}"
mkdir -p "${STAGING_DIR}/00-intake"
```

Or using Python:

```python
from datetime import datetime, timezone
from pathlib import Path
staging_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
staging_dir = Path(f".service-approval/_staging/{staging_ts}/00-intake")
staging_dir.mkdir(parents=True, exist_ok=True)
manifest_path = staging_dir / "intake-manifest.json"
```

Write to `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json`:

```json
{
  "schema_version": "2.1.0",
  "generated_at": "{ISO-8601 timestamp}",
  "staging_timestamp": "{STAGING_TS}",
  "service": {
    "name": "{service-name}",
    "friendly_name": "{AWS Service Friendly Name}",
    "sar_slug": "{slug from sar-slugs.json}",
    "service_prefix": "{IAM prefix}",
    "candidate_slug": "{lowercase, hyphenated service name from user input}"
  },
  "inputs": {
    "input_folder": "{path or null}",
    "has_custom_threat_model": true|false,
    "has_custom_framework": true|false,
    "framework_type": "ccmv4|nist|cis|iso",
    "framework_file": "{path or null}",
    "has_mitigation_report": true|false,
    "input_files": [
      {"path": "...", "type": "threat_model|framework|mitigation_report|context"}
    ]
  },
  "testing": {
    "mode": "full-deploy|dry-run|skip|manual-cli",
    "aws_profile": "{profile-name or null}",
    "region": "{region or us-east-1}",
    "keep": false,
    "timeout_minutes": 30
  },
  "output": {
    "include_attack_surface": true|false,
    "include_artifact_matrix": true|false
  },
  "pipeline_flags": {
    "service": "{service-name}",
    "input_folder": "{path or null}",
    "env": "{profile or null}",
    "region": "{region}",
    "framework": "{type}",
    "framework_file": "{path or null}",
    "skip_test": true|false,
    "dry_run": true|false,
    "keep": true|false,
    "timeout": 30,
    "skip_attack_surface": true|false,
    "include_unverified": false,
    "clean": false
  }
}
```

**Derivation from `testing.mode` to `pipeline_flags`:**

| `testing.mode` | `skip_test` | `dry_run` | `env`               | Phase 5 effect                         |
|----------------|-------------|-----------|---------------------|----------------------------------------|
| `full-deploy`  | false       | false     | `testing.aws_profile` | `test` full mode                     |
| `dry-run`      | false       | true      | `testing.aws_profile` or null | `test` `--dry-run` (Tier 1/2)  |
| `skip`         | true        | false     | null                | Phase 5 skipped                        |
| `manual-cli`   | true        | false     | null                | Phase 5 skipped; Summarize prints CLI cheat-sheet |

CLI flag overrides: if the user passes `--env`, `--skip-test`, or `--dry-run`
to the orchestrator, those override the intake-derived flags (CLI > intake >
defaults).

**Note:** `iac_formats` and `iac_support` are NOT in the intake manifest. They are
determined by Phase 0 (Assess) and written to `<slug>/01-assess/iac-support.json`.

**Staging → Canonical Promotion:** Phase 0 (Assess) will atomically promote this staging directory to `.service-approval/<slug>/` after deriving the canonical slug from the SAR `service_prefix`. The promotion is described in Phase 0's Step 0b.

---

## User Confirmation

After collecting inputs, present a summary:

```
┌─────────────────────────────────────────────────────────────┐
│  SERVICE APPROVAL — Intake Summary                          │
├─────────────────────────────────────────────────────────────┤
│  Service:        {friendly_name} ({service-id})             │
│  Input:          {description of inputs}                    │
│  Framework:      {framework_type}                           │
│  Testing mode:   {full-deploy | dry-run | skip | manual-cli}│
│  AWS profile:    {profile or n/a}                           │
│  Region:         {region}                                   │
│  ATT&CK Mapping: {Yes | No}                                 │
├─────────────────────────────────────────────────────────────┤
│  Note: IaC output formats will be determined in Phase 0     │
│  (Assess) based on actual provider support for this service.│
└─────────────────────────────────────────────────────────────┘

Proceed? (Y/n)
```

---

## Error Handling

| Condition | Action |
|-----------|--------|
| Service not found in `sar-slugs.json` | Warn user, attempt SAR page lookup via MCP. If found, continue. If not, halt. |
| Input folder path invalid | Ask user to correct the path |
| `testing.mode == full-deploy` but `aws_profile` missing | Re-prompt for profile; if still missing, downgrade to `mode: skip` |
| AWS profile not configured in `~/.aws/` | Warn and downgrade `testing.mode` to `skip` |
| Intake YAML file not found | Fall back to interactive mode |
| Intake YAML missing required fields | Report which fields are missing, halt |
| Intake YAML has invalid `testing.mode` | List valid modes (full-deploy, dry-run, skip, manual-cli), halt |

---

## Downstream Consumption

| Phase | What it reads from intake-manifest.json |
|-------|----------------------------------------|
| Phase 0 (Assess) | `service`, `inputs.input_folder`, `service.sar_slug`, `staging_timestamp` (to locate staging dir for promotion) |
| Phase 1 (Research) | `service`, `inputs.*`, `output.include_attack_surface` |
| Phase 2 (Validate) | `service` |
| Phase 3 (Map) | `inputs.framework_type`, `inputs.framework_file` |
| Phase 4 (Generate) | Reads `<slug>/01-assess/iac-support.json` (from Phase 0), NOT intake |
| Phase 5 (Test) | `testing.mode`, `testing.aws_profile`, `testing.region`, `testing.timeout_minutes` (orchestrator translates to `--env` / `--skip-test` / `--dry-run`). Note: Phase 5 always passes `--keep` to smoke-deploy-test.sh when Phase 7 is in scope; `testing.keep` itself is consumed by Phase 7, not Phase 5. |
| Phase 6 (Summarize) | Full manifest for report metadata; `testing.mode` drives the manual-cli cheat-sheet render when mode == `manual-cli` |
| Phase 7 (Evidence) | `testing.keep` — when `true`, Phase 7 skips its end-of-run teardown (stack stays alive for manual debugging); when `false` (default), Phase 7 tears down the stack from `06-test/deployed-resources.json` after evidence collection completes. |

---

## Print Summary

```
Intake complete:
  Service: {friendly_name} ({service-id})
  SAR slug: {slug}
  Inputs: {N} files ({types})
  Framework: {framework_type}
  Testing mode: {full-deploy|dry-run|skip|manual-cli} (profile: {name or n/a}, region: {region})
  Staging: .service-approval/_staging/{STAGING_TS}/00-intake/intake-manifest.json

Canonical service slug will be derived in Phase 0 (Assess).
IaC formats will be determined in Phase 0 (Assess).
Ready for Phase 0.
```
