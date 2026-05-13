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

### Mode 1: From Intake File (recommended for repeatable use)

```bash
service-approval --from-intake=intakes/bedrock-agentcore.yaml
```

Reads a YAML file with all configuration. See `intake-template.yaml` for the schema.
No interactive prompts — pipeline starts immediately.

### Mode 2: Interactive (default when no file provided)

Present the intake form to the user and collect answers.

### Mode 3: CLI Flags

```bash
service-approval --service=s3 ./input --env=my-profile --framework=ccmv4
```

All required fields provided via flags — no prompts needed.

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

### 3. Testing Requirements (optional)

```
Do you want to deploy and validate the generated controls against a live AWS account?
  [ ] Yes — provide your AWS CLI profile name and region
  [ ] No — generate controls only (no deployment)
```

- If testing is requested, record the profile name and region
- If no testing, the pipeline will skip Phase 5 (Test) entirely
- Default: No testing (safe default — no credentials required)

### 4. Additional Options (optional)

```
Additional options:
  [ ] Include MITRE ATT&CK threat mapping (adds ~15 min to pipeline)
  [ ] Generate artifact dependency matrix (ARTIFACT-FLOW-MATRIX.md)
```

---

## Output

Write to `.service-approval/state/intake-manifest.json`:

```json
{
  "schema_version": "2.0.0",
  "generated_at": "{ISO-8601 timestamp}",
  "service": {
    "name": "{service-name}",
    "friendly_name": "{AWS Service Friendly Name}",
    "sar_slug": "{slug from sar-slugs.json}",
    "service_prefix": "{IAM prefix}"
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
    "enabled": true|false,
    "aws_profile": "{profile-name or null}",
    "region": "{region or us-east-1}",
    "dry_run": true|false
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
    "skip_attack_surface": true|false,
    "include_unverified": false,
    "clean": false
  }
}
```

**Note:** `iac_formats` and `iac_support` are NOT in the intake manifest. They are
determined by Phase 0 (Assess) and written to `state/iac-support.json`.

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
│  Testing:        {Yes (profile: X, region: Y) | No}        │
│  ATT&CK Mapping: {Yes | No}                                │
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
| AWS profile not configured | Warn and disable testing (set `skip_test: true`) |
| Intake YAML file not found | Fall back to interactive mode |
| Intake YAML missing required fields | Report which fields are missing, halt |

---

## Downstream Consumption

| Phase | What it reads from intake-manifest.json |
|-------|----------------------------------------|
| Phase 0 (Assess) | `service`, `inputs.input_folder`, `service.sar_slug` |
| Phase 1 (Research) | `service`, `inputs.*`, `output.include_attack_surface` |
| Phase 2 (Validate) | `service` |
| Phase 3 (Map) | `inputs.framework_type`, `inputs.framework_file` |
| Phase 4 (Generate) | Reads `state/iac-support.json` (from Phase 0), NOT intake |
| Phase 5 (Test) | `testing.*` |
| Phase 6 (Summarize) | Full manifest for report metadata |

---

## Print Summary

```
Intake complete:
  Service: {friendly_name} ({service-id})
  SAR slug: {slug}
  Inputs: {N} files ({types})
  Framework: {framework_type}
  Testing: {enabled/disabled}
  Manifest: .service-approval/state/intake-manifest.json

IaC formats will be determined in Phase 0 (Assess).
Ready for Phase 0.
```
