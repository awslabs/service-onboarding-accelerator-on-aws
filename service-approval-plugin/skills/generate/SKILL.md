---
name: generate
description: Generate all security control artifacts and compliant IaC templates from validated.json
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Control Generator v2

Read `.service-approval/state/validated.json` (produced by Validator v2). Generate artifacts
organized by the Controls Matrix (Category × Scope). Write to `.service-approval/controls/`.

## Prerequisites

- [ ] Confirm validated.json exists:
  ```bash
  test -f .service-approval/state/validated.json && echo "OK" || echo "ERROR: run validator first"
  ```

- [ ] Create output directories:
  ```bash
  mkdir -p .service-approval/controls/{proactive,preventive,detective,remediation,iac}
  mkdir -p .service-approval/controls/proactive/opa-policies
  mkdir -p .service-approval/controls/remediation/lambda-remediator
  ```

- [ ] Filter controls to generate: unless `--include-unverified` is set, skip any control
  where `verified: false`. Log skipped controls to the summary.

## Artifact header template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|resource>
# LAYER: <proactive|preventive|detective|remediation>
# CONTROLS: <comma-separated control IDs from controls[]>
# CCMv4: <comma-separated CCMv4 control IDs>
# MITRE: <comma-separated technique IDs e.g. T1078.004,T1562.008>
# GENERATED: service-approval v2.0.0
# SERVICE: <service-name>
```
For JSON files, add these as a `"_metadata"` key at the top level.
For TypeScript/HCL, use comment blocks.

Populate `CONTROLS` from the `id` fields of controls that contributed to this artifact.
Populate `MITRE` from `mitre_attack.technique_id` of threats linked to those controls.
Populate `CCMv4` from `ccmv4_mappings[]` entries for those controls.

---

## Generation by Controls Matrix

Iterate over `controls[]` in `validated.json`. Group by `category` × `scope`.
Generate one or more artifacts per cell. A single artifact may combine multiple controls
from the same cell — use the `id` field to group related controls into the right artifact.

---

### Organisation × Proactive

**Tag Policy (`preventive/tag-policy.json`)**:
For controls in this cell that enforce required tags:
- Generate an AWS Organizations tag policy
- Enforce tags: Owner, Environment, Purpose, CostCenter (plus any service-specific tags from controls)
- Use `awsknowledge` MCP to confirm valid tag key formats for the service

**OPA Org Policy (`proactive/opa-policies/org-policy.rego`)**:
For controls enforcing org-wide provisioning rules not expressible as tag policies:
- Generate OPA `.rego` rules that check CloudFormation/Terraform resources at pipeline time

**SCP Provisioning Deny (`preventive/scp-provisioning.json`)**:
For controls where `scp_expressible: true` and the intent is to block non-compliant resource
creation at provisioning time (distinct from runtime deny):
- Use the same SCP authoring rules as Organisation × Preventive below
- File suffix `-provisioning` to distinguish from runtime deny SCPs

---

### Organisation × Preventive

**SCP Runtime Deny (`preventive/scp-policy.json`)**:

Only generate SCP statements for controls where `scp_expressible: true`.
If `scp_expressible: false`, write a `_metadata.scp_gap` note explaining why
(e.g. "No condition key exists for this control; use Config rule instead") — skip generation.

Authoring rules (strict):
- Always `"Effect": "Deny"` — never Allow-only
- Always include the relevant condition key(s) — never a bare action deny without conditions
  (bare denies block legitimate use; conditions target only non-compliant calls)
- Use real condition keys from `awsknowledge` MCP — confirm each key is valid for the action
- Use `"NotAction"` pattern only for region-restriction controls
- Use `"Principal": "*"` only in resource-based policies, NOT in SCPs
- Respect the SCP size limit: track cumulative character count; if approaching 5120 chars,
  split into separate guardrail files (one concern per file, merged at deploy time)
- Add `"ArnNotLike": {"aws:PrincipalARN": ["arn:*:iam::*:role/BreakGlassRole"]}` exclusion
  in Condition for controls that should exempt emergency access roles

Guardrail format (array of statements, no Version wrapper — pipeline adds it at merge time):
```json
[
  {
    "Effect": "Deny",
    "Action": "<service>:CreateX",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "<service>:ConditionKey": "required-value"
      },
      "ArnNotLike": {
        "aws:PrincipalARN": ["arn:*:iam::*:role/BreakGlassRole"]
      }
    }
  }
]
```

Final `scp-policy.json` wraps all merged statements:
```json
{
  "_metadata": { ... },
  "Version": "2012-10-17",
  "Statement": [ <merged array of all guardrail statements> ]
}
```

After generating, validate using AWS IAM Access Analyzer (if `--env` is set):
```bash
aws accessanalyzer validate-policy \
  --policy-document file://.service-approval/controls/preventive/scp-policy.json \
  --policy-type SERVICE_CONTROL_POLICY \
  --query 'findings[?findingType==`ERROR` || findingType==`SECURITY_WARNING`]'
```
Block on ERROR or SECURITY_WARNING. Log SUGGESTION and WARNING only.

**AI Opt-out Policy (`preventive/ai-optout-policy.json`)**:
Only for controls where `ai_optout_applicable: true`. Generate org-level AI opt-out policy.

---

### Organisation × Detective

**Config Org Rules (`detective/config-org-rules.json`)**:
- Use `awsknowledge` MCP to find managed Config rules for each control's resource type
- Deploy org-wide via AWS Config Organizations aggregator
- Each rule entry maps to one or more control IDs in `_metadata`

**Security Hub Org Config (`detective/security-hub-org-config.json`)**:
- List Security Hub standards to enable org-wide
- List specific controls to enable per standard that map to controls in this cell

**CloudTrail Org Trail (`detective/cloudtrail-org-config.json`)**:
- Org trail configuration with data events enabled for the service's resource types

---

### Organisation × Corrective

**Org SSM Runbook (`remediation/ssm-runbook-org.yaml`)**:
- SSM Automation document for org-level corrective actions
- Triggered by Config Org Rule non-compliance events

---

### Account × Proactive

**CloudFormation Guard rules (`proactive/cfn-guard-rules.guard`)**:
- Use `awsiac` MCP to look up valid cfn-guard syntax for each resource type
- One rule per control in this cell checking the relevant `parameters_controlled`
- Append all rules to a single `.guard` file

**CloudFormation Hooks policy (`proactive/cfn-hooks-policy.json`)**:
- Use `awsiac` MCP to confirm the resource type supports CFN Hooks
- Generate activation policy JSON

**Checkov config (`proactive/checkov-config.yaml`)**:
- Generate Checkov configuration specifying checks for IAM, encryption, network, tagging
- Include check IDs that map to controls in this cell

**OPA Account policies (`proactive/opa-policies/<ResourceType>.rego`)**:
- One `.rego` file per resource type

---

### Account × Preventive

**Permission Boundary (`preventive/permission-boundary.json`)**:
- Limit role permissions to only what is needed for the service
- Scope to specific API actions from `api_surface` that align with controls in this cell
- Use `awsknowledge` MCP to get real action names

---

### Account × Detective

**Config rules (`detective/config-rules.json`)**:
- Use `awsknowledge` MCP to find managed Config rules covering each resource type
- For uncovered controls, generate custom Config rules (Lambda-backed)

**Config Conformance Pack (`detective/config-conformance-pack.yaml`)**:
- Bundle all Config rules from this cell into a conformance pack

**EventBridge rules (`detective/eventbridge-rules.json`)**:
- One rule per critical API operation (Create, Update, Delete, PutResourcePolicy)
- Pattern matches on CloudTrail event source and event name
- Target: Lambda remediator ARN placeholder

**CloudWatch alarms (`detective/cloudwatch-alarms.json`)**:
- Use `awsknowledge` MCP to confirm available metrics
- Generate alarms for error rates, throttling, unexpected API call patterns

**Access Analyzer (`detective/access-analyzer.json`)**:
- Only if any resource type supports resource-based policies
- Organization-level analyzer configuration

---

### Account × Corrective

**Lambda remediator (`remediation/lambda-remediator/handler.py`)**:
Write Python Lambda that:
1. Receives EventBridge event (CloudTrail non-compliant API call)
2. Parses event to extract resource ARN and violation details
3. Calls remediation action (add missing tag, update non-compliant policy, etc.)
4. Logs to CloudWatch

**Lambda CFN template (`remediation/lambda-remediator/template.yaml`)**:
CloudFormation template: Lambda + least-privilege IAM role + EventBridge trigger.

**SSM Runbook (`remediation/ssm-runbook.yaml`)**:
SSM Automation document for manual/scheduled remediation.

**Step Functions workflow (`remediation/stepfunctions-workflow.json`)**:
Multi-step workflow: detect → notify → remediate → verify → close finding.

---

### Resource × Proactive

**Per-resource CFN Guard rules**:
Append resource-specific rules to `.service-approval/controls/proactive/cfn-guard-rules.guard`
with a comment header separating resource-level rules from account-level rules.

---

### Resource × Preventive

**Resource Policy (`preventive/resource-policy.json`)**:
- Generate resource-based policy for the service's resource types
- Use `awsknowledge` MCP for real ARN patterns and action names
- Include confused deputy protection (`aws:SourceArn`, `aws:SourceAccount` conditions)

**KMS Key Policy (`preventive/kms-key-policy.json`)**:
- Only if encryption controls exist in this cell
- Generate CMK key policy with least-privilege grants
- Include `kms:ViaService` condition to restrict use to the service

**RCP (`preventive/rcp-policy.json`)**:
Only for controls where `rcp_expressible: true`.
If `rcp_expressible: false`, write a `_metadata.rcp_gap` note and skip.

Authoring rules (strict):
- Always `"Effect": "Deny"` and always `"Principal": "*"` — RCPs require both
- Use `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}` to exempt AWS service calls
- Use `"StringNotEquals": {"aws:PrincipalOrgID": "<org-id-placeholder>"}` for org restriction
- Do NOT generate RCP for `kms:RetireGrant` — exempt from RCPs
- Do NOT generate RCP for AWS-managed KMS keys (`aws/...` aliases)

Guardrail format (array of statements):
```json
[
  {
    "Effect": "Deny",
    "Principal": "*",
    "Action": "<service>:*",
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalOrgID": "${ORG_ID}"
      },
      "BoolIfExists": {
        "aws:PrincipalIsAWSService": "false"
      }
    }
  }
]
```

After generating, validate using AWS IAM Access Analyzer (if `--env` is set):
```bash
aws accessanalyzer validate-policy \
  --policy-document file://.service-approval/controls/preventive/rcp-policy.json \
  --policy-type RESOURCE_CONTROL_POLICY \
  --query 'findings[?findingType==`ERROR` || findingType==`SECURITY_WARNING`]'
```
Block on ERROR or SECURITY_WARNING.

**Declarative Policy (`preventive/declarative-policy.json`)**:
Only if `declarative_policy_expressible: true` for any control in this cell.

**Backup Policy (`preventive/backup-policy.json`)**:
Only if `backup_policy_applicable: true` for any control in this cell.

---

### Resource × Detective

**Resource-specific Config rules**:
Append to `.service-approval/controls/detective/config-rules.json` with resource-level scope.

---

### Resource × Corrective

**Resource-specific Step Functions workflow**:
Extend `.service-approval/controls/remediation/stepfunctions-workflow.json` with
resource-level remediation steps (e.g., encrypt unencrypted resource, remove public access).

---

## Compliant IaC templates

Generate using ALL controls (all matrix cells combined) as requirements:

**CDK TypeScript (`iac/compliant-resource.cdk.ts`)**:
Use `aws-cdk-mcp-server` MCP to get the correct L2/L3 construct for each resource type.
Generate a CDK construct class that creates the resource with ALL control requirements as
properties. Include comments referencing control IDs.

**Terraform module (`iac/compliant-resource.tf`)**:
Use `aws-documentation` MCP for the Terraform provider resource schema.
Generate module with required variables pre-set to compliant values.

**CloudFormation template (`iac/compliant-resource.cfn.yaml`)**:
Use `awsiac` MCP for resource schema.

**CDK for Terraform (`iac/compliant-resource.cdktf.ts`)**:
Use `aws-documentation` MCP for CDKTF provider bindings (`@cdktf/provider-aws`).

---

## Apply enrichment opportunities

For each `enrichment_opportunity` in `validated.json` with `verified: true`:
- Find the referenced control in the already-generated artifact(s)
- Add the specific enhancement (e.g., inject `aws:SourceArn` condition key, add
  `kms:ViaService` condition, expand VPC endpoint list)
- Re-annotate the artifact header with the enrichment reference

Enrichments refine existing artifacts — they do not create new files.

---

## Validate generated artifacts

```bash
# Validate all JSON files
for f in $(find .service-approval/controls -name "*.json"); do
  python3 -m json.tool "$f" > /dev/null && echo "OK: $f" || echo "INVALID: $f"
done

# Validate key IAM policy files with Access Analyzer
for f in .service-approval/controls/preventive/scp-policy.json \
          .service-approval/controls/preventive/rcp-policy.json \
          .service-approval/controls/preventive/permission-boundary.json; do
  [ -f "$f" ] && aws accessanalyzer validate-policy \
    --policy-document "file://$f" \
    --policy-type SERVICE_CONTROL_POLICY 2>&1 | grep -q "ValidationException" \
    && echo "INVALID: $f" || echo "OK: $f"
done

# Validate all YAML files
for f in $(find .service-approval/controls -name "*.yaml" -o -name "*.yml"); do
  python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" && echo "OK: $f" || echo "INVALID: $f"
done
```

---

## Print summary

```
Control generation complete (v2):
  Controls matrix:
    Org×Proactive:    tag-policy, OPA org policy [, scp-provisioning if applicable]
    Org×Preventive:   scp-policy [, ai-optout-policy if applicable]
    Org×Detective:    config-org-rules, security-hub-org-config, cloudtrail-org-config
    Org×Corrective:   ssm-runbook-org
    Acc×Proactive:    cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA policies
    Acc×Preventive:   permission-boundary
    Acc×Detective:    config-rules, conformance-pack, eventbridge-rules, cloudwatch-alarms [, access-analyzer]
    Acc×Corrective:   lambda-remediator, ssm-runbook, stepfunctions-workflow
    Res×Preventive:   resource-policy [, kms-key-policy] [, rcp-policy] [, declarative-policy] [, backup-policy]
    Res×Corrective:   stepfunctions-workflow (resource-level steps)
  IaC:                CDK (TypeScript), Terraform, CloudFormation, CDK for Terraform
  Controls skipped (unverified): N
  Output: .service-approval/controls/
```
