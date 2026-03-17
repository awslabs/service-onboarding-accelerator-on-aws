---
name: generate
description: Generate all security control artifacts and compliant IaC templates from validated.json
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Control Generator

Read `.service-approval/state/validated.json`. Generate all applicable control artifacts and
compliant IaC templates. Write to `.service-approval/controls/`.

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

## Artifact header template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|service|resource>
# LAYER: <proactive|preventive|detective|remediation>
# MITIGATIONS: <comma-separated mitigation IDs>
# CCMv4: <comma-separated control IDs>
# MITRE: <comma-separated technique IDs e.g. T1530,T1562.008>
# GENERATED: service-approval v1.0.0
# SERVICE: <service-name>
```
For JSON files, add these as a `"_metadata"` key at the top level.
For TypeScript/HCL, use comment blocks.

## Step 1: Proactive controls

For each item with `applicable_controls.proactive` containing `cfn-guard-rules`:
- Use `awsiac` MCP to look up valid cfn-guard syntax for the resource type
- Generate a rule that checks the specific parameter(s) the mitigation covers
- Append to `.service-approval/controls/proactive/cfn-guard-rules.guard`

For `cfn-hooks-policy`:
- Use `awsiac` MCP to confirm the resource type supports CFN Hooks
- Generate a CloudFormation Hooks activation policy JSON
- Write to `.service-approval/controls/proactive/cfn-hooks-policy.json`

For `checkov-config.yaml`:
- Generate a Checkov configuration file specifying checks relevant to the resource type
- Include check IDs for IAM, encryption, network, and tagging policies
- Write to `.service-approval/controls/proactive/checkov-config.yaml`

For OPA policies:
- Generate one OPA `.rego` file per resource type
- Write to `.service-approval/controls/proactive/opa-policies/<ResourceType>.rego`

## Step 2: Preventive controls

For each applicable policy type, generate using real condition keys from `awsknowledge` MCP:

**SCP (`scp-policy.json`)**: Deny the relevant API actions unless required conditions are met.
Pattern: Deny CreateX/UpdateX where the required parameter is missing or non-compliant.
Must include at least one Deny statement — never Allow-only.

**RCP (`rcp-policy.json`)**: Restrict resource access to trusted identities and organizations.

**Declarative Policy (`declarative-policy.json`)**: Only generate if `awsknowledge` MCP confirms
a declarative policy type exists for this service.

**AI Opt-out Policy (`ai-optout-policy.json`)**: Only for AI/ML services.

**Backup Policy (`backup-policy.json`)**: Only if service resources are AWS Backup-compatible.

**Tag Policy (`tag-policy.json`)**: Enforce required tags: Owner, Environment, Purpose, CostCenter.

**Permission Boundary (`permission-boundary.json`)**: Limit role permissions to only what is needed.

**Config Org Rules (`config-org-rules.json`)**: Deploy Config rules org-wide.

**Config Conformance Pack (`config-conformance-pack.yaml`)**: Bundle all Config rules.

For each policy, use `awsknowledge` MCP to get:
- Real API action names (e.g., `bedrock-agentcore:CreateAgentRuntime`)
- Real condition key names (e.g., `aws:SourceArn`, `aws:SourceAccount`)
- Real resource ARN patterns

## Step 3: Detective controls

**Config rules (`config-rules.json`)**:
- Use `awsknowledge` MCP to find managed Config rules covering the resource type
- For uncovered gaps, generate custom Config rules (Lambda-backed)
- Each rule maps to one or more mitigation IDs in `_metadata`

**EventBridge rules (`eventbridge-rules.json`)**:
- Generate one rule per critical API operation (Create, Update, Delete, PutResourcePolicy)
- Pattern matches on CloudTrail event source and event name
- Target: Lambda remediator ARN (placeholder: `arn:aws:lambda:<region>:<account>:function:service-approval-remediator`)

**CloudWatch alarms (`cloudwatch-alarms.json`)**:
- Use `awsknowledge` MCP to confirm available metrics for the service
- Generate alarms for error rates, throttling, unexpected API call patterns

**Security Hub config (`security-hub-config.json`)**:
- List Security Hub standards to enable (e.g., AWS Foundational Security Best Practices)
- List Security Hub controls to explicitly enable per standard

**Access Analyzer (`access-analyzer.json`)**: Organization-level analyzer configuration.

**CloudTrail config (`cloudtrail-config.json`)**: Org trail with data events for the service.

## Step 4: Remediation

**Lambda remediator (`remediation/lambda-remediator/handler.py`)**:
Write Python Lambda function that:
1. Receives EventBridge event (CloudTrail CreateX/UpdateX with non-compliant parameters)
2. Parses event to extract resource ARN and violation details
3. Calls remediation action (add missing required tag, update non-compliant resource policy, etc.)
4. Logs remediation to CloudWatch

**Lambda CFN template (`remediation/lambda-remediator/template.yaml`)**:
CloudFormation template deploying Lambda + IAM role (least-privilege) + EventBridge trigger.

**SSM Runbook (`remediation/ssm-runbook.yaml`)**: SSM Automation document for manual/scheduled remediation.

**Step Functions workflow (`remediation/stepfunctions-workflow.json`)**: Multi-step remediation
(e.g., detect → notify → remediate → verify → close finding).

## Step 5: Compliant IaC templates

**CDK TypeScript (`iac/compliant-resource.cdk.ts`)**:
Use `aws-cdk-mcp-server` MCP to get correct L2/L3 construct for each resource type.
Generate CDK construct class that creates the resource with ALL mitigation requirements as properties.
Include comments referencing each mitigation ID.

**Terraform module (`iac/compliant-resource.tf`)**:
Use `aws-documentation` MCP for the Terraform provider resource schema.
Generate Terraform module with required variables pre-set to compliant values.

**CloudFormation template (`iac/compliant-resource.cfn.yaml`)**:
Use `awsiac` MCP for resource schema. If CFN resource type not yet registered, use
CloudFormation custom resource backed by Lambda SDK calls.

**CDK for Terraform (`iac/compliant-resource.cdktf.ts`)**:
Use `aws-documentation` MCP for CDKTF provider bindings (`@cdktf/provider-aws`).
Generate CDKTF stack class with same compliant property values as the CDK construct.

## Step 6: Apply enrichment opportunities

For each `enrichment_opportunity` in `validated.json` with `verified: true`:
- Look up the referenced `mitigation_id` in the already-generated artifact(s)
- Add the specific enhancement (e.g., inject the `aws:SourceArn` condition key example into
  the SCP, add `kms:ViaService` condition to KMS policy, expand VPC endpoint list in CFN template)
- Re-annotate the artifact header with the enrichment opportunity reference

Enrichments refine existing artifacts — they do not create new files.

## Step 7: Validate generated artifacts

```bash
# Validate all JSON files (syntax)
for f in $(find .service-approval/controls -name "*.json"); do
  python3 -m json.tool "$f" > /dev/null && echo "OK: $f" || echo "INVALID: $f"
done

# Validate IAM policy semantics for key policy files
for f in .service-approval/controls/preventive/scp-policy.json \
          .service-approval/controls/preventive/rcp-policy.json \
          .service-approval/controls/preventive/permission-boundary.json; do
  [ -f "$f" ] && aws iam validate-policy \
    --policy-document "file://$f" \
    --policy-type SERVICE_CONTROL_POLICY 2>&1 | grep -q "ValidationException" \
    && echo "INVALID: $f" || echo "OK: $f"
done

# Validate all YAML files
for f in $(find .service-approval/controls -name "*.yaml" -o -name "*.yml"); do
  python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" && echo "OK: $f" || echo "INVALID: $f"
done
```

## Step 8: Print summary

```
Control generation complete:
  Proactive:   cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA policies
  Preventive:  SCP, RCP, tag-policy, permission-boundary, config-org-rules [+ applicable]
  Detective:   config-rules, eventbridge-rules, cloudwatch-alarms, security-hub-config
  Remediation: lambda-remediator, ssm-runbook, stepfunctions-workflow
  IaC:         CDK (TypeScript), Terraform, CloudFormation, CDK for Terraform
  Output: .service-approval/controls/
```

## Verify frontmatter
```bash
head -5 skills/generate/SKILL.md
```
Expected: starts with `---` and contains `name: generate`.

## Commit
```bash
cd "/Users/hardikvt/Library/CloudStorage/OneDrive-amazon.com/Hackathon/service-approval-plugin"
git add skills/generate/SKILL.md
git commit -m "feat: add control generator agent skill"
```

Report: Status DONE + commit SHA.
