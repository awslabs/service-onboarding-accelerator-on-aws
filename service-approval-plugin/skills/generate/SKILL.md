---
name: generate
description: Generate all security control artifacts and compliant IaC templates from validated.json
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Control Generator v2

Read `.service-approval/state/validated.json` (produced by Validator v2). Generate artifacts
organized by the Controls Matrix (Category × Scope). Write to `.service-approval/controls/`.

## Agent model rule

When spawning subagents (via the Agent tool) for parallel artifact generation, do NOT specify
a `model` parameter. Omitting `model` causes subagents to inherit the caller's model. This
ensures the same model quality used to invoke the skill is applied to all generated artifacts.

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

- [ ] Create Terraform module directories (one per asset in validated.json):
  ```bash
  for asset in $(python3 -c "import json; d=json.load(open('.service-approval/state/validated.json')); [print(a['name'].lower().replace(' ','-')) for a in d['assets']]"); do
    mkdir -p ".service-approval/controls/iac/modules/${asset}"
  done
  mkdir -p .service-approval/controls/iac/modules/_shared
  ```

- [ ] Filter controls to generate: unless `--include-unverified` is set, skip any control
  where `verified: false`. Log skipped controls to the summary.

## Per-control rule differentiation

Even when multiple controls share the same artifact type (e.g., both CTRL-ACC-PRO-001 and
CTRL-ACC-PRO-003 need `cfn-guard-rules`), the specific rules generated within that artifact
must differ based on each control's security goal (`description` and `parameters_controlled`):

- Do NOT copy-paste one rule for every control — generate distinct rules per control
- The rule name/comment must reference the specific control ID (e.g., `rule enforce_kms_ctrl_acc_pro_001`)
- If two controls have the same `parameters_controlled` but different `description`, generate
  separate rules with separate comments explaining each security objective

## Artifact header template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|resource>
# LAYER: <proactive|preventive|detective|remediation>
# CONTROLS: <comma-separated control IDs from controls[]>
# CCMv4: <comma-separated CCMv4 control IDs — FULL union from ALL controls and threats>
# MITRE: <comma-separated technique IDs e.g. T1078.004,T1562.008>
# GENERATED: service-approval v2.0.0
# SERVICE: <service-name>
```
For JSON files, add these as a `"_metadata"` key at the top level.
For TypeScript/HCL, use comment blocks.

- `CONTROLS` — `id` fields of controls that contributed to this artifact
- `CCMv4` — FULL union from ALL ccmv4_mappings[] entries across all controls and threats.
  Copy the identical sorted CCMv4 list to EVERY file header, including per-module TF files.
  Do NOT filter by resource type. Do NOT omit IDs present in the union.
- `MITRE` — `mitre_attack.technique_id` values from threats[] linked to those controls

### Metadata completeness rule

The `CONTROLS` list must include every control ID whose category+scope maps to this artifact.
The `CCMv4` list must include every CCMv4 ID from `ccmv4_mappings[]` in the union across all
controls and threats — never a subset. The `MITRE` list must include all technique IDs from
`threats[]` linked to those controls. Missing any ID is a generation error.

---

## Generation by Controls Matrix

Iterate over `controls[]` in `validated.json`. Group by `category` × `scope`.
Generate one or more artifacts per cell. A single artifact may combine multiple controls
from the same cell — use the `id` field to group related controls into the right artifact.

---

### Organisation × Proactive

**Tag Policy (`preventive/tag-policy.json`)**:
- Generate an AWS Organizations tag policy enforcing: Owner, Environment, Purpose, CostCenter
  plus any service-specific tags from controls in this cell
- Use `awsknowledge` MCP to confirm valid tag key formats

**OPA Org Policy (`proactive/opa-policies/org-policy.rego`)**:
- Generate OPA `.rego` rules for org-wide provisioning rules not expressible as tag policies

**SCP Provisioning Deny (`preventive/scp-provisioning.json`)**:
- Only for controls where `scp_expressible: true` with provisioning-time intent
- Use the same SCP authoring rules as Organisation × Preventive below
- File suffix `-provisioning` to distinguish from runtime deny SCPs

---

### Organisation × Preventive

**SCP Runtime Deny (`preventive/scp-policy.json`)**:

Only generate SCP statements for controls where `scp_expressible: true`.
If `scp_expressible: false`, write a `_metadata.scp_gap` note explaining why and skip.

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
      "StringNotEquals": { "<service>:ConditionKey": "required-value" },
      "ArnNotLike": { "aws:PrincipalARN": ["arn:*:iam::*:role/BreakGlassRole"] }
    }
  }
]
```

Final `scp-policy.json` wraps all merged statements:
```json
{ "_metadata": { ... }, "Version": "2012-10-17", "Statement": [ ... ] }
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
Only for controls where `ai_optout_applicable: true`.

---

### Organisation × Detective

**Config Org Rules (`detective/config-org-rules.json`)**:
- Use `awsknowledge` MCP to find managed Config rules for each control's resource type
- Deploy org-wide via AWS Config Organizations aggregator

**Security Hub Org Config (`detective/security-hub-org-config.json`)**:
- List Security Hub standards to enable org-wide
- List specific controls per standard that map to controls in this cell

**CloudTrail Org Trail (`detective/cloudtrail-org-config.json`)**:
- Org trail with data events enabled for the service's resource types

---

### Organisation × Corrective

**Org SSM Runbook (`remediation/ssm-runbook-org.yaml`)**:
- SSM Automation document for org-level corrective actions
- Triggered by Config Org Rule non-compliance events

---

### Account × Proactive

**CloudFormation Guard rules (`proactive/cfn-guard-rules.guard`)**:
- Use `awsiac` MCP to look up valid cfn-guard syntax for each resource type
- One distinct rule per control in this cell referencing `parameters_controlled`
- Rule name must include the control ID (e.g., `rule enforce_encryption_ctrl_acc_pro_001`)

**CloudFormation Hooks policy (`proactive/cfn-hooks-policy.json`)**:
- Use `awsiac` MCP to confirm the resource type supports CFN Hooks

**Checkov config (`proactive/checkov-config.yaml`)**:
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
- Bundle all Config rules into a conformance pack

**EventBridge rules (`detective/eventbridge-rules.json`)**:
- One rule per critical API operation (Create, Update, Delete, PutResourcePolicy)

**CloudWatch alarms (`detective/cloudwatch-alarms.json`)**:
- Use `awsknowledge` MCP to confirm available metrics

**Access Analyzer (`detective/access-analyzer.json`)**:
- Only if any resource type supports resource-based policies

---

### Account × Corrective

**Lambda remediator (`remediation/lambda-remediator/handler.py`)**:
Python Lambda: receive EventBridge event → parse resource ARN + violation → remediate → log.

**Lambda CFN template (`remediation/lambda-remediator/template.yaml`)**:
Lambda + least-privilege IAM role + EventBridge trigger.

**SSM Runbook (`remediation/ssm-runbook.yaml`)**:
SSM Automation document for manual/scheduled remediation.

**Step Functions workflow (`remediation/stepfunctions-workflow.json`)**:
detect → notify → remediate → verify → close finding.

---

### Resource × Proactive

Append resource-specific CFN Guard rules to `proactive/cfn-guard-rules.guard` with a
comment header separating them from account-level rules.

---

### Resource × Preventive

**Resource Policy (`preventive/resource-policy.json`)**:
- Use `awsknowledge` MCP for real ARN patterns and action names
- Include confused deputy protection (`aws:SourceArn`, `aws:SourceAccount` conditions)

**KMS Key Policy (`preventive/kms-key-policy.json`)**:
- Only if encryption controls exist in this cell
- Include `kms:ViaService` condition

**RCP (`preventive/rcp-policy.json`)**:
Only for controls where `rcp_expressible: true`. If false, write `_metadata.rcp_gap` and skip.

Authoring rules (strict):
- Always `"Effect": "Deny"` and `"Principal": "*"`
- `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}` to exempt AWS service calls
- `"StringNotEquals": {"aws:PrincipalOrgID": "${ORG_ID}"}` for org restriction
- Do NOT generate RCP for `kms:RetireGrant` or AWS-managed KMS keys

After generating, validate with Access Analyzer (if `--env` set):
```bash
aws accessanalyzer validate-policy \
  --policy-document file://.service-approval/controls/preventive/rcp-policy.json \
  --policy-type RESOURCE_CONTROL_POLICY \
  --query 'findings[?findingType==`ERROR` || findingType==`SECURITY_WARNING`]'
```

**Declarative Policy** (`preventive/declarative-policy.json`): only if `declarative_policy_expressible: true`.
**Backup Policy** (`preventive/backup-policy.json`): only if `backup_policy_applicable: true`.

---

### Resource × Detective

Append resource-specific rules to `detective/config-rules.json` with resource-level scope.

---

### Resource × Corrective

Extend `remediation/stepfunctions-workflow.json` with resource-level remediation steps.

---

## Compliant IaC templates

Generate using ALL controls (all matrix cells combined) as requirements.
Before generating any template, build a **parameter coverage matrix**:

### Step 5a: Parameter coverage matrix

For every control in `controls[]`, extract `parameters_controlled[]`. Build a matrix:

| Control ID | Scope | Category | Parameter | Template(s) |

Cross-check: every parameter in the matrix must appear as a variable/property in ALL 4
templates (CDK, TF, CFN, CDKTF). After generating each template, diff its parameters against
this matrix. Log `WARNING: <template> missing parameter <param> required by <control_id>`.
Fix all gaps before writing the file.

### Step 5b: Resource policy lifecycle

For every control with `parameters_controlled[]` referencing a `PutResourcePolicy` action:
- Generate a resource policy for EVERY such resource type, not just the primary one
- If `PutResourcePolicy` supports multiple resource types (e.g., runtime, gateway,
  runtime-endpoint), generate policies for all of them
- **Coverage verification** (MANDATORY): count distinct resource policy resources generated.
  Compare against the length of the `resource_types` array from PutResourcePolicy in
  `api_surface`. If counts don't match, identify and add missing resource types.
  For sub-resources, check if the CFN/TF resource type exists in `resources[]`. If yes,
  provision it AND its policy. If no, document as KNOWN GAP with placeholder ARN.

### Step 5c-arch: Modular Terraform architecture

Generate Terraform as **separate modules per resource type** — not a single monolithic file.
Derive the module list dynamically from `validated.json` `assets[]`. Each asset becomes one
module. This is service-agnostic: never hardcode resource names.

**Directory layout**:
```
iac/
├── main.tf                          # Root module — wires child modules
├── variables.tf                     # Root-level inputs (region, org_id, tags, etc.)
├── outputs.tf                       # Re-exports from child modules
├── modules/
│   ├── _shared/
│   │   └── variables.tf             # Common variable definitions
│   ├── <asset-1>/                   # e.g., agentruntime/
│   │   ├── main.tf                  # Primary resource + IAM role + KMS key + resource policy
│   │   ├── variables.tf             # Module inputs with validation blocks
│   │   └── outputs.tf               # ARNs, IDs for cross-module references
│   └── <asset-N>/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
```

**Module derivation** (service-agnostic):
1. Read `assets[]`. Each entry `name` + `cfn_type` = one module (kebab-case dir name).
2. Group controls by `resource_type` — controls for that cfn_type belong to that module.
3. Cross-cutting threats (no specific resource) → KNOWN GAP comment in every module.

Each module wraps: primary resource + IAM role + KMS key + resource policy + schema gap resources.

### Step 5c-rules: Terraform coding rules

- All variables must have `description` explaining the security control they implement
- All sensitive variables must have `sensitive = true`
- Optional parameters must have `default = ""` + use `count` on dependent resources
- Use `local` values for computed ARNs rather than repeating expressions
- Always include a `destroy` provisioner on `null_resource` blocks
- `null_resource` triggers must include the resource ID so changes force re-run
- `environment` block on `local-exec` provisioner for all dynamic values — never interpolate
  directly in command string (injection risk)
- Export all resource ARNs as outputs from each module
- Root module `outputs.tf` re-exports from child modules
- Generate the root module (`iac/main.tf`, `iac/variables.tf`, `iac/outputs.tf`)
  that wires all child modules and passes through common variables

### JWT authorizer completeness rule

For controls whose `parameters_controlled[]` includes JWT authorizer paths
(e.g., `$.authorizerConfiguration.customJWTAuthorizer.*`), generate ALL 4 JWT fields
as both variables/parameters AND as properties set on the resource's `authorizerConfiguration`:
1. `discoveryUrl` — OIDC discovery endpoint (must end with `.well-known/openid-configuration`)
2. `allowedAudience` — list of allowed JWT audience values
3. `allowedClients` — list of allowed OAuth client IDs
4. `allowedScopes` — list of allowed OAuth scopes

Do NOT just declare variables — MUST set them on `authorizerConfiguration.customJWTAuthorizer`.
If some fields are schema gaps, handle via post-apply CLI/AwsCustomResource with the FULL
authorizer configuration (all 4 fields), not just the gap field in isolation.

### Tag property completeness rule

For any control whose `parameters_controlled[]` includes tag paths or whose `description`
references tagging:
1. Set the `tags` property on the resource (not just declare a variable)
2. Add PII validation — reject tag keys/values matching: `@`, `ssn`, `creditcard`,
   `password`, `phone`, `address`, `dob`, `social.security`
3. Enforce required tags: Owner, Purpose, Environment, CostCenter
4. CDK: runtime `throw new Error(...)` checks in constructor
5. TF: `validation` block on the tags variable
6. CFN: deployment warning comment (AllowedPattern cannot validate maps)
7. CDKTF: note validation limitation in variable description

### Cross-parameter validation rule

When multiple parameters are related (e.g., JWT: discoveryUrl requires audience/clients/scopes):
- **TF**: `lifecycle { precondition }` on the resource block
- **CDK**: runtime `if` check + `throw new Error(...)` in constructor
- **CFN**: deployment warning comment
- **CDKTF**: `check` block

### VPC networkModeConfig rule

When setting `networkMode=VPC`, MUST also populate `networkModeConfig` with `subnets` and
`securityGroups` arrays from variables. Do NOT set networkMode alone — a VPC-mode resource
without subnets/SGs is non-functional. If the provider schema doesn't expose `networkModeConfig`,
create a schema gap resource that calls UpdateX with the full networkConfiguration including
networkModeConfig.

### CDK TypeScript (`iac/compliant-resource.cdk.ts`)

MANDATORY: Before generating any CDK code, call `awsknowledge` MCP to check if a native CFN
resource type exists for this service. If it does, prefer `CfnResource` over `AwsCustomResource`.

Use `aws-cdk-mcp-server` MCP to get the correct L2/L3 construct for each resource type.
Generate a CDK construct class with ALL control requirements as properties.

CDK-specific rules:
1. **Custom resource completeness**: if using `AwsCustomResource`, include BOTH `onCreate`
   AND `onUpdate` with identical parameters — `onCreate`-only resources cannot be updated
2. **`installLatestAwsSdk: false`** on every `AwsCustomResource` — never omit this
3. **PhysicalResourceId**: use `PhysicalResourceId.of(<unique-stable-id>)`, never
   `PhysicalResourceId.fromResponse(...)` for creation operations
4. **Optional properties**: CDK props need `?` optional marker; use conditional property
   spread for optional parameters
5. **IAM policy scoping**: `AwsCustomResource` policies must be scoped to specific resource
   ARN patterns — never `*`
6. Include comments referencing control IDs on every property

### Terraform modules (`iac/modules/<asset>/`)

MANDATORY: Before generating any Terraform code, call the `terraform` MCP `search_providers`
tool with `service_slug` set to the service name and `provider_document_type: "resources"`.
Then call `get_provider_details` for each matching resource type. This determines:
- Which parameters are natively supported (set directly on the resource)
- Valid enum values (may differ from the API)
- Attributes NOT on the TF schema needing post-apply CLI/SDK calls

Generate one module per asset per 5c-arch. Each module wraps the primary resource with
IAM role, KMS key, resource policy, and schema gap resources.

**TF schema gap handling** (MANDATORY for every gap):
For every parameter in the matrix (5a) missing from the TF provider schema:
1. Declare a `variable` in the module's `variables.tf`:
   ```hcl
   variable "stream_delivery_kinesis_arn" {
     description = "Kinesis stream ARN (CTRL-RES-DET-001). TF schema gap — applied via AWS CLI post-deploy."
     type        = string
     default     = ""
   }
   ```
2. Generate a `null_resource` with `local-exec` in the module's `main.tf`:
   ```hcl
   resource "null_resource" "stream_delivery" {
     count    = var.stream_delivery_kinesis_arn != "" ? 1 : 0
     triggers = { kinesis_arn = var.stream_delivery_kinesis_arn }
     provisioner "local-exec" {
       command     = "aws <service> update-<resource> --id \"$ID\" --stream-delivery ..."
       environment = { ID = aws_<service>_<resource>.this.id }
     }
     provisioner "local-exec" {
       when        = destroy
       command     = "aws <service> update-<resource> --id \"$ID\" --stream-delivery \"{\"kinesisDataFirehose\":null}\""
       environment = { ID = aws_<service>_<resource>.this.id }
     }
   }
   ```
Only use `null_resource` for the main resource when NO native provider resource exists.

### CloudFormation (`iac/compliant-resource.cfn.yaml`)

Use `awsiac` MCP for resource schema. If CFN resource type not yet registered, use
CloudFormation custom resource backed by Lambda SDK calls.

CFN-specific rules:
1. Optional parameters: use `Default: ""` + `Condition` to only set when non-empty
2. Cross-parameter validation: deployment warning comment (CFN lacks cross-parameter validation)
3. Tag validation: required tag warning in parameter Description

### CDK for Terraform (`iac/compliant-resource.cdktf.ts`)

Use `aws-documentation` MCP for CDKTF provider bindings (`@cdktf/provider-aws`).
Follow the same per-resource modular pattern as Terraform: one CDKTF construct class per
asset, each wrapping primary resource with IAM, KMS, resource policy, and schema gap resources.

CDKTF-specific rules:
1. Optional parameters: TerraformVariable needs a `default`
2. Cross-parameter validation: add a Terraform `check` block
3. Schema gaps: use `TerraformLocal` for computed values; use `TerraformResource` for gaps

### Dependent actions handling

For every dependent action referenced in `api_surface` (e.g., `iam:PassRole`):
- Document the requirement in the template as a comment on the relevant parameter
- Example: `"IAM role ARN. Caller must have iam:PassRole permission on this role."`
- Add a comment block noting which operations require which dependent actions
- For `iam:PassRole` specifically, add a concrete IAM policy example:
  ```
  # Deployer IAM policy must include:
  # { "Effect": "Allow", "Action": "iam:PassRole", "Resource": "<role-arn>",
  #   "Condition": { "StringEquals": { "iam:PassedToService": "<service>.amazonaws.com" } } }
  ```

### Control ID inline comments

For the main resource block in EVERY template, add inline comments with control IDs on
EVERY property that maps to a `parameters_controlled` entry in validated.json:
```hcl
resource "aws_<service>_<resource>" "this" {
  name               = var.resource_name            # CTRL-ACC-PRV-001, CTRL-ORG-PRV-002
  encryption_key_arn = local.effective_kms_arn      # CTRL-RES-PRV-001
  execution_role_arn = local.effective_role_arn     # CTRL-ACC-PRV-001, CTRL-RES-PRV-003
  tags               = var.tags                     # CTRL-ORG-PRO-001
}
```
Apply the same pattern to CDK properties, CFN resource Properties, and CDKTF attributes.

### Known threat gaps

For every threat in `threats[]` with `residual_risk != "ACCEPTED"` and `gaps != ""`:
add a `KNOWN GAP` comment block in ALL 4 templates:
```
# KNOWN GAP: <threat-id> — <title>
# MITRE: <tactic_id> — <technique_id>
# Risk: <risk_rating> | Residual risk: <residual_risk>
# Gap: <gaps>
# Recommended action: <suggested_mitigation>
```
Place in the module for the resource type the threat affects. Cross-cutting threats go
in every module/template.

### CCMv4 and MITRE header completeness

The CCMv4 list in EVERY file header — including per-module TF files (main.tf, variables.tf,
outputs.tf) — MUST be the FULL sorted union from ALL ccmv4_mappings[] entries.
Do NOT filter by resource type. Copy the identical list to every file.
Do NOT invent CCMv4 IDs not present in validated.json.

The MITRE list must include ALL technique IDs from threats[] linked to controls in this artifact.
For THREAT IDs: if all threats from threats[] are addressed, include all THREAT-NNN IDs
in the `CONTROLS` line of the header.

---

## Apply enrichment opportunities

For each `enrichment_opportunity` in `validated.json` with `verified: true`:
- Find the referenced control in the already-generated artifact(s)
- Add the specific enhancement (inject `aws:SourceArn` condition, add `kms:ViaService`, etc.)
- Re-annotate the artifact header with the enrichment reference

For enrichments that reference IAM condition keys, generate a **concrete IAM policy example**
inline near the property the enrichment targets:
```
# ENRICHMENT: <control_id> — <condition_key>
# Use in SCP to enforce approved values:
# { "Effect": "Deny", "Action": ["<service>:CreateX"], "Resource": "*",
#   "Condition": { "ForAnyValue:StringNotEquals": {
#     "<condition_key>": ["approved-value-1", "approved-value-2"] } } }
```

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

# Validate Terraform module structure
TF_IAC=".service-approval/controls/iac"
for f in main.tf variables.tf outputs.tf; do
  [ -f "$TF_IAC/$f" ] && echo "OK: $TF_IAC/$f" || echo "MISSING: $TF_IAC/$f"
done
for mod in "$TF_IAC"/modules/*/; do
  [ -d "$mod" ] || continue
  mod_name=$(basename "$mod")
  [ "$mod_name" = "_shared" ] && continue
  for f in main.tf variables.tf outputs.tf; do
    [ -f "$mod/$f" ] && echo "OK: $mod/$f" || echo "MISSING: $mod/$f"
  done
done
if command -v terraform &>/dev/null; then
  (cd "$TF_IAC" && terraform fmt -check -recursive && echo "OK: terraform fmt" || echo "WARN: terraform fmt issues")
  (cd "$TF_IAC" && terraform validate 2>&1 && echo "OK: terraform validate" || echo "WARN: terraform validate issues")
fi
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
  IaC:          CDK (TypeScript), CloudFormation, CDK for Terraform
  Terraform:    <N> modules (<list asset names>) + root module
  Controls skipped (unverified): N
  Output: .service-approval/controls/
```
