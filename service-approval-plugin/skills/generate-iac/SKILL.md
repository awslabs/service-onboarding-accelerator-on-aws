---
name: generate-iac
description: >
  Generate compliant IaC templates in all 4 formats — modular Terraform, CDK TypeScript,
  CloudFormation YAML, and CDK for Terraform. Uses parameter coverage matrix from
  mapping-results.json and API surface from validated.json.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Generator: IaC Templates

Generate compliant infrastructure-as-code templates in all 4 required formats from the
Controls Matrix. Each template implements ALL controls as properties/variables on the
compliant resource.

**Output:** `.service-approval/controls/iac/`

This is one of 3 focused generate sub-skills. Each writes to separate directories.

---

## Prerequisites

```bash
test -f .service-approval/state/mapping-results.json && echo "mapping-results: OK" || echo "ERROR"
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR"
```

Create directory structure:
```bash
mkdir -p .service-approval/controls/iac/modules/_shared
for asset in $(python3 -c "import json; d=json.load(open('.service-approval/state/validated.json')); [print(a['name'].lower().replace(' ','-')) for a in d['assets']]"); do
  mkdir -p ".service-approval/controls/iac/modules/${asset}"
done
```

Load controls and API surface:
```bash
python3 -c "
import json
mr = json.load(open('.service-approval/state/mapping-results.json'))
vj = json.load(open('.service-approval/state/validated.json'))
print(f'Controls: {len(mr[\"controls\"])}')
print(f'Assets: {len(vj[\"assets\"])}')
print(f'API operations: {len(vj[\"api_surface\"][\"operations\"])}')
fw = mr['framework']
if isinstance(fw, dict): print(f'Framework: {fw[\"name\"]}')
"
```

## Artifact Header Template

Every generated file MUST include:
```
# SCOPE: resource
# LAYER: proactive
# CONTROLS: <all control IDs>
# FRAMEWORK: <framework-name> — <FULL sorted union of ALL MAPPED objective IDs>
# MITIGATIONS: <all mitigation IDs>
# GENERATED: service-approval v3.0.0
# SERVICE: <service-name>
```

The `FRAMEWORK` list MUST be the FULL sorted union from ALL `framework_mapping[]` entries
where `status == "MAPPED"` — the identical list in EVERY file, including per-module TF files.

---

## Step 1: Parameter Coverage Matrix

For every control in `controls[]`, extract `parameters_controlled[]`. Build a matrix:

| Control ID | Scope | Category | Parameter | Template(s) |

Cross-check: every parameter must appear as a variable/property in ALL 4 templates.
After generating each template, diff its parameters against this matrix.

---

## Step 2: Resource Policy Lifecycle

For every control with `parameters_controlled[]` referencing `PutResourcePolicy`:
- Generate resource policies for EVERY applicable resource type
- Count distinct resource policy resources generated vs `resource_types` from PutResourcePolicy
- Document any gaps as KNOWN GAP

---

## IMPORTANT: Generation Order for Context Efficiency

All 4 formats are REQUIRED. To avoid running out of context before completing all formats,
generate in this order:

1. **CDK TypeScript** (Step 4) — single file, compact
2. **CloudFormation YAML** (Step 5) — single file, compact
3. **CDK for Terraform** (Step 6) — single file, compact
4. **Modular Terraform** (Step 3) — multi-file, largest

This ensures the 3 single-file formats are written first. If context pressure is high,
the Terraform modules can be generated with less verbose comments while still including
all required parameters and control ID annotations.

---

## Cross-Format Quality Rules (apply to ALL 4 formats)

These rules MUST be enforced in every template format — not just one:

1. **JWT Authorizer Completeness**: Generate ALL 4 fields on JWT authorizer configuration:
   `discoveryUrl`, `allowedAudience`, `allowedClients`, `allowedScopes`. Every format must
   include all 4 (conditionally if some are optional). Missing `allowedScopes` is a common
   omission in CloudFormation and CDKTF — check every format before finalizing.

2. **VPC Endpoint Condition on Network-Scoped IAM Policies**: When a resource has VPCE-based
   network controls, the IAM execution role policy SHOULD include `aws:SourceVpce` condition
   when a VPC endpoint ID is provided. This applies to Terraform modules and CDK constructs.

3. **Control ID annotations**: Every resource property that implements a control MUST have
   an inline comment with the control ID (e.g., `# CTRL-ACC-PRV-001`).

4. **No unused variables/parameters**: Every variable declared in a TF `variables.tf` or CFN
   `Parameters` section MUST be referenced by at least one resource. After generating, scan
   for any variable not referenced in `main.tf` or any resource block — remove it. Common
   cause: a variable was planned for a resource that ended up using a different parameter name.

5. **Cross-format parameter parity**: After generating all 4 formats, verify that the same set
   of user-configurable parameters appears in each. If TF has `var.jwt_allowed_scopes` but CFN
   is missing a `JwtAllowedScopes` parameter, add it. The parameter coverage matrix from Step 1
   is the source of truth — every format must cover every parameter.

---

## Step 3: Modular Terraform (`iac/modules/`)

### Architecture

One module per asset from `validated.json` `assets[]`:
```
iac/
├── main.tf           # Root module — wires child modules
├── variables.tf      # Root-level inputs
├── outputs.tf        # Re-exports from child modules
└── modules/
    ├── _shared/
    │   └── variables.tf
    ├── <asset-1>/
    │   ├── main.tf
    │   ├── variables.tf
    │   └── outputs.tf
    └── <asset-N>/
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

### Module Derivation
1. Each `assets[]` entry → one module (kebab-case dir name)
2. Group controls by `resource_type` → controls for that CFN type go in that module
3. Cross-cutting controls → comment in every module

### Per-Module Contents
Each module wraps: primary resource + IAM role + KMS key + resource policy + schema gap resources.
Only pass arguments that the child module actually declares as variables. If a capability
(e.g., VPC endpoint, resource policy) is not applicable to a resource type, do NOT add
the argument to the root module block — even if other modules accept it.

### Terraform Provider Schema Check
**MANDATORY:** Before generating, call the `terraform` MCP `search_providers` tool with
the service name, then `get_provider_details` for each resource type. This determines:
- Which parameters are natively supported
- Valid enum values
- Attributes NOT on the TF schema (schema gaps)

### Schema Gap Handling
For every parameter missing from the TF provider schema:
1. Declare a `variable` in `variables.tf` with description noting the gap
2. Generate a `null_resource` with `local-exec` in `main.tf`:
   - Apply provisioner: `aws <service> update-<resource>` with the parameter
   - Destroy provisioner: reset the parameter (use `self.triggers.*` for ARN values)

### Coding Rules
- **Root ↔ module name consistency**: When the root `main.tf` passes arguments to a child module,
  the argument name MUST exactly match a `variable` name declared in that child module's
  `variables.tf`. After generating each module, re-read its `variables.tf` and verify every
  argument in the root `module {}` block uses the exact same name. Common mismatches:
  pluralization (`audiences` vs `audience`), abbreviations (`vpce_id` vs `vpc_endpoint_id`),
  and renames (`resource_policy_principals` vs `trusted_principal_arns`).
- All variables: `description` explaining the security control
- Sensitive variables: `sensitive = true`
- Optional parameters: `default = ""` + `count` on dependent resources
- `local` values for computed ARNs
- Destroy provisioners: access `self.triggers.*` NOT `var.*`, NOT `data.*`, NOT `local.*`.
  Store ALL values needed at destroy time in `triggers {}` — including `region` and `account_id`.
  At destroy time, `var`, `data`, and `local` references may not be available. Only
  `self.triggers.*` is guaranteed to resolve. Example:
  ```hcl
  triggers = {
    resource_arn = aws_resource.this.arn
    region       = data.aws_region.current.id
    account_id   = data.aws_caller_identity.current.account_id
  }
  provisioner "local-exec" {
    when    = destroy
    command = "aws <cmd> --region ${self.triggers.region}"
  }
  ```
- **Region data source**: Use `data.aws_region.current.id` NOT `data.aws_region.current.name`.
  The `name` attribute was deprecated in AWS provider v6.39.0 and replaced by `id`. Using
  `name` triggers deprecation warnings and will break in future provider versions. Apply this
  everywhere: triggers, locals, interpolations, and output values.
- `null_resource` triggers: include resource ID
- `environment` block on `local-exec`: all dynamic values (injection prevention)
- Export all resource ARNs as outputs
- Root module re-exports ALL child module outputs — every output defined in any child
  module's `outputs.tf` MUST have a corresponding re-export in the root `outputs.tf`.
  This includes ARNs, IDs, names, AND aliases (e.g., KMS key aliases). Missing re-exports
  break the module contract for consumers.

### Control ID Inline Comments
```hcl
resource "aws_<service>_<resource>" "this" {
  encryption_key_arn = local.effective_kms_arn      # CTRL-RES-PRV-001
  execution_role_arn = local.effective_role_arn     # CTRL-ACC-PRV-001
  tags               = var.tags                     # CTRL-ORG-PRO-001
}
```

---

## Step 4: CDK TypeScript (`iac/compliant-resource.cdk.ts`)

**MANDATORY:** Call `awsknowledge` MCP to check for native CFN resource type. If it exists,
prefer `CfnResource` over `AwsCustomResource`.

Use `aws-cdk-mcp-server` MCP for L2/L3 constructs.

### CDK Rules
1. `AwsCustomResource`: include BOTH `onCreate` AND `onUpdate`
2. `installLatestAwsSdk: false` on every `AwsCustomResource`
3. `PhysicalResourceId.of(<unique-stable-id>)` — never `fromResponse(...)` for creation
4. Optional props: `?` marker + conditional spread
5. IAM policy scoping: specific ARN patterns, never `*`
6. One construct class per asset

### Tag PII Validation
Runtime `throw new Error(...)` checks in constructor for PII patterns.

### JWT Authorizer Completeness
Generate ALL 4 fields: `discoveryUrl`, `allowedAudience`, `allowedClients`, `allowedScopes`.
Set on `authorizerConfiguration.customJWTAuthorizer`.

### VPC networkModeConfig
When `networkMode=VPC`, MUST populate `networkModeConfig` with `subnets` and `securityGroups`.

---

## Step 5: CloudFormation YAML (`iac/compliant-resource.cfn.yaml`)

Use `awsiac` MCP for resource schema. If CFN type not registered, use custom resource.

### CFN Rules
1. **Optional parameters MUST have BOTH `Default: ""` AND a `Condition`**:
   - **CRITICAL — Parameter type for Fn::Equals**: ALL parameters referenced in `Fn::Equals`
     conditions MUST be `Type: String`, NOT `Type: CommaDelimitedList`. `Fn::Equals` requires
     two string operands — a `CommaDelimitedList` resolves to a list, causing a CloudFormation
     validation error: "every Fn::Equals object requires a list of 2 string parameters." If
     you need list behavior, accept a comma-separated `String` and use `Fn::Split` where needed.
   - **CRITICAL — Resource-level Condition must be a string**: The `Condition:` key on a CFN
     resource accepts only a plain string (the name of a condition defined in the Conditions
     section). Do NOT use intrinsic functions like `!Not [ConditionName]` — this causes
     "Every Condition member must be a string" errors. Instead, define inverse conditions
     in the Conditions section (e.g., `NeedsKmsKey: !Equals [!Ref KmsKeyArn, ""]`) and
     reference them by name on resources.
   - Define a `Condition` for each optional parameter: `HasXyz: !Not [!Equals [!Ref Xyz, ""]]`
   - Every resource property that uses the optional parameter MUST be wrapped in `!If [HasXyz, !Ref Xyz, !Ref "AWS::NoValue"]`
   - Parameters without Default+Condition will cause stack failures when empty strings are passed to APIs
   - **Common omission**: JWT fields, VPC fields, Permission Boundary ARN — check ALL optional parameters
2. Cross-parameter validation: deployment warning comment
3. Tag validation: required tag warning in Description
4. Dependent actions: document in parameter Description
5. **Custom Resource Lambda for non-registered CFN types**: When a CFN resource type is NOT
   registered in the CloudFormation registry (checked via `awsiac` MCP), implement it as a
   `AWS::CloudFormation::CustomResource` backed by a `AWS::Lambda::Function`:
   - The Lambda handler MUST implement Create, Update, and Delete actions via SDK calls
   - Include the Lambda code inline (ZipFile) or reference an S3 key
   - The custom resource MUST send SUCCESS/FAILED to the pre-signed URL
   - Do NOT leave TODO/stub comments like "implement Lambda handler" — write the actual handler
   - The Lambda execution role needs IAM permissions for the specific API calls, including
     `TagResource` and `UntagResource` — most AWS Create* APIs that accept tags also require
     separate tag permissions. Always include these in the custom resource role policy.
   - **CRITICAL — 4096-byte response limit**: CloudFormation custom resource responses are
     limited to 4096 bytes total. The `send_response` helper MUST:
     (1) Truncate `Reason` to 1000 chars max
     (2) Limit `Data` values to 200 chars each
     (3) If total response > 4000 bytes, strip `Data` to `{}` to stay under limit
     (4) Include `print()` logging of response size for CloudWatch debug visibility
     Exceeding 4096 bytes causes "Response object is too long" and stack CREATE_FAILED.
   - **CRITICAL — boto3/CLI service name**: The boto3 client name and AWS CLI command name
     for the target service MUST match the official SDK service identifier. Before generating,
     verify with `aws <service-name> help` or check `botocore.loaders.Loader().list_available_services()`.
     Common error: inserting extra hyphens or using inconsistent suffixes across files.
     The SAME correct name must be used in ALL generated files:
     CFN custom resource handler, Terraform `local-exec` provisioners, CDKTF provisioners,
     CDK `AwsCustomResource` SDK calls, SSM runbook steps, and Lambda remediators.
   - **Lambda Layer for new services**: When the target service's boto3 model is not yet
     bundled in the Lambda Python runtime, the CFN template MUST include a `Boto3LayerArn`
     parameter and attach it as a Layer to the custom resource Lambda. Make this conditional
     (`HasBoto3Layer` condition) so the template works with or without the layer.
   - **CRITICAL — SDK model validation for custom resources**: Before generating the custom
     resource Lambda handler, read the SDK model (via `awsknowledge` or `terraform` MCP) to
     verify for EACH API call:
     (a) **Request shape nesting** — the exact structure of each parameter (e.g.,
         `agentRuntimeArtifact.containerConfiguration.containerUri`, NOT `agentRuntimeArtifact.containerUri`)
     (b) **Enum values** — valid enum strings for each field (e.g., `AWS_IAM` not `IAM_AUTH`,
         `CUSTOM_JWT` not `CUSTOM_JWT_AUTHORIZER`). Use create-time enum names for IaC templates.
     (c) **Name constraints** — regex patterns for names, IDs, and ARNs. Add `AllowedPattern`
         on CFN parameters to fail fast at deploy time, not at API call time.
     (d) **Parameter types** — whether a URI is S3, ECR, HTTPS, etc. Match the description.
     (e) **Dependent actions** — the custom resource Lambda role MUST include ALL actions needed
         by Create/Update/Delete calls, including: `TagResource`, `UntagResource`, sub-resource
         operations triggered by parent creation (e.g., a Create call may implicitly create
         dependent sub-resources that require separate IAM permissions), and KMS permissions (`kms:GenerateDataKey`,
         `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`, `kms:CreateGrant`) on any KMS keys
         passed to the resource. Missing permissions produce `AccessDeniedException` at deploy
         time — the #1 cause of custom resource deployment failures.
6. **Terraform `local-exec` and CDKTF provisioner CLI validation**: When using `null_resource`
   provisioners with `aws` CLI commands (schema-gap pattern), the CLI parameter surface differs
   from the SDK. Before generating, run `aws <service> <command> help` via MCP to verify:
   (a) **Every CLI flag exists** — some SDK parameters (e.g., `tags`) are NOT accepted as CLI
       flags. If `--tags` is rejected, use a separate `aws <service> tag-resource` call after
       creation. Never assume SDK parameters map 1:1 to CLI flags.
   (b) **Required parameters** — the CLI marks required params with `(required)` in help text.
       Include ALL required params in the provisioner command. Some parameters are conditionally
       required (e.g., a configuration object required alongside a type selector).
   (c) **JSON array construction** — when passing lists (subnets, security groups) into JSON
       structures via shell, use `jq` or proper bash array-to-JSON conversion. Do NOT embed
       comma-delimited strings directly into JSON arrays — `"subnets":"sub-1,sub-2"` is wrong,
       `"subnets":["sub-1","sub-2"]` is correct. Use:
       ```hcl
       IFS=',' read -ra ITEMS <<< "$SUBNET_IDS"
       SUBNET_JSON=$(printf '"%s",' "${ITEMS[@]}" | sed 's/,$//')
       ```
       Or use `jq -c --arg` for safe construction.
   (d) **Post-creation tagging** — if the Create API doesn't support inline tags, add a second
       provisioner step: `aws <service> tag-resource --resource-arn "$ARN" --tags "$TAGS"`.
       Check tag-resource exists for the service. If it doesn't, document the tagging gap.
   (e) **Prefer `--cli-input-json` over positional flags** — for complex parameters (tagged
       unions, nested JSON), use `--cli-input-json` with Terraform's `jsonencode()` in the
       environment block. This avoids shell quoting issues with JSON in heredocs.
   (f) **Verify CLI sub-command existence** — some SDK operations (`PutResourcePolicy`,
       `TagResource`, `UntagResource`) may not have CLI equivalents. Check the service's
       valid choices list. If a needed operation is missing, document it as a gap comment.
   (g) **IAM propagation delay** — when a provisioner creates an IAM role then immediately
       passes it to a service API, add a `time_sleep` resource (15s) between role creation
       and the provisioner. Service APIs validate role trust policies synchronously and fail
       if the role hasn't propagated. Add `hashicorp/time` provider to the module.
   (h) **Identity-based KMS permissions** — KMS key policies (resource-based) grant the service
       principal, but the service role also needs identity-based permissions for `kms:GenerateDataKey`,
       `kms:Decrypt`, `kms:DescribeKey`. Add an `aws_iam_role_policy` for KMS access.
   (i) **ECR permissions for container runtimes** — if the service runs container workloads,
       execution roles need `ecr:GetAuthorizationToken` (on `*`), `ecr:BatchGetImage`, and
       `ecr:GetDownloadUrlForLayer` (on the repository ARN). The service validates ECR access
       at create time. Only add these if `validated.json` indicates container-based execution.
   (j) **Enum values from CLI help** — the CLI help shows valid enum values for each parameter.
       Use ONLY values listed there — SDK documentation may show different or additional values.
       If only one value exists, hardcode it and document.

   (k) **CFN custom resource Lambda handlers — parameter validation**: When generating CloudFormation
       custom resource Lambda handlers that call service APIs (via boto3), only pass parameters the
       API actually accepts. Common error: passing `tags` to `create_*()` when the service doesn't
       accept tags on creation (tag-resource may be a separate API, or may not exist at all). Before
       generating the handler, cross-reference the API parameters from `validated.json`
       `api_surface.operations[]` and only include accepted parameters. If tagging is a separate API
       call, make it a separate step after creation. If tag-resource doesn't exist, document the gap.

   (l) **Cross-format enum consistency**: When the CLI only accepts specific valid enum values
       for a parameter, ALL 4 IaC formats must enforce the same set: TF variable with `validation`,
       CDK with runtime check, CDKTF variable with default, CFN with `AllowedValues`. Verify the
       valid set via `aws <service> <command> help` and use it consistently — do not default to
       values the API does not accept.

   (m) **CFN custom resource delete handler resilience**: Delete handlers in CloudFormation custom
       resource Lambdas MUST catch ALL exceptions and return SUCCESS. When a Create fails,
       CloudFormation calls Delete during rollback — but the resource was never created, so the
       delete call gets `ResourceNotFoundException` or `AccessDeniedException`. Catch both
       specifically, plus a broad `except Exception: pass` fallback. A delete handler that only
       catches `ResourceNotFoundException` will cause `ROLLBACK_FAILED` when permissions errors
       occur on never-created resources, requiring manual stack cleanup.

   (n) **API response key validation**: Different service APIs return response fields at different
       nesting levels. Before generating custom resource handlers, check the API response structure
       via `aws <service> <command> help` OUTPUT section. Common patterns:
       - Some APIs wrap the response in a named object (e.g., `{"resource": {"id": "...", "arn": "..."}}`)
       - Others return fields at the top level (e.g., `{"resourceId": "...", "resourceArn": "..."}`)
       Assuming one pattern when the API uses the other causes a KeyError. Use defensive access:
       `resp.get('<resource_key>', resp).get('id', '')` to handle both patterns.

   (o) **API field validation via `--generate-cli-skeleton`**: Before generating any API call params
       (in Lambda handlers, provisioners, or CLI commands), verify the exact accepted fields using
       `aws <service> <command> --generate-cli-skeleton` or boto3 docs. Common errors:
       - Configuration objects may accept fewer fields than documentation suggests — verify the
         exact set of accepted sub-fields via the skeleton output.
       - Nested configuration objects (e.g., `networkConfiguration`) may only accept a mode selector
         at the top level, with no sub-object for detailed config in the current API version.
       - Some Create APIs do not accept `tags` inline — tagging requires a separate
         `tag-resource` call after creation. Check the skeleton for each Create operation.

---

## Step 6: CDK for Terraform (`iac/compliant-resource.cdktf.ts`)

Use `aws-documentation` MCP for CDKTF provider bindings.

### CDKTF Rules
1. Optional parameters: TerraformVariable with `default`
2. Cross-parameter validation: Terraform `check` block
3. Schema gaps: `TerraformLocal` for computed values
4. One construct class per asset (matching TF module structure)
5. **Never evaluate Terraform tokens at synth time**: `TerraformVariable.value` returns a
   token string (e.g., `${var.foo}`), NOT the runtime value. TypeScript conditionals like
   `if (myVar.value)` always evaluate to `true` because the token string is truthy. Use
   Terraform-native conditionals instead:
   ```typescript
   // WRONG — always true at synth time:
   if (vpcEndpointId.value) { ... }
   // CORRECT — use conditional expression or count:
   new TerraformLocal(this, 'effective_vpce', Token.asString(
     Fn.conditional(Fn.lengthOf(vpcEndpointId.value) > 0, vpcEndpointId.value, '')
   ));
   ```
   Alternatively, use `Fn.conditionIf` or resource `count` with `Fn.lengthOf` to gate
   resources on optional variables. This applies to ALL optional TerraformVariables.
5. **NullResource provisioners**: When using `NullResource` for schema gaps, include the actual
   `local-exec` provisioner with the AWS CLI command — not just triggers. The CDKTF `NullResource`
   supports `addOverride('provisioner', [...])` for provisioner configuration. A `NullResource`
   with only triggers and no provisioners is a no-op.
   ```typescript
   const schemaGap = new NullResource(this, 'schema-gap', { triggers: { ... } });
   schemaGap.addOverride('provisioner', [{
     'local-exec': { command: 'aws <service> update-<resource> ...' }
   }]);
   ```

---

## Step 7: Known Coverage Gaps

For every entry in `mapping-results.json` `coverage_gaps[]`:
Add a `KNOWN GAP` comment block in ALL 4 templates:
```
# KNOWN GAP: <type> — <id>
# Description: <description>
# Recommendation: <recommendation>
```

---

## Step 8: Cross-Parameter Validation

When multiple parameters are related:
- **TF**: `lifecycle { precondition }` on the resource block
- **CDK**: runtime `if` check + `throw new Error(...)` in constructor
- **CFN**: deployment warning comment
- **CDKTF**: `check` block

---

## Validate Generated Artifacts

IaC validation runs automatically via Stop hook (validate_cross.py Checks X6, X7). Run `terraform validate` manually if terraform CLI is available.

## Print Summary

```
Generate (IaC) complete:
  Terraform modules:  {N} modules + root module
  CDK TypeScript:     compliant-resource.cdk.ts ({N} construct classes)
  CloudFormation:     compliant-resource.cfn.yaml
  CDK for Terraform:  compliant-resource.cdktf.ts
  Parameter coverage: {N}/{N} parameters across all templates
  Known gaps:         {N} documented
  Output: .service-approval/controls/iac/
```
