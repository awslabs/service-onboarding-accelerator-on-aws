---
name: generate-preventive
description: >
  Generate preventive and proactive security control artifacts — SCPs, resource policies,
  KMS key policies, permission boundaries, tag policies, OPA policies, and CloudFormation
  Guard rules. Reads from mapping-results.json and validated.json.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Generator: Preventive & Proactive Controls

Generate all preventive and proactive security control artifacts from the Controls Matrix.
This covers Organisation×Proactive, Organisation×Preventive, Account×Proactive,
Account×Preventive, Resource×Proactive, and Resource×Preventive cells.

**Output:** `.service-approval/controls/preventive/` and `.service-approval/controls/proactive/`

This is one of 3 focused generate sub-skills. Each writes to separate directories.

---

## Prerequisites

```bash
test -f .service-approval/state/mapping-results.json && echo "mapping-results: OK" || echo "ERROR"
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR"
mkdir -p .service-approval/controls/{preventive,proactive/opa-policies}
```

Load controls from `mapping-results.json` and API surface from `validated.json`:
```bash
python3 -c "
import json
mr = json.load(open('.service-approval/state/mapping-results.json'))
vj = json.load(open('.service-approval/state/validated.json'))
prv = [c for c in mr['controls'] if c['category'] == 'PRV']
pro = [c for c in mr['controls'] if c['category'] == 'PRO']
print(f'Preventive controls: {len(prv)}')
print(f'Proactive controls: {len(pro)}')
print(f'API operations: {len(vj[\"api_surface\"][\"operations\"])}')
"
```

Unless `--include-unverified` is set, skip controls where `verified: false`.

## Artifact Header Template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|resource>
# LAYER: <proactive|preventive>
# CONTROLS: <comma-separated control IDs>
# FRAMEWORK: <framework-name> — <FULL sorted union of ALL MAPPED objective IDs>
# MITIGATIONS: <comma-separated mitigation IDs>
# GENERATED: service-approval v3.0.0
# SERVICE: <service-name>
```
For JSON files, add as a `"_metadata"` key. For HCL/TypeScript, use comment blocks.

The `FRAMEWORK` list MUST be the FULL sorted union from ALL `framework_mapping[]` entries
where `status == "MAPPED"` — the identical list in every file header.

---

## Organisation × Proactive

### Tag Policy (`preventive/tag-policy.json`)
- Enforce: Owner, Environment, Purpose, CostCenter + service-specific tags from controls
- Use `awsknowledge` MCP to confirm valid tag key formats

### OPA Org Policy (`proactive/opa-policies/org-policy.rego`)
- OPA `.rego` rules for org-wide provisioning rules not expressible as tag policies

### SCP Provisioning Deny (`preventive/scp-provisioning.json`)
- Only for controls where `scp_expressible: true` with provisioning-time intent
- Follow SCP authoring rules from Organisation × Preventive below

---

## Organisation × Preventive

### SCP Runtime Deny (`preventive/scp-policy.json`)

Only generate if `validated.json` `capabilities.organization_policies.scp_expressible: true`.
If false, write `_metadata.scp_gap` note and skip.

**SCP authoring rules (strict):**
- Always `"Effect": "Deny"` — never Allow-only
- Always include relevant condition key(s) — never bare action deny without conditions
- Use real condition keys from `awsknowledge` MCP — confirm each key is valid for the action
- **No custom placeholders in policy documents**: SCPs are IAM policies. Custom placeholders
  like `${trusted:account-id}` or `${ORGANIZATION_ID}` cause `MalformedPolicyDocument` errors.
  IAM policy variables like `${aws:PrincipalAccount}` work in real SCPs evaluated by Organizations
  but fail when the policy is tested as a standalone IAM managed policy (which the smoke test does).
  Use literal placeholder values like `123456789012` with a `_metadata._deployment_notes` field
  explaining what values to substitute at deployment time.
- **MANDATORY — Include ALL applicable actions per condition key**: When a condition key
  applies to multiple actions (e.g., both `Create*` and `Update*`), the SCP statement MUST
  include ALL actions from the condition key's `applies_to_actions[]` in validated.json.
  Only covering Create* leaves Update* unprotected — an attacker could modify existing
  resources to remove security controls. Read `capabilities.iam.condition_keys[].applies_to_actions`
  for every condition key used and include the full action set.
- **Tag enforcement MUST cover UntagResource**: SCPs that enforce mandatory tags on Create*
  operations MUST also deny `UntagResource` for those tag keys using `aws:TagKeys` condition.
  Without this, mandatory tags can be removed after resource creation. Add a separate Deny
  statement: `"Action": "<prefix>:UntagResource"` with
  `"Condition": {"ForAnyValue:StringEquals": {"aws:TagKeys": ["Owner", "Purpose"]}}`.
- Use `"NotAction"` only for region-restriction controls
- Use `"Principal": "*"` only in resource-based policies, NOT in SCPs
- Track cumulative character count; split at 5120 chars
- **MANDATORY BreakGlass exclusion**: `"ArnNotLike": {"aws:PrincipalARN": ["arn:*:iam::*:role/BreakGlassRole"]}`
  in EVERY Deny statement. Only exception: `DenyProhibitedTagKeys` (PII patterns).
- **AND-logic awareness**: Conditions in one block use AND. If exceptions should be
  independent (OR), use SEPARATE statements.

**No non-standard fields in Statements**: IAM policy Statements only accept standard
keys (`Sid`, `Effect`, `Principal`, `NotPrincipal`, `Action`, `NotAction`, `Resource`,
`NotResource`, `Condition`). Do NOT add `_description`, `_comment`, `_control_ids`, or
any other underscore-prefixed metadata inside Statement objects — IAM Access Analyzer
and the SCP API will reject them. Put per-statement documentation in the `Sid` field
(e.g., `"Sid": "DenyUnencryptedCreation"`) or as `_metadata` at the top level only.

Format:
```json
{ "_metadata": { ... }, "Version": "2012-10-17", "Statement": [ ... ] }
```

SCP validation (JSON syntax and 5120-char size limit) runs automatically via PostToolUse hook (validate_controls.py Checks 7, 12).

**SCP simulation metadata (REQUIRED for every SCP):** Each SCP JSON MUST include a
`_simulation_tests` field in the `_metadata` object. This tells the smoke-deploy-controls
script what actions to simulate as denied and what actions should remain allowed.

```json
{
  "_metadata": {
    "framework": "...",
    "controls": ["CTRL-..."],
    "_simulation_tests": {
      "should_deny": [
        {"action": "lambda:CreateFunction", "context": {"lambda:CodeSigningConfigArn": ""}}
      ],
      "should_allow": [
        {"action": "lambda:CreateFunction", "context": {"lambda:CodeSigningConfigArn": "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csc-abc"}}
      ]
    }
  },
  "Version": "2012-10-17",
  "Statement": [...]
}
```

The `should_deny` list includes actions + context values that the SCP should block.
The `should_allow` list includes actions + context values that should pass.
The smoke test creates a test role, attaches the SCP as an IAM policy, and uses
`simulate_principal_policy` to verify the deny/allow behavior matches.

### AI Opt-out Policy (`preventive/ai-optout-policy.json`)
Only if `ai_optout_applicable: true`.

---

## Account × Proactive

### CloudFormation Guard Rules (`proactive/cfn-guard-rules.guard`)

**Cross-validation constraint**: Every Guard rule MUST pass when evaluated against the
compliant CloudFormation template generated by generate-iac. The smoke test runs:
```
cfn-guard validate --rules proactive/CTRL-*.guard --data iac/cloudformation/*.cfn.yaml
```
If a guard rule flags a violation in the compliant template, either the guard rule
uses an incorrect property path or the CFN template is missing a required property.
Both must be fixed together — trace to the source of the discrepancy.

- Use `awsiac` MCP for valid cfn-guard syntax per resource type
- **Every rule MUST have a control ID**: rule name includes control ID.
  Example: `rule enforce_encryption_ctrl_acc_pro_001 { ... }`
  Do NOT generate "bonus" rules that are not mapped to any CTRL-* control. If a check is
  needed but has no control, either assign it to an existing control or omit it. Unmapped
  rules create audit confusion — every rule must trace back to the controls catalog.
- **Valid Guard 2.x syntax only**: Do NOT use `%size()` function — it is not standard CFN Guard
  2.x syntax. For collection size checks, use `some` clauses, `[N] EXISTS` checks, or iterate
  with `when` blocks. Example: check subnet count ≥ 2 with `Properties.Subnets[1] EXISTS`.
- **Authorizer field completeness**: When validating authorizer controls, guard rules MUST
  check ALL accepted configuration fields. Verify the exact set of accepted fields via
  `aws <service> <command> --generate-cli-skeleton` — do NOT assume fields exist based on
  documentation alone. Only generate rules for fields the API actually accepts.
- **Enum value accuracy (CRITICAL — #1 recurring failure)**: Guard rules, OPA policies, and
  Checkov custom policies MUST use the EXACT enum values from `validated.json`. Before
  generating ANY enum comparison, perform this mandatory lookup:
  1. Find the parameter in `validated.json` `api_surface.operations[].parameters[]`
  2. Read the `feasibility_note` for the relevant mitigation — it often lists valid enum values
  3. Read the `enrichment_opportunities[]` and `condition_keys[]` for enforcement guidance
  4. Use ONLY the values found — do NOT invent camelCase or SCREAMING_SNAKE_CASE transforms
  Example: if validated.json says `authorizerType (IAM_AUTH, CUSTOM_JWT_AUTHORIZER)`, use
  exactly `IAM_AUTH` and `CUSTOM_JWT_AUTHORIZER` — do NOT substitute `IAM`, `CustomJWT`,
  or any other variant. Incorrect enum values in `when` clauses cause Guard rules to be
  silently skipped. In OPA `deny` rules, they cause false negatives. In Checkov, they cause
  the check to never trigger. ALL THREE proactive layers become ineffective.

### CloudFormation Hooks Policy (`proactive/cfn-hooks-policy.json`)
- Use `awsiac` MCP to confirm resource type supports CFN Hooks
- **Header completeness**: The `CONTROLS` header MUST list ALL proactive controls, not just a
  subset. The hook executes the Guard file which implements all proactive controls, so the hook
  header must claim all of them.

### Checkov Config (`proactive/checkov-config.yaml`)
- Check IDs mapping to controls in this cell
- **Custom policy directory**: If any custom check IDs are referenced (e.g., `CKV_AWS_<SERVICE>_*`),
  the `custom-policies-dir` MUST point to a directory that exists and contains the actual policy
  definitions. Create `proactive/custom-policies/` and write a `.py` or `.yaml` policy file for
  each custom check. A Checkov config referencing non-existent custom policies will fail at runtime.
  ```bash
  mkdir -p .service-approval/controls/proactive/custom-policies
  ```
  Each custom policy file must define the check ID, resource type, and evaluation logic.

### OPA Account Policies (`proactive/opa-policies/<ResourceType>.rego`)
- One `.rego` file per resource type
- **Authorizer field completeness**: When validating authorizer controls, OPA deny rules
  MUST check ALL accepted configuration fields. Verify the exact set via
  `aws <service> <command> --generate-cli-skeleton`. Generate separate deny blocks for
  each required field — do not generate checks for fields the API does not accept.

---

## Account × Preventive

### Permission Boundary (`preventive/permission-boundary.json`)
- Limit role permissions to needed service actions
- Use `awsknowledge` MCP for real action names

**IAM action validation (CRITICAL):** Before generating any IAM policy artifact (SCP,
permission boundary, IAM policies, resource policies, VPCE policies), verify that every
`Action` value exists in `validated.json` `api_surface.operations[].operation` OR is listed
as a permission-only action in `capabilities.iam.permission_only_actions[]`. Permission-only
actions (e.g., `InvokeGateway`) are valid IAM-evaluated actions without API endpoints — they
CAN be used in policies. Common error: inventing action patterns (e.g., `<prefix>:Describe*`)
when the service only supports `Get*` and `List*` for read operations. Check the service's
IAM actions via `awsknowledge` MCP or
the IAM Actions Reference. If the service prefix does not support a particular action verb,
do not generate it. This applies to ALL policy files: `scp-policy.json`, `iam-policies.json`,
`permission-boundary.json`, `resource-policy.json`, `vpce-policy.json`.

### IAM Policies and Trust Policies (`preventive/iam-policies.json`)
- Generate standalone IAM policy and trust policy documents for ACC-PRV controls with `mechanism`
  of "IAM Policy" or "IAM Trust Policy"
- Each control gets a named policy document in the JSON file
- Trust policies: include `Condition` block for confused deputy protection
- IAM policies: scope to specific resource ARN patterns, not `*`
- **Do NOT skip these controls** — they are distinct from the permission boundary and implement
  specific scoped access patterns (execution role policies, trust relationships). Controls with
  IAM Policy/Trust Policy mechanism that have no standalone artifact are a generation gap.

---

## Resource × Proactive

Append resource-specific CFN Guard rules to `proactive/cfn-guard-rules.guard` with
a comment header separating them from account-level rules.

---

## Resource × Preventive

### Resource Policy (`preventive/resource-policy.json`)
- Use `awsknowledge` MCP for real ARN patterns and action names
- **MANDATORY confused deputy protection on resource-based policies**: EVERY resource-based
  policy Statement (policies attached TO a resource like Runtime or Gateway) MUST include
  `"Condition": { "StringEquals": { "aws:SourceAccount": "${AWS::AccountId}" } }` at minimum.
  For service-to-service calls, also add `"ArnLike": { "aws:SourceArn": "arn:aws:<service>:<region>:<account>:*" }`.
  A resource-based policy without confused deputy conditions is a security gap.
- **VPC endpoint policies are different**: VPCE endpoint policies control who can use the
  endpoint, not who can access the resource. Use `aws:PrincipalOrgID` for org scoping, NOT
  `aws:SourceAccount`/`aws:SourceArn` (confused deputy conditions do not apply to endpoint policies).

### KMS Key Policy (`preventive/kms-key-policy.json`)
- Only if encryption controls exist — include `kms:ViaService` condition

### RCP (`preventive/rcp-policy.json`)
Only if `rcp_expressible: true`. If false, write `_metadata.rcp_gap` and skip.
- **Gap placeholder metadata**: Even gap/skip files MUST include complete `_metadata` with ALL
  required fields (scope, layer, controls, framework, mitigations, generated, service). The
  `controls` field can be `[]` for gaps, but `framework` and `mitigations` MUST be populated
  with the full union lists. A gap file with missing metadata fields breaks downstream validation.
- Always `"Effect": "Deny"` and `"Principal": "*"`
- `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}`
- `"StringNotEquals": {"aws:PrincipalOrgID": "${ORG_ID}"}`

### Declarative Policy (`preventive/declarative-policy.json`)
Only if `declarative_policy_expressible: true`.

### Backup Policy (`preventive/backup-policy.json`)
Only if `backup_policy_applicable: true`.

---

## Apply Enrichment Opportunities

For each `enrichment_opportunity` in `validated.json` with `verified: true`:
- Find the referenced control in already-generated artifacts
- Add the enhancement (inject condition key, add `kms:ViaService`, etc.)
- Generate concrete IAM policy example inline

---

## Validate Generated Artifacts

Artifact validation runs automatically via PostToolUse hook (validate_controls.py) and Stop hook (validate_cross.py Check X9).

## Print Summary

```
Generate (preventive/proactive) complete:
  Org×Proactive:    tag-policy, OPA org policy [, scp-provisioning]
  Org×Preventive:   scp-policy [, ai-optout-policy]
  Acc×Proactive:    cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA policies
  Acc×Preventive:   permission-boundary
  Res×Proactive:    cfn-guard resource rules
  Res×Preventive:   resource-policy [, kms-key-policy] [, rcp-policy]
  Output: .service-approval/controls/preventive/, .service-approval/controls/proactive/
```
