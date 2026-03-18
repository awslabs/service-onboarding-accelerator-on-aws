---
name: validate
description: Verify research.json findings via MCP — confirm APIs, condition keys, Config rules are real. Produce validated.json.
disable-model-invocation: false
---

# Service Approval — Validator

Read `.service-approval/state/research.json`. Verify every finding against live MCP sources.
Produce `.service-approval/state/validated.json`.

## Prerequisites

- [ ] Confirm research.json exists:
  ```bash
  test -f .service-approval/state/research.json && echo "OK" || echo "ERROR: run researcher first"
  ```
  Stop if missing.

## MCP call logging

Log every MCP call to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] [Validator] MCP CALL: <tool_name>
  <parameters>
  result: <summary>
```

## Verification note rules

Every `verification_note` must be specific to the item being verified. Do NOT copy-paste a generic
note across all items. Include:
- The specific parameter name or condition key that was checked
- The MCP response detail that confirmed or denied it
- Any caveats (e.g., "parameter exists but no condition key available for SCP enforcement")

If MCP returns ambiguous results, set `verified: true` with a qualified note, or `verified: false`
with explanation. Blanket `verified: true` across all items with identical notes indicates
insufficient verification.

## Step 1: Verify API parameters

For each item in `api_surface.operations[].parameters[]`:
- Call `awsknowledge` MCP: confirm the parameter exists in the live API schema for the operation
- Set `verified: true/false`, `verification_source` (MCP response reference), `verification_note`

## Step 2: Verify condition keys

For each IAM condition key referenced in any mitigation's `request_parameters` or `statement`:
- Extract condition key names (pattern: `aws:Source*`, `<service>:*`)
- Look up the key in the **IAM Service Authorization Reference**
  (`https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html`)
  Use `awsknowledge` MCP to read the service-specific authorization reference page
  (e.g., `list_<service>.html`) — this lists all supported condition keys, the actions they apply
  to, and their types.
- Do NOT verify condition keys by checking the service's API reference — the API docs describe
  request parameters, not IAM condition keys. The authoritative source is the Service Authorization Reference.
- For global condition keys (`aws:SourceArn`, `aws:PrincipalOrgID`, etc.), confirm against the
  global condition keys page in the Service Authorization Reference.
- Flag keys not found in the Service Authorization Reference as `verified: false`

Each `verification_note` must include the specific key name, which actions it applies to (from the
authorization reference), its type (String, ARN, etc.), and any caveats (e.g., "condition key
exists but only applies to CreateX, not UpdateX").

## Step 2b: Verify SCP and RCP expressibility

This step determines whether each finding can actually be expressed as an SCP or RCP.
Results feed into `applicable_controls` in Step 4. Run this BEFORE Step 4.

**SCP expressibility check** — for each `existing_mitigation` and `missing_threat`:

1. Identify the control intent (what must be enforced: encryption, IMDSv2, no public access, etc.)

2. Call `awsknowledge` MCP: fetch the service authorization reference for `<service-prefix>`.
   - Look up each API action involved in this control
   - Extract the "Condition keys" column for those actions — these are the ONLY condition keys
     that work with that action in an SCP
   - If no service-specific condition key covers the control intent, check global condition keys
     (`aws:RequestedRegion`, `aws:PrincipalArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, etc.)

3. Call `aws-documentation` MCP to verify SCP limitations for this service:
   ```
   URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
   Extract: any service-specific SCP exemptions or limitations
   ```

4. Mark `scp_expressible: false` if ANY of:
   - The action does not appear in the service authorization reference (not a real action)
   - No condition key in the action's "Condition keys" column matches the control intent
   - The control targets service-linked roles (exempt from SCPs)
   - The control exclusively targets the management account
   - The only enforcement path is a resource-based policy condition (use RCP instead)

5. Set `scp_expressible: true/false` and `scp_gap_reason` — cite the specific condition key
   found or explain exactly why none exists (e.g., "CreateAgentRuntime has no condition key
   for KMS key enforcement; use resource policy + Config rule instead")

**RCP expressibility check** — do NOT use a hardcoded service list. Fetch the current live list:

```
Call aws-documentation MCP:
  URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
  Extract: table of supported services and their service prefixes
```
Log the fetched list to mcp-calls.log. This is the authoritative current list — AWS adds services over time.

For the target service, call `awsknowledge` MCP:
- Query the service authorization reference for `<service-prefix>`
- Look for "Resource control policies" column or RCP applicability notes
- Check whether the specific action being controlled appears in the RCP-applicable action list

Set `rcp_expressible`:
- Service NOT in live docs list → `rcp_expressible: false`, `rcp_gap_reason: "Service <prefix> not in current RCP supported services list (fetched from AWS docs)"`
- Service in list but action exempt (e.g., `kms:RetireGrant`, AWS-managed keys) → `rcp_expressible: false`, `rcp_gap_reason: "<action> is exempt from RCPs per service authorization reference"`
- Service in list and action covered → `rcp_expressible: true`

**Declarative policy check:**
```
Call aws-documentation MCP:
  URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative.html
  Extract: which services and resource types have declarative policy support
```
Set `declarative_policy_expressible: true/false`.

**Backup policy check:**
```
Call awsknowledge MCP: check if <cfn_type> resource is listed as AWS Backup-supported
  OR call aws-documentation MCP:
  URL: https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
  Extract: list of supported resource types
```
Set `backup_policy_applicable: true/false`.

**AI opt-out policy check:**
```
Call aws-documentation MCP:
  URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai_opt_out.html
  Extract: which AI/ML services support opt-out policies
```
Set `ai_optout_applicable: true/false`.

**Permission boundary check:**
Always `true` — permission boundaries apply to all IAM roles and users.
Note which specific actions from `api_surface` should be scoped into the boundary.

Add to each `existing_mitigation`, `missing_threat`, and `enrichment_opportunity`:
```json
{
  "scp_expressible": true,
  "scp_gap_reason": "",
  "rcp_expressible": false,
  "rcp_gap_reason": "Service not supported by RCPs (fetched from live docs)",
  "declarative_policy_expressible": false,
  "backup_policy_applicable": false,
  "ai_optout_applicable": false
}
```

## Step 3: Verify enrichment opportunities

For each item in `enrichment_opportunities[]`:
- Call `awsknowledge` MCP to confirm the enhancement is technically feasible
- Determine `applicable_controls` in the same way as `missing_threats` (see Step 4 below)
- Set `verified: true/false` with `verification_source` and `verification_note`
- Flag unconfirmable enhancements as `verified: false`

Enrichment opportunities ARE carried forward in `validated.json` and processed by the Generator —
they produce additional detail in generated policies rather than new artifact files.

## Step 4: Verify AWS feature support

For each `missing_threat`, `existing_mitigation`, and `enrichment_opportunity`, determine `applicable_controls`:
- **SCP**: applicable UNLESS `scp_expressible: false` from Step 2b
- **RCP**: applicable ONLY if `rcp_expressible: true` from Step 2b (live docs confirmed)
- **Declarative Policy**: applicable ONLY if `declarative_policy_expressible: true` from Step 2b
- **AI Opt-out Policy**: applicable ONLY if `ai_optout_applicable: true` from Step 2b
- **Backup Policy**: applicable ONLY if `backup_policy_applicable: true` from Step 2b
- **Tag Policy**: always applicable
- **Permission Boundary**: always applicable
- **Config rules**: check if a managed Config rule exists for this resource type via `awsknowledge` MCP
- **Config Conformance Pack**: applicable if 2+ Config rules generated
- **cfn-guard rules**: applicable if resource has a CFN resource type
- **CloudFormation Hooks**: applicable if resource has a CFN resource type
- **OPA policies**: always applicable (fallback for non-CFN pipelines)
- **checkov**: always applicable if resource has a CFN resource type
- **EventBridge rules**: applicable if service emits CloudTrail events (confirm via docs MCP)
- **CloudWatch Alarms**: applicable if service has CloudWatch metrics (confirm via `awsknowledge` MCP)
- **Security Hub**: applicable if Security Hub has a standard covering this resource
- **Lambda remediator**: applicable for any detective control that has a clear remediation action
- **SSM Runbook**: applicable for operational remediation scenarios
- **CloudTrail config**: always applicable
- **Access Analyzer**: applicable if resource supports resource-based policies

**Exclusion rules — do NOT include controls that are irrelevant to the mitigation goal:**

| Control | Exclude when... |
|---|---|
| `rcp-policy` | `rcp_expressible: false`, OR mitigation is about tagging/network config/logging |
| `ai-optout-policy` | Mitigation is NOT about AI/ML model invocation, training data, or content processing |
| `tag-policy` | Mitigation is NOT about tagging (e.g., network, encryption, IAM role, logging mitigations) |
| `access-analyzer` | Resource type doesn't support resource-based policies, OR mitigation is about tagging/network/logging |
| `config-rules` | No managed or custom Config rule is feasible for this specific check (confirm via MCP) |
| `permission-boundary` | Mitigation is about resource-level config (encryption, network, tags), not IAM role permissions |

The goal is precision: only list controls that can actually enforce or detect the specific
mitigation requirement.

Populate `applicable_controls` map per item:
```json
{
  "applicable_controls": {
    "proactive": ["cfn-guard-rules", "cfn-hooks-policy", "checkov"],
    "preventive": ["scp-policy", "tag-policy"],
    "detective": ["config-rules", "eventbridge-rules", "security-hub-config"],
    "remediation": ["lambda-remediator", "ssm-runbook"]
  }
}
```

## Step 5: Verify CCMv4 mappings

For each entry in `ccmv4_mappings[]`:
- Open the CCMv4 xlsx file (path from research.json input or `./input-folder`)
- For each control ID in `ccmv4_controls[]`: exact-match against the Control ID column
- If matched: set `verified: true`, `verification_source: "CCMv4 xlsx — row N"`,
  `verification_note: "<Control Title from xlsx>"`
- If NOT matched: set `verified: false`,
  `verification_note: "Control ID not found in CCMv4 xlsx"`
- Do NOT use keyword mapping or inference as a verification source — only exact xlsx match counts

## Step 6: Count and flag unverified items

Count all items with `verified: false` across all arrays (mitigations, threats, enrichments,
API params, CCMv4 mappings). Populate top-level `unverified_count` and `unverified_items[]`.

## Step 7: Write output

Write `.service-approval/state/validated.json` — same root structure as `research.json` with
the following additions per item:

For `existing_mitigations[]` items, add:
```json
{
  "verified": true,
  "verification_source": "awsknowledge MCP — <service> API schema",
  "verification_note": "<specific note for this item>",
  "applicable_controls": { ... },
  "scp_expressible": true,
  "scp_gap_reason": "",
  "rcp_expressible": false,
  "rcp_gap_reason": "..."
}
```

For `missing_threats[]` items, add same fields.
For `enrichment_opportunities[]` items, add same fields.
For `api_surface.operations[].parameters[]` items, add: `verified`, `verification_source`, `verification_note`.
For `ccmv4_mappings[]` items, add: `verified`, `verification_source`, `verification_note`.

Top-level additions:
```json
{
  "unverified_count": 0,
  "unverified_items": []
}
```

The `applicable_controls` field is the authoritative signal for the Control Generator.

Print summary:
```
Validation complete:
  - API parameters verified: N/N
  - Condition keys verified: N/N
  - Enrichment opportunities verified: N/N
  - Applicable controls determined: N items × M control types
  - CCMv4 mappings verified: N/N
  - UNVERIFIED items: N (run with --include-unverified to include them)
  Output: .service-approval/state/validated.json
```

