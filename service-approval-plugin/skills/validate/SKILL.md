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

## Step 1: Verify API parameters

For each item in `api_surface.operations[].parameters[]`:
- Call `awsknowledge` MCP: confirm the parameter path exists in the live API schema for the operation
- Set `verified: true/false`, `verification_source` (MCP response reference), `verification_note`

Each `verification_note` must be specific to the item being verified. Do NOT copy-paste a generic note across all items. Include:
- The specific parameter name or condition key that was checked
- The MCP response detail that confirmed or denied it
- Any caveats (e.g., "parameter exists but no condition key available for SCP enforcement")

If MCP returns ambiguous results, set `verified: true` with a qualified note, or `verified: false` with explanation. Blanket `verified: true` across all items with identical notes indicates insufficient verification.

Log every MCP call to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] [Validator] MCP CALL: <tool_name>
  <parameters>
  result: <summary>
```

## Step 2: Verify condition keys

For each IAM condition key referenced in any mitigation's `request_parameters` or `statement`:
- Extract condition key names (pattern: `aws:Source*`, `<service>:*`)
- Look up the key in the **IAM Service Authorization Reference** (`https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html`). Use `awsknowledge` MCP to read the service-specific authorization reference page (e.g., `list_<service>.html`) — this lists all supported condition keys, the actions they apply to, and their types.
- Do NOT verify condition keys by checking the service's API reference — the API docs describe request parameters, not IAM condition keys. The authoritative source is the Service Authorization Reference.
- For global condition keys (`aws:SourceArn`, `aws:PrincipalOrgID`, etc.), confirm against the global condition keys page in the Service Authorization Reference.
- Flag keys not found in the Service Authorization Reference as `verified: false`

Each `verification_note` must be specific to the condition key being verified. Include the specific key name, which actions it applies to (from the authorization reference), its type (String, ARN, etc.), and any caveats (e.g., "condition key exists but only applies to CreateX, not UpdateX"). Do NOT use identical notes across multiple items.

Log every MCP call to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] [Validator] MCP CALL: <tool_name>
  <parameters>
  result: <summary>
```

## Step 3: Verify enrichment opportunities

For each item in `enrichment_opportunities[]`:
- Call `awsknowledge` MCP to confirm the enhancement is technically feasible (e.g., condition key exists, API supports the recommended pattern)
- Determine `applicable_controls` in the same way as `missing_threats` (see Step 4 below)
- Set `verified: true/false` with `verification_source` and `verification_note`
- Flag unconfirmable enhancements as `verified: false`

Log every MCP call to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] [Validator] MCP CALL: <tool_name>
  <parameters>
  result: <summary>
```

Enrichment opportunities ARE carried forward in `validated.json` and processed by the Generator — they produce additional detail in generated policies (e.g., more specific condition key examples) rather than new artifact files.

## Step 4: Verify AWS feature support

For each `missing_threat`, `existing_mitigation`, and `enrichment_opportunity`, determine `applicable_controls`:
- **SCP**: Use `awsknowledge` MCP to read the SCPs documentation at `https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html`. SCPs are service-agnostic — they apply to all AWS services and actions. Always applicable.
- **RCP**: Use `awsknowledge` MCP to read the RCPs documentation at `https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html`. RCPs are service-agnostic authorization policies that set permission guardrails on resources in your organization. Check the RCP documentation for any service-specific limitations or unsupported resource types. Do NOT conflate RCP support with whether a service has resource-based policies — RCPs are an Organizations feature, not a per-service resource policy feature.
- **Declarative Policy**: check if a declarative policy exists for this service via `awsknowledge` MCP
- **AI Opt-out Policy**: applicable only if service is an AI/ML service
- **Backup Policy**: applicable if service resources can be backed up via AWS Backup
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

Log every MCP call to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] [Validator] MCP CALL: <tool_name>
  <parameters>
  result: <summary>
```

**Exclusion rules — do NOT include controls that are irrelevant to the mitigation goal:**

| Control | Exclude when... |
|---|---|
| `rcp-policy` | Mitigation is about tagging, network config, logging, or the resource type doesn't support resource policies |
| `ai-optout-policy` | Mitigation is NOT about AI/ML model invocation, training data, or content processing |
| `tag-policy` | Mitigation is NOT about tagging (e.g., network, encryption, IAM role, logging mitigations) |
| `access-analyzer` | Resource type doesn't support resource-based policies, OR mitigation is about tagging/network/logging |
| `config-rules` | No managed or custom Config rule is feasible for this specific check (confirm via MCP) |
| `permission-boundary` | Mitigation is about resource-level config (encryption, network, tags), not IAM role permissions |

The goal is precision: only list controls that can actually enforce or detect the specific mitigation requirement. A control that "exists for the service" but cannot address the specific mitigation goal should NOT be listed.

Populate `applicable_controls` map per item. Example structure:
```json
{
  "applicable_controls": {
    "proactive": ["cfn-guard-rules", "cfn-hooks-policy", "checkov"],
    "preventive": ["scp-policy", "rcp-policy", "tag-policy"],
    "detective": ["config-rules", "eventbridge-rules", "security-hub-config"],
    "remediation": ["lambda-remediator", "ssm-runbook"]
  }
}
```

## Step 5: Verify CCMv4 mappings

For each entry in `ccmv4_mappings[]`:
- Open the CCMv4 xlsx file (path from research.json input or `./input-folder`)
- For each `ccmv4_controls[]` ID: exact-match against the Control ID column
- If matched: set `verified: true`, `verification_source: "CCMv4 xlsx — row N"`, `verification_note: "<Control Title from xlsx>"`
- If NOT matched: set `verified: false`, `verification_note: "Control ID not found in CCMv4 xlsx"`
- Do NOT use "Deterministic keyword mapping algorithm" as a verification source — that is the research tool's method, not independent verification

## Step 6: Count and flag unverified items

Count all items with `verified: false` across all arrays (mitigations, threats, enrichments, API params, CCMv4 mappings).
Populate top-level `unverified_count` and `unverified_items[]`.

## Step 7: Write output

Write `.service-approval/state/validated.json` — same root structure as `research.json` with the following additions per item:

For `existing_mitigations[]` items, add:
```json
{
  "verified": true,
  "verification_source": "awsknowledge MCP — bedrock-agentcore-control API schema",
  "verification_note": "",
  "applicable_controls": { ... }
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

## Verify frontmatter
```bash
head -5 skills/validate/SKILL.md
```
Expected: starts with `---` and contains `name: validate`.

## Commit
```bash
cd "/Users/hardikvt/Library/CloudStorage/OneDrive-amazon.com/Hackathon/service-approval-plugin"
git add skills/validate/SKILL.md
git commit -m "feat: add validator agent skill"
```

Report: Status DONE + commit SHA.
