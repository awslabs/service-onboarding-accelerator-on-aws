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
- Log to `.service-approval/state/mcp-calls.log`

## Step 2: Verify condition keys

For each IAM condition key referenced in any mitigation's `request_parameters` or `statement`:
- Extract condition key names (pattern: `aws:Source*`, `<service>:*`)
- Call `awsknowledge` MCP to confirm the key is a real IAM global or service-specific condition key
- Flag unrecognized keys as `verified: false`

## Step 3: Verify enrichment opportunities

For each item in `enrichment_opportunities[]`:
- Call `awsknowledge` MCP to confirm the enhancement is technically feasible (e.g., condition key exists, API supports the recommended pattern)
- Determine `applicable_controls` in the same way as `missing_threats` (see Step 4 below)
- Set `verified: true/false` with `verification_source` and `verification_note`
- Flag unconfirmable enhancements as `verified: false`

Enrichment opportunities ARE carried forward in `validated.json` and processed by the Generator — they produce additional detail in generated policies (e.g., more specific condition key examples) rather than new artifact files.

## Step 4: Verify AWS feature support

For each `missing_threat`, `existing_mitigation`, and `enrichment_opportunity`, determine `applicable_controls`:
- **SCP**: always applicable (all services are covered by SCPs)
- **RCP**: check if service supports resource-based policies (confirm via `awsknowledge` MCP)
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
- Confirm the `ccmv4_control_id` exists in the CCMv4 xlsx (exact match on Control ID column)
- Set `verified: true/false`

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
