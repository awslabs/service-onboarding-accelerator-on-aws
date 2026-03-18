---
name: validate
description: Verify research.json findings via MCP — confirm controls, threats, MITRE assignments, and CCMv4 mappings are real. Produce validated.json.
disable-model-invocation: false
---

# Service Approval — Validator v2

Read `.service-approval/state/research.json` (produced by Researcher v2). Verify every control,
threat, MITRE ATT&CK assignment, and CCMv4 mapping against live MCP sources.
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

Every `verification_note` must be specific to the item being verified. Do NOT copy-paste a
generic note across items. Include:
- The specific parameter, key, technique, or control ID that was checked
- The MCP response detail that confirmed or denied it
- Any caveats

Blanket `verified: true` across all items with identical notes = insufficient verification.

## Step 1: Verify API parameters

For each operation in `api_surface.operations[]` and each parameter in `.parameters[]`:
- Call `awsknowledge` MCP: confirm the parameter exists in the live API schema for the operation
- Set `verified: true/false`, `verification_source`, `verification_note`

## Step 2: Verify condition keys

For each control in `controls[]` where `category` is `Preventive` and `enforcement_point`
references an IAM condition key:
- Extract condition key names (pattern: `aws:Source*`, `<service>:*`)
- Look up the key in the **IAM Service Authorization Reference**
  (`https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html`)
  Use `awsknowledge` MCP to read the service-specific authorization reference page
  (e.g., `list_<service>.html`) — this lists all supported condition keys, actions they
  apply to, and their types.
- Do NOT verify via the API reference — use only the Service Authorization Reference.
- For global condition keys (`aws:SourceArn`, `aws:PrincipalOrgID`, etc.), confirm against
  the global condition keys page in the Service Authorization Reference.
- Flag keys not found as `verified: false`

Each `verification_note` must include the key name, which actions it applies to, its type,
and any caveats (e.g., "key exists but only applies to CreateX, not UpdateX").

## Step 2b: Verify SCP and RCP expressibility

Run for every control in `controls[]` where `category` is `Preventive`. Results are used
by the Generator. Run BEFORE Step 6.

**SCP expressibility** — for controls where `scope` is `Organisation` or `Account`:

1. Identify the control intent from `description` and `parameters_controlled`
2. Call `awsknowledge` MCP: fetch the service authorization reference for the service prefix.
   - Look up each API action involved in this control
   - Extract the "Condition keys" column — these are the ONLY condition keys that work in an SCP
   - If no service-specific key covers the intent, check global keys
3. Call `aws-documentation` MCP to verify SCP limitations:
   ```
   URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
   Extract: any service-specific SCP exemptions
   ```
4. Mark `scp_expressible: false` if ANY of:
   - The action is not in the service authorization reference
   - No condition key in the action's "Condition keys" column matches the control intent
   - The control targets service-linked roles (exempt from SCPs)
   - The only enforcement path is a resource-based policy condition (use RCP instead)
5. Set `scp_expressible: true/false` and `scp_gap_reason` — cite the specific condition key
   found or explain why none exists.

**RCP expressibility** — for controls where `scope` is `Resource`:

Step 1 — Fetch current RCP-supported services from live docs:
```
Call aws-documentation MCP:
  URL: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
  Extract: table of supported services and their service prefixes
```
Log the fetched list. This is authoritative — AWS adds services over time.

Step 2 — For the target service, call `awsknowledge` MCP:
- Query the service authorization reference for `<service-prefix>`
- Look for "Resource control policies" column or RCP applicability notes

Step 3 — Set `rcp_expressible`:
- Service NOT in live docs list → `false`, reason: "Service not in current RCP supported list"
- Service in list but action exempt → `false`, reason: cite the specific exemption
- Service in list and action covered → `true`

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
Always `true` — applies to all IAM roles and users.
Note which actions from `api_surface` should be scoped into the boundary.

Add to each `controls[]` item:
```json
{
  "scp_expressible": true,
  "scp_gap_reason": "",
  "rcp_expressible": false,
  "rcp_gap_reason": "Service not in current RCP supported list (fetched from live docs)",
  "declarative_policy_expressible": false,
  "backup_policy_applicable": false,
  "ai_optout_applicable": false
}
```

## Step 3: Verify MITRE ATT&CK assignments

For each threat in `threats[]`:
- Verify `mitre_tactic_id` is a valid MITRE ATT&CK for Cloud tactic (TA0001–TA0040)
- Verify `mitre_attack.technique_id` exists under the stated tactic
- Confirm the technique is applicable to cloud environments
- Use the technique mapping table from research.json as a cross-reference
- Set `mitre_verified: true/false`, `mitre_verification_note`

Valid cloud tactics: TA0001 Initial Access, TA0002 Execution, TA0003 Persistence,
TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0006 Credential Access,
TA0007 Discovery, TA0009 Collection, TA0010 Exfiltration, TA0040 Impact.

## Step 4: Verify CCMv4 mappings

For each entry in `ccmv4_mappings[]`:
- Verify `control_id` exists in `controls[]` (exact match on `id` field)
- Verify `ccmv4_control_id` is within the valid range for its domain using the domain
  reference table from research.json Phase 3.1 — NEVER invent or guess control IDs
- If matched: set `verified: true`, `verification_source: "CCMv4 domain reference — <domain> range"`
  `verification_note: "<ccmv4_control_title>"`
- If NOT matched: set `verified: false`,
  `verification_note: "Control ID not found in CCMv4 domain reference"`
- Do NOT use keyword mapping or inference as a verification source

## Step 5: Verify enrichment opportunities

For each item in `enrichment_opportunities[]`:
- Call `awsknowledge` MCP to confirm the enhancement is technically feasible
- Set `verified: true/false` with `verification_source` and `verification_note`
- Flag unconfirmable enhancements as `verified: false`

## Step 6: Verify AWS feature support per control

For each control in `controls[]`, confirm the enforcement mechanism is supported:
- **Config rules**: use `awsknowledge` MCP to confirm a managed Config rule exists for this
  resource type, or verify a custom rule is feasible
- **Security Hub**: confirm Security Hub has a standard covering this resource type
- **EventBridge**: confirm the service emits the relevant CloudTrail events
- **CloudWatch Alarms**: use `awsknowledge` MCP to confirm available metrics for the service
- **Access Analyzer**: confirm the resource type supports resource-based policies

**Exclusion rules — do NOT verify controls that cannot apply to this mitigation:**

| Enforcement Mechanism | Exclude when... |
|---|---|
| RCP | `rcp_expressible: false`, OR control is about tagging/network config/logging |
| AI opt-out policy | Control is NOT about AI/ML model invocation or content processing |
| Tag policy | Control is NOT about tagging |
| Access Analyzer | Resource type doesn't support resource-based policies |
| Config rules | No managed or custom Config rule is feasible (confirm via MCP) |
| Permission boundary | Control is about resource-level config, not IAM role permissions |

## Step 7: Count and flag unverified items

Count all items with `verified: false` across all arrays (controls, threats, CCMv4 mappings,
API params, enrichments). Populate top-level `unverified_count` and `unverified_items[]`.

## Step 8: Write output

Write `.service-approval/state/validated.json` — same root structure as `research.json` with
the following additions:

For `controls[]` items, add:
```json
{
  "verified": true,
  "verification_source": "awsknowledge MCP — <service> service authorization reference",
  "verification_note": "<specific note for this control>",
  "scp_expressible": true,
  "scp_gap_reason": "",
  "rcp_expressible": false,
  "rcp_gap_reason": "..."
}
```

For `threats[]` items, add:
```json
{
  "verified": true,
  "verification_note": "<specific note>",
  "mitre_verified": true,
  "mitre_verification_note": "<technique confirmed for cloud tactic TA####>"
}
```

For `ccmv4_mappings[]` items, add: `verified`, `verification_source`, `verification_note`.
For `api_surface.operations[].parameters[]` items, add: `verified`, `verification_source`,
`verification_note`.
For `enrichment_opportunities[]` items, add: `verified`, `verification_source`,
`verification_note`.

Top-level additions:
```json
{
  "unverified_count": 0,
  "unverified_items": []
}
```

Print summary:
```
Validation complete:
  - Controls verified: N/N
  - API parameters verified: N/N
  - Condition keys verified: N/N
  - MITRE ATT&CK assignments verified: N/N
  - CCMv4 mappings verified: N/N
  - Enrichment opportunities verified: N/N
  - UNVERIFIED items: N
  Output: .service-approval/state/validated.json
```
