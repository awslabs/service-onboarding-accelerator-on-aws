---
name: map-generate-controls
description: >
  Generate security controls from mitigations x capabilities, organized by Category x Scope matrix.
  Produces map-controls-generated.json with rich metadata for downstream framework mapping.
  Consumes validated.json.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Map: Generate Controls

Using the mitigation inventory and verified service capabilities, generate security controls
organized by the Category x Scope matrix. Each control traces back to mitigation(s) and
includes rich metadata so downstream skills (framework-mapping, generate) can work without
re-deriving the reasoning chain.

**Input:** `.service-approval/state/validated.json`
**Output:** `.service-approval/state/map-controls-generated.json`

This is one of 4 focused map sub-skills. Each writes to a separate intermediate state file.

---

## Prerequisites

```bash
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR: run validator first"
mkdir -p .service-approval/state
```

Load validated.json and extract:
```bash
python3 -c "
import json
vj = json.load(open('.service-approval/state/validated.json'))
print(f'Assets: {len(vj[\"assets\"])}')
print(f'Operations: {len(vj[\"api_surface\"][\"operations\"])}')
print(f'Mitigations: {len(vj[\"existing_mitigations\"])}')
print(f'Condition keys: {len(vj[\"capabilities\"][\"iam\"][\"condition_keys\"])}')
gaps = vj.get('assessment_gaps', [])
print(f'Assessment gaps: {len(gaps)}')
print(f'SCP: {vj[\"capabilities\"][\"organization_policies\"][\"scp\"][\"supported\"]}')
print(f'RCP: {vj[\"capabilities\"][\"organization_policies\"].get(\"rcp\", {}).get(\"supported\", False)}')
"
```

---

## Phase 1: Build Mitigation Index

For each mitigation in `existing_mitigations[]`, build a rich index:

```json
{
  "id": "M-AgentRuntime.0",
  "statement": "...",
  "mitigation_goal": "...",
  "request_parameters": ["$.encryptionKeyArn", "$.executionRoleArn"],
  "resource_type": "AWS::BedrockAgentCore::AgentRuntime",
  "verified": true,
  "verification_note": "..."
}
```

Group mitigations by `resource_type` for efficient lookup during control generation.

### Cross-reference with assessment gaps

If `assessment_gaps[]` exists in validated.json:
- For each gap with `status` = `REQUIREMENT GAP` or `CUSTOMER ACTION REQUIRED`:
  - Check if any existing mitigation addresses this gap
  - If not, flag as `unaddressed_gap` — must generate controls for it

---

## Phase 2: Generate Controls

For each mitigation, generate controls using the Category x Scope matrix.

### 2.1 Control generation logic

For each mitigation:
1. Read the `mitigation_goal` — defines WHAT needs to be controlled
2. Read `request_parameters[]` — the API parameters that enforce the control
3. Look up the corresponding capability in `capabilities{}` — defines HOW the service supports it
4. Generate one or more controls that enforce the mitigation goal using available capabilities
5. Write the **security_rationale** — a 2-3 sentence explanation of WHY this control is the right
   mechanism for this mitigation, including the reasoning chain from mitigation goal to enforcement
   mechanism. This rationale is consumed by map-framework-mapping to make informed mapping decisions.

**CRITICAL — Condition key action applicability:**

When assigning `condition_keys` and `actions` to a control, verify that each condition key
actually applies to the specified actions. The SAR page defines which condition keys work with
which actions — a condition key used in an SCP/IAM Deny on an action it doesn't apply to will
be silently ignored by IAM, making the control ineffective.

Before assigning a condition key to a control:
1. Look up the key in `capabilities.iam.condition_keys[]`
2. Read its `applies_to_actions[]` list
3. Confirm that EVERY action in the control's `actions[]` appears in `applies_to_actions[]`
4. If the action is NOT in `applies_to_actions[]`, do NOT use that condition key for that action.
   Instead, find an alternative enforcement mechanism (resource policy, Config rule, etc.)

Common error: using a resource-type-specific condition key (e.g., one that applies to Gateway
operations) on a different resource type's actions (e.g., Runtime). Each resource type may have
different applicable condition keys.

### 2.2 Control sources to enumerate

- **IAM controls** — from `capabilities.iam` (condition keys, resource policies, permission boundaries, SCPs)
- **Encryption controls** — from `capabilities.encryption` (KMS CMK, SSE, TLS, key rotation)
- **Network controls** — from `capabilities.network` (VPC, endpoints, PrivateLink, security groups)
- **Logging controls** — from `capabilities.logging` (CloudTrail, CloudWatch, data events)
- **Configuration controls** — from `capabilities.config` (Config rules, conformance packs)
- **Organization policy controls** — from `capabilities.organization_policies` (SCPs, RCPs, declarative policies)
- **Tagging controls** — tag policies, required tags
- **Availability controls** — backup, multi-AZ, lifecycle
- **AI-specific controls** — guardrails, prompt validation (if applicable)

### 2.3 Control Matrix — Category x Scope

Assign each control a primary **category** (X-axis) and a **scope level** (Y-axis):

**Categories (X-axis):**

| Category | Code | Definition | Examples |
|----------|------|-----------|----------|
| Proactive | PRO | Prevents non-compliant resources from being created | CFN Guard, SCP deny, Config proactive rules, OPA |
| Preventive | PRV | Blocks unauthorized actions at runtime | IAM policies, resource policies, SCPs, VPC SGs, KMS key policies |
| Detective | DET | Identifies non-compliant or suspicious state after the fact | Config rules, CloudTrail analysis, CloudWatch alarms |
| Corrective | COR | Automatically remediates non-compliant state | SSM runbooks, Lambda remediation, EventBridge workflows |

**Scope Levels (Y-axis):**

| Scope | Code | Definition | Examples |
|-------|------|-----------|----------|
| Organisation | ORG | Applied across the AWS Organization | SCPs, tag policies, Config org rules |
| Account | ACC | Applied within a single AWS account | IAM policies, permission boundaries, Config rules |
| Resource | RES | Applied directly to an individual resource | Resource-based policies, KMS key policies |

Each control MUST have exactly one category AND one scope level.

### 2.4 Control output schema

Every control MUST include these fields:

```json
{
  "id": "CTRL-ORG-PRV-001",
  "name": "Enforce CMK encryption on AgentRuntime creation via SCP",
  "description": "SCP denies bedrock-agentcore:CreateAgentRuntime unless encryptionKeyArn condition is present",
  "scope": "ORG",
  "category": "PRV",
  "mechanism": "SCP",
  "mitigation_ids": ["M-AgentRuntime.0", "M-AgentRuntime.3"],
  "parameters_controlled": ["$.encryptionKeyArn"],
  "condition_keys": ["bedrock-agentcore:encryptionKeyArn"],
  "actions": ["bedrock-agentcore:CreateAgentRuntime", "bedrock-agentcore:UpdateAgentRuntime"],
  "resource_types": ["AWS::BedrockAgentCore::AgentRuntime"],
  "assessment_gap_ids": [],
  "security_rationale": "The mitigation requires encryption key enforcement at creation time. An SCP is the strongest mechanism because it operates at the organization level, denying any CreateAgentRuntime call that lacks the encryptionKeyArn parameter regardless of the caller's IAM permissions. This ensures no runtime can be created without customer-managed encryption.",
  "attack_techniques": ["T1530", "T1486"],
  "framework_keywords": ["encryption", "key management", "data protection", "policy enforcement"]
}
```

**Field requirements:**
- `id`: Format `CTRL-{SCOPE}-{CATEGORY}-{NNN}` (e.g., CTRL-ORG-PRV-001)
- `scope`: Abbreviated code: `ORG`, `ACC`, `RES`
- `category`: Abbreviated code: `PRV`, `PRO`, `DET`, `COR`
- `mechanism`: AWS enforcement mechanism (SCP, CloudFormation Hook, AWS Config Rule, VPC Endpoint Policy, IAM Permission Boundary, Resource Policy, IAM Trust Policy, IaC Template, CloudTrail, CloudWatch Alarm, CloudWatch Logs, Kinesis Data Streams, SSM Automation, Lambda Remediation, EventBridge + Step Functions, Tag Policy, OPA Policy, CloudFormation Guard, Compensating Control Documentation)
- `mitigation_ids`: Non-empty array — every control MUST trace to at least one mitigation
- `parameters_controlled`: API parameters this control enforces (from mitigation `request_parameters[]`)
- `condition_keys`: IAM condition keys used (empty array for non-IAM controls)
- `actions`: IAM actions restricted/monitored (empty array for non-IAM controls)
- `resource_types`: AWS resource types affected (CFN format)
- `assessment_gap_ids`: Assessment gaps addressed (empty array if none)
- `security_rationale`: 2-3 sentences explaining the mitigation-to-mechanism reasoning chain. MUST include:
  (1) what the mitigation requires, (2) why this specific mechanism was chosen, (3) what it prevents/detects.
  This field is the PRIMARY context for downstream framework-mapping — write it as if the reader has
  never seen the mitigation text.
- `attack_techniques`: ATT&CK technique IDs this control mitigates (empty array if `attack_surface`
  not present in validated.json). Populated by cross-referencing the control's `actions[]`,
  `condition_keys[]`, and `mechanism` against `attack_surface.applicable_techniques[].api_surface_evidence[]`.
  A control mitigates a technique if it restricts/monitors any action listed in that technique's evidence.
- `framework_keywords`: 4-8 keywords for framework objective matching. Include BOTH domain keywords
  (encryption, access, network) AND mechanism keywords (deny, monitor, audit, enforce, restrict).

### 2.5 Corrective control generation

For every detective control, evaluate whether a corrective control is appropriate. Generate
corrective controls for at minimum:
- **Encryption drift**: auto-remediate resources created without CMK encryption
- **Authentication drift**: alert + optional auto-remediate gateways with AuthorizerType=NONE
- **Tag compliance**: auto-tag resources missing mandatory tags
- **VPC configuration drift**: alert on resources created without VPC networking

Link each corrective control to the same mitigation IDs as its corresponding detective control.
Use mechanism types: `SSM Automation`, `Lambda Remediation`, `EventBridge + Step Functions`.

### 2.6 Assessment gap coverage

For every `REQUIREMENT GAP` and `CUSTOMER ACTION REQUIRED` from `assessment_gaps[]`:
- Generate at least one control that addresses the gap
- Link via `assessment_gap_ids[]` on the control

### 2.7 ATT&CK technique cross-reference (optional)

If `validated.json` contains `attack_surface.applicable_techniques[]`:
1. For each control, check if any of its `actions[]` appear in a technique's `api_surface_evidence[]`
2. If so, add that technique's ID to `attack_techniques[]` on the control
3. Also check mechanism alignment:
   - SCP/IAM controls → relevant to T1078, T1098, T1548 (identity techniques)
   - Encryption controls → relevant to T1530, T1486 (data techniques)
   - Network controls → relevant to T1190, T1133 (access techniques)
   - Logging controls → relevant to T1562, T1070 (evasion techniques)
4. If `attack_surface` is NOT present in validated.json, set `attack_techniques: []` on all controls

### 2.8 Compensating control documentation

Some capabilities are NOT available for the service (e.g., RCP not supported, no delegated admin,
ABAC partial). For each unavailable capability referenced in assessment_gaps or where controls
cannot be implemented:
- Generate a control with `mechanism: "Compensating Control Documentation"`
- Describe what compensating measures should be taken
- Include in the controls array like any other control

---

## Phase 3: Mitigation Coverage Completeness Check (MANDATORY)

**CRITICAL — Do NOT write output until this check passes.**

After generating all controls, verify that EVERY mitigation in `existing_mitigations[]` has at
least one control referencing its ID in `mitigation_ids[]`:

```python
all_mit_ids = set(m['id'] for m in existing_mitigations)
covered_mit_ids = set()
for ctrl in controls:
    covered_mit_ids.update(ctrl.get('mitigation_ids', []))
uncovered = all_mit_ids - covered_mit_ids
if uncovered:
    print(f"UNCOVERED MITIGATIONS: {sorted(uncovered)}")
    # MUST generate controls for each — see guidance below
```

**For each uncovered mitigation, generate controls using this guidance:**

- **Availability mitigations** (multi-AZ, redundancy): CloudFormation Guard rule + Config rule
  checking subnet AZ diversity. Distinct from "has VPC subnets."
- **Authentication configuration mitigations** (JWT, OIDC): Guard rule validating full auth config
  (discovery URL, audiences, clients, scopes). Distinct from "authorizer type != NONE."
- **Network perimeter mitigations** (approved networks): VPC endpoint policies + IAM conditions
  restricting by source VPC/endpoint.
- **Data lifecycle mitigations** (retention, deletion): Config rules checking resource config.
- **Any other**: Read `mitigation_goal` and `request_parameters[]` to determine domain, then generate.

**Re-run the check after generating gap-filling controls. Zero uncovered mitigations required.**

---

## Phase 4: Write Output

Write `.service-approval/state/map-controls-generated.json`:

```json
{
  "schema_version": "1.0",
  "service": "<service-name>",
  "controls": [
    {
      "id": "CTRL-ORG-PRV-001",
      "name": "...",
      "description": "...",
      "scope": "ORG",
      "category": "PRV",
      "mechanism": "SCP",
      "mitigation_ids": ["M-AgentRuntime.0"],
      "parameters_controlled": ["$.encryptionKeyArn"],
      "condition_keys": ["bedrock-agentcore:encryptionKeyArn"],
      "actions": ["bedrock-agentcore:CreateAgentRuntime"],
      "resource_types": ["AWS::BedrockAgentCore::AgentRuntime"],
      "assessment_gap_ids": [],
      "security_rationale": "...",
      "framework_keywords": ["encryption", "key management"]
    }
  ],
  "control_summary": {
    "total_controls": 60,
    "by_scope": { "ORG": 14, "ACC": 27, "RES": 19 },
    "by_category": { "PRV": 20, "PRO": 10, "DET": 18, "COR": 12 },
    "by_mechanism": { "SCP": 10, "AWS Config Rule": 12 }
  },
  "mitigation_coverage": {
    "total_mitigations": 37,
    "covered": 37,
    "uncovered": 0,
    "uncovered_ids": []
  },
  "assessment_gap_coverage": {
    "total_gaps": 13,
    "covered": 10,
    "uncovered": 3,
    "uncovered_ids": ["GAP-3", "GAP-7", "GAP-11"]
  }
}
```

---

## Validate Output

Output validation runs automatically via PostToolUse hook (validate_state.py Check S11).

## Print Summary

```
Map (Generate Controls) complete:
  Controls: {total} ({by_scope}, {by_category})
  Mitigations covered: {covered}/{total} (100%)
  Assessment gaps covered: {covered}/{total}
  Output: .service-approval/state/map-controls-generated.json
```
