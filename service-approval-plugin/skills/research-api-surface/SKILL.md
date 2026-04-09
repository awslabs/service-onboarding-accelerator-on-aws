---
name: research-api-surface
description: >
  Discover the complete API surface for an AWS service — all operations (control-plane AND
  data-plane), parameters, and cross-reference validation against SAR condition keys.
  Produces research-api-surface.json consumed by the research merge step.
disable-model-invocation: false
argument-hint: "[--service=<name>]"
---

# Service Approval — Researcher: API Surface

Retrieve the COMPLETE API reference for the target AWS service. Every operation from the
Service Authorization Reference must be captured — both control-plane AND data-plane.

**Output:** `.service-approval/state/research-api-surface.json`

This is one of 3 focused research sub-skills. The orchestrator merges outputs from all 3
into the final `research.json`.

---

## Prerequisites

```bash
mkdir -p .service-approval/state
touch .service-approval/state/mcp-calls.log
```

## Inputs

- `--service=<name>` — AWS service identifier (REQUIRED)

## Assessment & Capability Data

Check for data from sibling sub-skills and assessment phase:

```bash
test -f .service-approval/state/sar-facts.json && echo "SAR facts: OK" || echo "SAR facts: not found"
test -f .service-approval/state/research-capabilities.json && echo "Capabilities: OK" || echo "Capabilities: not found (running in parallel)"
```

**If `sar-facts.json` exists**: Use it as the authoritative action list. Every action
in the SAR page MUST appear in either `api_surface.operations[]` or as a permission-only
action. The SAR facts file gives you the complete action inventory to validate against.

**If `research-capabilities.json` exists**: Read `capabilities.iam.condition_keys[]` to
get the `applies_to_actions` lists for cross-reference validation. Also read
`capabilities.iam.permission_only_actions[]` to exclude those from the operations list.

If neither exists yet (running in parallel), you MUST read the SAR page directly via MCP
to get the action list and condition keys for validation.

---

## MCP Call Logging

Log every MCP call to `.service-approval/state/mcp-calls.log`:
```
[Step N] [API-Surface] <mcp-server> <tool-name> — <description> — <result-summary>
```
Append immediately after each call. Use `>>` mode.

---

## Step 1: Get the Authoritative Action List

Build the complete list of IAM actions for this service. This is your target — every action
must be accounted for.

**From sar-facts.json** (preferred):
```python
import json
sar = json.load(open('.service-approval/state/sar-facts.json'))
all_actions = [a['action'] for a in sar.get('actions', [])]
permission_only = sar.get('permission_only_actions', [])
api_actions = [a for a in all_actions if a not in permission_only]
```

**From MCP** (if sar-facts.json unavailable):
Use `awsknowledge` MCP to read the SAR page with FULL pagination:
- `start_index=0`, `start_index=30000`, `start_index=60000`, `start_index=85000`
- Extract ALL action names from the actions table
- Identify permission-only actions (those with no API operation)

Record the total action count — this is your completeness target.

---

## Step 2: Retrieve Full API Reference

Use `aws-documentation` MCP to read the API reference:

### 2a: CLI API Index Page
Read the CLI command reference index for the service. This gives you the complete list of
API operations organized by name.

```
Search: "<service> CLI command reference"
Read: CLI index page to get full operation list
```

### 2b: API Reference Pages
Read the service API reference documentation:

```
Search: "<service> API reference"
Read: API reference pages for operation details and parameters
```

### 2c: Data-Plane Operations
Many services separate control-plane and data-plane APIs. Explicitly search for:

```
Search: "<service> data plane API"
Search: "<service> runtime API"
```

Common data-plane patterns to look for:
- `Invoke*`, `Put*`, `Batch*`, `Start*`, `Stop*`, `Send*`
- `Get*` (read operations)
- `List*` (enumerate operations)
- `Create*` / `Delete*` for ephemeral resources (sessions, events, records)

---

## Step 3: Build Operations List

For EVERY API action (excluding permission-only actions), create an operation entry:

**CRITICAL — Field naming:** The operation name field MUST be `"operation"`, NOT `"action"`.
The downstream merge step and all consumers (Validate, Map, Generate) read
`api_surface.operations[].operation`. Using `"action"` as the key name will break
cross-reference validation and condition key completeness checks.

```json
{
  "operation": "CreateAgentRuntime",
  "parameters": [
    {
      "path": "$.agentRuntimeName",
      "type": "string",
      "required": true
    },
    {
      "path": "$.encryptionKeyArn",
      "type": "string",
      "required": false
    }
  ]
}
```

**Parameter extraction rules:**
- Include ALL parameters, not just security-relevant ones
- Use JSON path notation (`$.fieldName`)
- Mark `required: true/false` based on the API reference
- For nested parameters, use dot notation (`$.configuration.subnets`)
- Flag security-relevant parameters: encryption, auth, network, policy, tagging

**Completeness rule:**
After building the operations list, compare against the authoritative action list from Step 1.

Missing actions fall into 3 categories:
1. **Permission-only actions** — go in the capabilities `permission_only_actions[]` list (NOT here)
2. **API operations you missed** — add them with parameters from the API reference
3. **Actions with no documentation** — add with `"parameters": []` and a note

---

## Step 4: Cross-Reference Validation

This is the CRITICAL validation step that catches incomplete API surfaces.

### 4a: SAR Action Coverage
```
Total SAR actions:          {N}
Permission-only actions:    {N}
Expected API operations:    {N - permission_only}
Captured operations:        {N}
Missing:                    {list}
```

If missing > 0, go back to Step 2 and read additional API reference pages.

### 4b: Condition Key Cross-Reference

If condition keys are available (from capabilities sub-skill or SAR page):
- For each condition key's `applies_to_actions[]`, verify every action appears in either:
  - `operations[]` (as an operation name), OR
  - `permission_only_actions[]`
- Actions referenced by condition keys but missing from both lists = CRITICAL gap

```python
# Cross-reference check
condition_keys = [...]  # from capabilities or SAR
op_names = set(op['operation'] for op in operations)
poa = set(permission_only_actions)
all_known = op_names | poa

missing = set()
for ck in condition_keys:
    for action in ck.get('applies_to_actions', []):
        if action not in all_known:
            missing.add(action)

if missing:
    print(f'CRITICAL: {len(missing)} actions missing: {sorted(missing)}')
    # Must fix before proceeding
```

### 4c: Create Operation Coverage

Check that every `Create*` operation has corresponding CRUD operations:
- `Create*` → should also have `Get*`, `List*`, `Delete*`, `Update*` (where applicable)
- Missing CRUD operations may indicate data-plane gaps

---

## Step 5: Write Output

Write `.service-approval/state/research-api-surface.json`:

**CRITICAL — Output structure:** Operations MUST be nested under `api_surface.operations[]`,
NOT at the top level. Each entry MUST use the key `"operation"` (not `"action"` or `"name"`).
The merge step reads `data["api_surface"]["operations"]` — top-level `operations[]` will be
ignored and produce an empty API surface in research.json.

```json
{
  "phase": "research-api-surface",
  "service": "<service-name>",
  "api_surface": {
    "operations": [
      {
        "operation": "CreateAgentRuntime",
        "parameters": [
          { "path": "$.agentRuntimeName", "type": "string", "required": true }
        ]
      }
    ]
  },
  "completeness": {
    "sar_total_actions": 85,
    "permission_only_actions": 5,
    "expected_operations": 80,
    "captured_operations": 80,
    "missing_operations": [],
    "condition_key_cross_ref_pass": true,
    "missing_from_condition_keys": []
  },
  "doc_sources": ["https://docs.aws.amazon.com/..."]
}
```

## Output Verification

Output validation runs automatically via PostToolUse hook (validate_state.py Check S8).

## Print Summary

```
Research (API surface) complete:
  SAR total actions:       {N}
  Permission-only actions: {N}
  Expected operations:     {N}
  Captured operations:     {N}
  Missing operations:      {N}
  Condition key cross-ref: {PASS/FAIL}
  Doc sources:             {N}
  Output: .service-approval/state/research-api-surface.json
```
