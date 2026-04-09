---
name: research-mitigations
description: >
  Parse input files to extract existing mitigations, build initial asset inventory,
  and collect assessment gaps. Produces research-mitigations.json consumed by the
  research merge step.
disable-model-invocation: false
argument-hint: "[./input-folder] [--service=<name>]"
---

# Service Approval — Researcher: Mitigations & Assets

Parse customer-provided input files to extract existing mitigations, build an initial asset
inventory, and collect assessment gaps from the CAF assessment phase.

**Output:** `.service-approval/state/research-mitigations.json`

This is one of 3 focused research sub-skills. The orchestrator merges outputs from all 3
into the final `research.json`.

---

## Prerequisites

```bash
mkdir -p .service-approval/state
```

## Inputs

Parse arguments:
- `./input-folder` (optional) — read all `.md`, `.json`, `.xlsx`, `.pdf`, `.docx` files
- `--service=<name>` — AWS service identifier (e.g., `bedrock-agentcore`, `s3`, `lambda`)

If no input folder is provided, skip mitigation extraction (MCP-only mode — mitigations
will be empty). If no --service is provided, ask the user.

---

## Step 1: Parse Input Files

For each file in the input folder:

### JSON files (Mitigation Report)
Look for `entities` key containing mitigation arrays. For each entity:
- Extract resource type
- Extract mitigations with: id, statement, mitigation_goal, request_parameters
- Preserve the FULL statement and goal text — do NOT summarize or truncate

```python
import json
data = json.load(open("<file>"))
for entity in data.get("entities", []):
    resource_type = entity.get("resource_type", "")
    for mit in entity.get("mitigations", []):
        # Extract: id, statement, mitigation_goal, request_parameters[], resource_type
```

### Markdown files (Mitigation Report)
Extract mitigation IDs matching pattern `M-<Resource>.<N>`:
- Parse mitigation statement (full text between ID and next ID or section)
- Parse mitigation goal
- Extract request parameters (JSON paths like `$.encryptionKeyArn`)
- Associate with resource type from section headers

### XLSX files
Note as framework source file — record path for the Map skill. Do NOT parse framework
content here (that's the Map skill's job).

### PDF / DOCX files
Extract security-relevant content. Look for:
- Mitigation tables
- Security requirements
- Threat descriptions

### Other files
Read for context but do not extract structured data.

---

## Step 2: Build Existing Mitigations

Compile all extracted mitigations into a structured array:

```json
{
  "existing_mitigations": [
    {
      "id": "M-Resource.0",
      "statement": "<full statement text — NOT truncated>",
      "mitigation_goal": "<full goal text — NOT truncated>",
      "request_parameters": ["$.encryptionKeyArn", "$.executionRoleArn"],
      "resource_type": "AWS::<Service>::<Resource>"
    }
  ]
}
```

**Quality rules:**
- Every mitigation MUST have a non-empty `statement` field
- Every mitigation MUST have a non-empty `mitigation_goal` field
- **Truncation guard**: After extraction, verify `mitigation_goal` starts with an uppercase
  letter and forms a complete English phrase. If it starts lowercase or mid-word (e.g.,
  `"ulti-AZ"` instead of `"Multi-AZ"`), the extraction truncated — re-extract from source.
- `request_parameters` must be JSON paths (starting with `$.`)
- `resource_type` should use CloudFormation format (`AWS::<Service>::<Resource>`)
- Preserve ALL mitigations — do not deduplicate or merge similar ones

---

## Step 3: Build Initial Asset Inventory

From the mitigations, derive an initial asset list. Each unique `resource_type` becomes
an asset entry:

```json
{
  "assets_partial": [
    {
      "name": "<ResourceName>",
      "cfn_type": "AWS::<Service>::<Resource>",
      "data_classification": "<from mitigation context — what data does this resource handle?>",
      "trust_boundaries": [],
      "entry_points": [],
      "source": "mitigations"
    }
  ]
}
```

Derive `data_classification` from the mitigation statements — what do they describe the
resource as storing/processing? If unclear, set to `"<needs enrichment from capabilities>"`.

The `trust_boundaries` and `entry_points` will be enriched by the capabilities and
api-surface sub-skills respectively.

---

## Step 4: Collect Assessment Gaps

Check if the `/assess` skill has produced artifacts:

```bash
test -f .service-approval/state/assessment-summary.md && echo "OK" || echo "not found"
```

If `assessment-summary.md` exists:
- Parse each `[DOMAIN_GAPS] Compliance Matrix` table
- For every row with status `REQUIREMENT GAP`, `CUSTOMER ACTION REQUIRED`, or `PARTIALLY SUPPORTED`:
  - Record in `assessment_gaps[]` with: domain, requirement, status, details

```json
{
  "assessment_gaps": [
    {
      "domain": "IAM|LOGGING|INFRA|DATA|INCIDENT",
      "requirement": "...",
      "status": "REQUIREMENT GAP|CUSTOMER ACTION REQUIRED|PARTIALLY SUPPORTED",
      "details": "..."
    }
  ]
}
```

If assessment-summary.md does not exist, set `assessment_gaps` to an empty array.

---

## Step 5: Write Output

Write `.service-approval/state/research-mitigations.json`:

**CRITICAL — Field Name Enforcement:**
- The top-level key MUST be `"phase"` (not `"skill"`, not `"stage"`)
- Each `assets_partial[]` entry MUST use `"cfn_type"` (not `"resource_type"`) and `"name"` (not `"display_name"`)
- These exact field names are required for the merge step to work correctly

```json
{
  "phase": "research-mitigations",
  "service": "<service-name>",
  "existing_mitigations": [...],
  "assets_partial": [
    {
      "name": "<ResourceName>",
      "cfn_type": "AWS::<Service>::<Resource>",
      "data_classification": "...",
      "trust_boundaries": [],
      "entry_points": [],
      "source": "mitigations"
    }
  ],
  "assessment_gaps": [...],
  "input_files_parsed": ["<file1>", "<file2>"],
  "framework_file": "<path-to-xlsx-if-found>"
}
```

## Output Verification

Output validation runs automatically via PostToolUse hook (validate_state.py Check S6).

## Print Summary

```
Research (mitigations) complete:
  Mitigations extracted:   {N}
  Assets identified:       {N}
  Assessment gaps:         {N}
  Input files parsed:      {N}
  Framework file:          {path or "none"}
  Output: .service-approval/state/research-mitigations.json
```
