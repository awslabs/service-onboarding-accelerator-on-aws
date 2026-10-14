---
name: research-mitigations
description: Parse input files to extract existing mitigations, build initial asset inventory, and collect assessment gaps. Produces research-mitigations.json consumed by the research merge step.
disable-model-invocation: false
argument-hint: '[./input-folder] [--service=<name>]'
---

# Service Approval — Researcher: Mitigations & Assets

Parse customer-provided input files to extract existing mitigations, build an initial asset
inventory, and collect assessment gaps from the CAF assessment phase.

**Output:** `.service-approval/<slug>/02-research/research-mitigations.json`
**Schema:** `schemas/research-mitigations.schema.json` — encodes `phase: "research-mitigations"` const, mitigation `id` pattern `^M-.+`, assessment-gap `id` pattern `^GAP-`, `assets_partial[].cfn_type` pattern `^AWS::`, and per-mitigation required fields (`id`, `mitigation_goal`, `statement`). `resource_type` is allowed on mitigations but assets MUST use `cfn_type` (see Step 3 and "Quality rules" below).

This is one of 3 focused research sub-skills. The orchestrator merges outputs from all 3
into the final `research.json`.

---

## Prerequisites

Per-service phase directory (`.service-approval/<slug>/02-research/`) is created dynamically using `tools/paths.py::phase_dir(slug, "research")`.

## Inputs

Parse arguments:
- `inputs.threat_model_file` — required, validated AWS Threat Model JSON export from intake
- `./input-folder` — optional additional `.md`, `.json`, `.xlsx`, `.pdf`, `.docx` files
- `--service=<name>` — AWS service identifier (e.g., `bedrock-agentcore`, `lambda`, `s3`)

You MUST run `python3 tools/validate/validate_threat_model_input.py --slug "<slug>"`
before extraction. On failure, STOP; do not emit an empty mitigation inventory.
Parse `inputs.threat_model_file` even when it is outside the input folder, exactly
once. Other files supplement it; an entity-nested report does not replace it.

---

## Step 1: Parse Input Files

Parse the export selected by `inputs.threat_model_file` first. Then parse optional
supporting files in the input folder, without processing the selected file twice.
Skip every other AWS Threat Model export, including older versions and models
for other services: only the selected export supplies the citation index and
authoritative model mitigations.

### JSON files (Mitigation Report)

Two JSON shapes are supported. **Detect the shape before iterating** — picking
the wrong branch silently drops every mitigation.

**Shape A — entity-nested:** the file's `entities[]` entries each carry their
own `mitigations[]` sub-array. For each entity, read `resource_type` and walk
its mitigations.

**Shape B — top-level (AWS Threat Model export):** the file has a top-level
`mitigations[]` array AND `entities[]` entries with NO `mitigations` sub-key.
Each top-level mitigation carries `alias`, `statement`,
`configurationRequestParameters[]` (each `{service, operation, paths[].path}`),
and `mappings[]` (entries `{type, id}` where `type` is one of `ENTITY`,
`THREAT`, `MITIGATION_GOAL`, `IMPLEMENTATION`). Recover `resource_type` for a
mitigation by following its `mappings[type=="ENTITY"].id` to the matching
`entities[].id` and using the entity's `entityType` (or
`AWS::<Service>::<entityType>` when an explicit CFN type is not present).

```python
import json
data = json.load(open("<file>"))

# Shape detector: top-level mitigations[] AND entities[] lack a mitigations sub-key
top_level_mits = data.get("mitigations") or []
entities = data.get("entities") or []
shape_b = bool(top_level_mits) and not any("mitigations" in e for e in entities)

if shape_b:
    # Build entity-id -> entity lookup for resource_type recovery
    entity_by_id = {e.get("id"): e for e in entities}
    for mit in top_level_mits:
        # Recover resource_type via the ENTITY mapping
        entity_id = next(
            (m["id"] for m in mit.get("mappings", []) if m.get("type") == "ENTITY"),
            None,
        )
        ent = entity_by_id.get(entity_id, {}) if entity_id else {}
        resource_type = ent.get("resource_type") or ent.get("entityType") or ""
        # Carry alias, statement, configurationRequestParameters[]:
        #   request_parameters can be flattened from
        #   mit["configurationRequestParameters"][i]["paths"][j]["path"]
        # Preserve alias and full statement; do NOT summarize or truncate.
else:
    # Shape A — walk entity-nested mitigations
    for entity in entities:
        resource_type = entity.get("resource_type", "")
        for mit in entity.get("mitigations", []):
            # Extract: id, statement, mitigation_goal, request_parameters[], resource_type
            pass
```

**Visible warning on silent-zero:** after parsing, if the input folder
contained one or more `.json` files but `existing_mitigations[]` is empty,
emit a `WARN` line to `pipeline.log` (e.g.
`skill:research-mitigations:warn input JSON yielded zero mitigations`). A
zero-count outcome from a non-empty input set is almost always a shape
mismatch, not a real empty mitigation list.

A reference parser implementing this detector lives at
`tools/validate/threat_model_parse.py` — covered by `test_threat_model_parse.py`.

#### AWS Threat Model citation index (Shape B only)

An AWS Threat Model export also carries a top-level `implementations[]` array — typed
control examples (preventive SCP / RCP / resource-based / declarative policy,
proactive CloudFormation Hooks, detective AWS Config rules / CloudTrail events).
Each implementation carries the exact governed actions + condition keys (or API
operations / resource properties) AND a REFERENCE link to the public AWS
documentation it is grounded in. This is the **first-priority citation source**
for every control family downstream: a control anchored to an AWS Threat Model
implementation cites that implementation's `alias` and links straight to its
public doc URL.

Persist the required export's normalized index so downstream
citation lookups and the citation validator resolve against one source of truth:

```python
import json, sys
sys.path.insert(0, "tools/validate")
from threat_model_parse import build_threat_model_index

data = json.load(open("<threat-model-file>"))
manifest = json.load(open(".service-approval/<slug>/00-intake/intake-manifest.json"))
index = build_threat_model_index(data, service="<service-name>",
                                 source=manifest["inputs"]["threat_model_source"])
with open(".service-approval/<slug>/02-research/threat-model-index.json", "w") as f:
    json.dump(index, f, indent=2)
```

`threat-model-index.json` (schema: `schemas/threat-model-index.schema.json`) holds the
normalized `mitigations[]` (alias + statement + cited REFERENCE links) and
`implementations[]` (behavior, mechanism, governed actions/keys, and the
REFERENCE `href`s), plus `threat_model_url` links to verified readable report
headings at the fetched commit. Preserve these links as a separate provenance
field; they do not replace capability-documentation `reference_links` or the
existing `_metadata.citation.url` verification rules. Writing the index is mandatory
for every pipeline run.
The recommender and the authoring /
detective / proactive skills read this file first when deciding each control's
citation.

Published `DIRECTIVE` implementations are process/configuration guidance. Preserve
these rows, their `guidance` prose, and readable links in the index. Do not treat a
DIRECTIVE row as evidence that an automated preventive/proactive/detective control
exists; normal capability verification and behavior matching still apply.

### Markdown files (Mitigation Report)

Mitigation reports (e.g. `input/<Service Name> — Mitigation Report.md`)
follow a consistent shape. Parse with the reference spec below — do NOT reinvent on
each run.

**Block delimiter:** each mitigation begins with a level-3 header of shape
`### M-<Entity>.<N> — <title>`. Regex:

```python
BLOCK_RE = re.compile(r"^### M-(?P<entity>[A-Za-z]+)\.(?P<n>\d+) — (?P<title>.+)$", re.MULTILINE)
```

Split the document at each header match; each block runs until the next header or EOF.

**Per-block table:** the first Markdown table inside each block has column 1 as a
bolded label and column 2 as the value. Parse rows keyed by the bolded label:

| Label (col 1)          | Output field           | Notes                                                |
|------------------------|------------------------|------------------------------------------------------|
| `**ID**`               | `id`                   | Prepend `M-` if absent (e.g. `Resource.0` → `M-Resource.0`) |
| `**Statement**`        | `statement`            | Full cell text, preserve sentences.                 |
| `**Mitigation Goal**`  | `mitigation_goal`      | Full cell text, preserve sentences.                 |
| `**Resource Type**`    | `resource_type`        | CFN type string (e.g. `AWS::Bedrock::Agent`).       |
| `**Request Parameters**` | `request_parameters[]` | Split on commas or Markdown list bullets; strip whitespace; JSON paths like `$.encryptionKeyArn`. |

Emit each parsed block as an `existing_mitigations[]` entry with the fields above
plus `source: "<report-basename>"` (e.g. `"source": "<Service Name> — Mitigation Report.md"`) so downstream runs can trace provenance.

**Row parsing pseudocode:**

```python
ROW_RE = re.compile(r"^\|\s*\*\*(?P<label>[^*]+)\*\*\s*\|\s*(?P<value>.+?)\s*\|$", re.MULTILINE)
label_map = {
    "ID": "id",
    "Statement": "statement",
    "Mitigation Goal": "mitigation_goal",
    "Resource Type": "resource_type",
    "Request Parameters": "request_parameters",
}
row_fields = {label_map[m.group("label").strip()]: m.group("value").strip()
              for m in ROW_RE.finditer(block)
              if m.group("label").strip() in label_map}
if "request_parameters" in row_fields:
    row_fields["request_parameters"] = [
        p.strip().lstrip("-* ").strip()
        for p in re.split(r",|\n", row_fields["request_parameters"])
        if p.strip()
    ]
```

**Rationale:** the reports are hand-curated in this exact shape. Parsing via this
spec takes ~20 lines of Python; re-inventing the parser has cost ~15 min of LLM
time on every cold-start run (confirmed across iter-13 and iter-14 runs). If a
new report deviates from this shape, prefer fixing the report over making the
parser tolerant of drift — uniform input shape keeps every downstream step
deterministic.

If the input filename ends in `.md` but the shape diverges significantly, fall
back to the previous bullet-point heuristic (mitigation IDs by pattern, statement
= text between IDs) and log a warning to `mcp-calls.log` noting the deviation.

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
      "alias": "<dotted alias when provided by source, e.g. Mitigation.LAMBDA.X.1>",
      "statement": "<full statement text — NOT truncated>",
      "mitigation_goal": "<full goal text — NOT truncated>",
      "request_parameters": ["$.encryptionKeyArn", "$.executionRoleArn"],
      "configuration_request_parameters": [
        {"service": "lambda", "operation": "CreateX", "paths": [{"path": "$.foo"}]}
      ],
      "resource_type": "AWS::<Service>::<Resource>"
    }
  ]
}
```

`alias` and `configuration_request_parameters` are populated only when the
source provides them (e.g. the AWS Threat Model top-level shape). The flat
`request_parameters[]` list MUST always be populated — for the AWS Threat Model shape,
flatten every `configurationRequestParameters[].paths[].path` into it.

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
      "trust_boundaries": [],
      "entry_points": [],
      "source": "mitigations"
    }
  ]
}
```

Do **not** emit a `data_classification` field. The sensitivity of the data a resource
handles is the customer's determination, not something the tool infers from mitigation
statements or capabilities.

The `trust_boundaries` and `entry_points` will be enriched by the capabilities and
api-surface sub-skills respectively.

---

## Step 4: Collect Assessment Gaps

Check if the `/assess` skill has produced artifacts:

```bash
test -f .service-approval/<slug>/01-assess/assessment-summary.md && echo "OK" || echo "not found"
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

Write `.service-approval/<slug>/02-research/research-mitigations.json`:

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

Output validation runs automatically via PostToolUse hook. The JSON Schema (see Schema above) hard-fails on phase-const mismatch, missing `id` / `mitigation_goal` / `statement` on any mitigation, `assets_partial[].cfn_type` not matching `^AWS::`, or any assessment-gap `id` not matching `^GAP-`. `validate_state.py::check_research_mitigations` delegates entirely to the schema — no additional hand-rolled checks remain.

## MITRE ATT&CK Threat Overlay

Enrich mitigations with MITRE ATT&CK technique mappings using `data/attack-cloud-matrix.json`
or the `mitre-attack` MCP:

1. Load the cloud matrix (Tactics: Initial Access → Impact, ~70 techniques)
2. For each mitigation, match its `category` and `description` keywords against technique
   names and descriptions
3. Assign `mitre_technique_ids` (e.g., `["T1078", "T1190"]`) to each mitigation
4. Add a `threat_overlay` section to the output:
```json
"threat_overlay": {
  "techniques_mapped": 18,
  "tactics_covered": ["Initial Access", "Execution", "Persistence", "Privilege Escalation"],
  "technique_to_mitigation": {"T1078": ["MIT-001", "MIT-003"], ...}
}
```

The threat overlay feeds into controls-catalog.md and the SUMMARY-REPORT.md threat coverage section.

## Print Summary

```
Research (mitigations) complete:
  Mitigations extracted:   {N}
  Assets identified:       {N}
  Assessment gaps:         {N}
  MITRE techniques:        {N} (or "skipped — no matrix file")
  Input files parsed:      {N}
  Framework file:          {path or "none"}
  Output: .service-approval/<slug>/02-research/research-mitigations.json
```
