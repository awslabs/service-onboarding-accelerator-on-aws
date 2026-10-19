---
name: research-attack-surface
description: Identify applicable threat techniques for the target service based on API surface analysis and MITRE ATT&CK Cloud matrix (always runs). Enriched by customer threat model input (MITRE ATT&CK, STRIDE, or custom) when available. Produces research-attack-surface.json consumed by the research merge step.
disable-model-invocation: false
argument-hint: '[--service=<name>]'
---

# Service Approval — Research: Threat Attack Surface

Identify which MITRE ATT&CK threat techniques are applicable to the target AWS service.
This step is **mandatory** — it always runs for every service onboarding. Supports
enrichment from multiple threat model formats:

- **MITRE ATT&CK** (xlsx, json) — maps to ATT&CK Cloud techniques and tactics
- **STRIDE** (md, docx) — maps customer STRIDE categories to techniques
- **Custom threat catalogs** (xlsx, json, md) — any structured threat list with IDs and categories

Every pipeline run requires the matching AWS Threat Model export selected by
`inputs.threat_model_file` in intake. You MUST run
`python3 tools/validate/validate_threat_model_input.py --slug "<slug>"` before
analysis and STOP on failure. Read that selected file even when it is outside the
input folder. Additional MITRE ATT&CK, STRIDE, or custom documents enrich it;
none replaces the required export. Use the service API surface and capabilities
to supplement the exported threats with MITRE ATT&CK Cloud analysis.

**Input:** SAR facts, customer threat model (from input folder, if available), reference data
**Output:** `.service-approval/<slug>/02-research/research-attack-surface.json`

This is one of 4 focused research sub-skills. Each writes to a separate intermediate
state file. This sub-skill is **mandatory** — the pipeline requires MITRE ATT&CK threat
analysis for every service.

---

## Threat Model Detection

Read the selected AWS Threat Model first, then scan the input folder for optional
supplementary threat documents. Detection rules:

| File Pattern | Threat Model Type | Processing |
|---|---|---|
| JSON file with TOP-LEVEL `threats[]` AND `mitigations[]` | AWS Threat Model export (custom) | Ingest the `threats[]` entries verbatim; cross-link via `mappings[].id` to the file's `entities[]` and `mitigations[]` for context |
| `*MITRE*`, `*ATT&CK*`, `*attack*` (xlsx/json) | MITRE ATT&CK | Parse enterprise/cloud matrix techniques |
| `*STRIDE*`, `*threat*model*` (md/docx) | STRIDE | Extract 6 STRIDE categories |
| `*threat*catalog*`, `*threat*register*` (xlsx/json) | Custom | Parse ID, name, category, severity columns |
| Mitigation report with STRIDE keywords | STRIDE (implicit) | Extract from mitigation context |
| **Required AWS Threat Model missing/invalid** | **Prerequisite failure** | **STOP; return to Intake for published model retrieval** |

**AWS Threat Model detector (must run BEFORE the MITRE default):** for every `.json`
file in the input folder, peek at its top-level keys. If the file has both a
top-level `threats[]` array AND a top-level `mitigations[]` array, treat it
as an AWS Threat Model export and ingest the threats directly. Each AWS Threat Model threat
carries `alias`, `source`, `prerequisites`, `threatAction`, and
`requestParameters[]` — these are the fields to record. Without this
detector, the file falls through to the MITRE default branch and the
threat list is silently dropped. Reference detector at
`tools/validate/threat_model_parse.py::is_threat_model_threats_shape`.

Merge optional MITRE, STRIDE, and custom catalogs as supplementary context.
Skip other AWS Threat Model exports, including alternate versions of the selected
service's model; only `inputs.threat_model_file` supplies the authoritative graph.

**MITRE enrichment always runs after the required export is ingested.** The
MITRE MCP or bundled cloud matrix supplements the service model; absence of
additional STRIDE/MITRE documents is acceptable, absence of the required export
is not. Do not merge another service's export into the selected service model.

Record the detected threat model in the output:
```json
{
  "attack_matrix_version": "<version from file or 'custom'>",
  "attack_matrix_source": "<filename>",
  "threat_model_type": "<mitre_attack|stride|custom|hybrid>",
  "threat_model_name": "<display name for output titles>"
}
```

**Threat model name rules (CRITICAL for output titles):**

The `threat_model_name` field flows into the SUMMARY-REPORT.md section title and the
print summary. Set it using these rules:

| Source | `threat_model_name` value | Example output title |
|--------|--------------------------|---------------------|
| Default MITRE data file (`data/attack-cloud-matrix.json`) | `"MITRE ATT&CK"` | "MITRE ATT&CK Threat Coverage (v16.1)" |
| Customer file with "MITRE" or "ATT&CK" in name | `"MITRE ATT&CK"` | "MITRE ATT&CK Threat Coverage (v{version})" |
| Customer file with "STRIDE" in name | `"STRIDE"` | "STRIDE Threat Coverage" |
| Customer file that doesn't match known patterns | `"Custom Threat Model"` | "Custom Threat Model Coverage ({filename})" |
| Hybrid (multiple sources merged) | `"MITRE ATT&CK + STRIDE"` or `"MITRE ATT&CK + Custom"` | "MITRE ATT&CK + STRIDE Threat Coverage" |

---

## Prerequisites

```bash
mkdir -p .service-approval/<slug>/02-research
```

Load reference data (used for MITRE ATT&CK mapping — skip if custom-only):
```bash
test -f data/attack-cloud-matrix.json && echo "attack-matrix: OK" || echo "WARN: no ATT&CK reference (custom mode)"
test -f data/stride-to-attack-bridge.json && echo "stride-bridge: OK" || echo "WARN: no STRIDE bridge"
test -f data/attack-nist-ccm-crosswalk.json && echo "crosswalk: OK" || echo "WARN: no crosswalk"
```

If SAR facts exist from Phase 0, load them:
```bash
test -f .service-approval/<slug>/01-assess/sar-facts.json && echo "sar-facts: OK" || echo "sar-facts: not found (will use --service flag)"
```

---

## MCP call logging

**Required: emit canonical `mcp:<server>:call` events to `pipeline.log` after EVERY MCP tool invocation** (including `mitre-attack` MCP calls). The Stop hook's P1 check anchors on the `[mcp:<server>:call]` token. The `_hook_log` auto-mirror copies canonical events into `mcp-calls.log` for free.

After each MCP call, run:

```bash
python3 -m tools.validate.log \
    --slug <slug> \
    --phase 02-research \
    --source mcp:<server> \
    --verdict call \
    --message "<tool-name>: <one-line description>"
```

Substitute `<server>` with the MCP server name (`mitre-attack`, `awsknowledge`, `aws-documentation`). When the bundled snapshot is used, emit no MCP event. Log `skill:research-attack-surface:pass` for the normal default (optional server not configured), or `skill:research-attack-surface:retry` if an enabled server failed. Missing optional configuration is not an error.

## No-MCP mode

**MCP is the default.** When the run is in No-MCP mode
(`pipeline_flags.no_mcp == true` in `00-intake/intake-manifest.json`, set by the
`--no-mcp` flag), the reference-data preference order in
Step 2.1 shifts: instead of the `mitre-attack` MCP, fetch ATT&CK data over the
web per [`rules/web-access.md`](../../rules/web-access.md) — `WebFetch`
`https://attack.mitre.org/matrices/enterprise/` and per-technique
`https://attack.mitre.org/techniques/T<id>/` — and if `attack.mitre.org` is
unreachable, fall back to the bundled `data/attack-cloud-matrix.json` snapshot
exactly as before. For supporting AWS threat context, use the discovery→verify
loop (open `WebSearch`, then `WebFetch` the authoritative `docs.aws.amazon.com`
page). Log each web lookup with `--source web:attack-mitre --verdict fetch` (or
`--source web:search --verdict search` for a discovery query) instead of the
`mcp:mitre-attack:call` event; these `web:*` events satisfy the same P1 call
floor.

---

## Step 1: Parse Customer Threat Model (if provided)

Scan input files for threat model content. Look for:
- Files with "threat" in the filename
- Files containing STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Mitigation reports that reference threat categories

For each STRIDE category found, extract:
- Which mitigations reference it (by mitigation ID if available, or by keyword)
- Indicator phrases that signal this threat type

Build `customer_stride_profile`:
```json
{
  "Spoofing": {
    "mitigations_referenced": ["M-AgentRuntime.0", "M-AgentRuntime.9"],
    "indicators": ["confused deputy", "role assumption", "principal trust"]
  }
}
```

**If no supplementary STRIDE content exists**, leave `customer_stride_profile` empty `{}`.
The auto-derivation in Step 2 still runs.

---

## Step 2: Auto-Derive Attack Surface from Service API

This enrichment step always runs after the mandatory AWS Threat Model input gate passes.

### 2.1 Load reference data

ATT&CK technique data has two sources, in preference order:

1. **`mitre-attack` MCP** (live MITRE ATT&CK knowledge base, source:
   https://github.com/stoyky/mitre-attack-mcp). Optional and disabled by default.
   Use it only when the user has configured it. Query technique details,
   sub-techniques, and tactic relationships. Do not install or require it.
2. **`data/attack-cloud-matrix.json`** (bundled snapshot, schema_version 1.0,
   ATT&CK 16.1). Default when the optional MCP is not configured; also the fallback on failure.
   Always present in the repo, so this branch always works.

```python
import json

# The agent sets mitre_mcp_enabled from the user's MCP configuration.
# Do not attempt an MCP call when the optional server is not configured.
cloud_matrix = None
if mitre_mcp_enabled:
    try:
        # mitre-attack MCP exposes get_techniques / get_tactics / get_technique_by_id
        # Pseudocode — the agent should issue actual MCP tool calls here.
        cloud_matrix = mcp_call("mitre-attack", "list_techniques",
                                 {"matrix": "enterprise-attack",
                                  "platforms": ["IaaS", "SaaS", "Identity Provider"]})
    except Exception as e:
        # MCP unavailable (server didn't spawn, timed out, etc.) — fall back
        print(f"mitre-attack MCP unreachable ({e}); using bundled snapshot")

# Fallback: bundled JSON
if not cloud_matrix:
    cloud_matrix = json.load(open('data/attack-cloud-matrix.json'))

stride_bridge = json.load(open('data/stride-to-attack-bridge.json'))
crosswalk = json.load(open('data/attack-nist-ccm-crosswalk.json'))
```

The bundled JSON's structure (tactics → techniques) is the canonical shape every
downstream step expects. If the MCP returns a different shape, normalize it to
match `attack-cloud-matrix.json` before continuing — do NOT rewrite the consuming
steps.

Record the source in the output for provenance:

```json
{
  "attack_matrix_source": "mitre-attack-mcp" | "bundled-snapshot",
  "attack_matrix_version": "<MCP version string OR '16.1' for snapshot>"
}
```

### 2.2 Analyze service API patterns

If SAR facts exist, extract API operations. Otherwise use the `--service` flag to
identify the service. Map API action patterns to ATT&CK techniques:

For each ATT&CK technique below, mark `applies` (the service has the API
pattern in its surface) or `does-not-apply` (no matching pattern, or the
pattern is gated such that the technique cannot reach the service). State the
rationale verbatim from the API surface — do not assign numeric or level
scores.

| API Action Pattern | ATT&CK Technique | Rationale |
|---|---|---|
| `Create*` with IAM role parameter | T1078.004 (Cloud Accounts) | Service uses assumable roles — credential compromise enables access |
| `PutResourcePolicy`, `SetResourcePolicy` | T1098 (Account Manipulation) | Resource policies can be modified to grant unauthorized access |
| `Delete*` any resource | T1485 (Data Destruction) | Resources can be deleted to disrupt service |
| Data-plane `Invoke*`, `Get*` on user content | T1530 (Data from Cloud Storage) | Data-plane reads expose customer content |
| Encryption parameter is optional (not required) | T1530 (Data from Cloud Storage) | Unencrypted data is exposed at rest |
| Public endpoint available (no VPC-only mode) | T1190 (Exploit Public-Facing App) | Public endpoints are attack surface |
| VPC mode optional | T1190 (Exploit Public-Facing App) | Network perimeter not enforced |
| `Tag*`, `Untag*` operations | T1565 (Data Manipulation) | Tag manipulation enables classification evasion |
| Cross-account role trust | T1199 (Trusted Relationship) | Cross-account trust enables lateral movement |
| `*CredentialProvider*`, `*Token*` operations | T1528 (Steal Application Access Token) | Credential material in the service |
| `*WorkloadIdentity*`, `*OAuth*` operations | T1556 (Modify Authentication Process) | Authentication config can be tampered with |
| Streaming/logging to external services | T1537 (Transfer Data to Cloud Account) | Data channels can be redirected |

### 2.3 Cross-reference with STRIDE bridge

For each identified technique, check if the corresponding STRIDE category appears in
the customer profile. If yes, record that alignment in the technique's
`stride_categories` field — do not adjust an applicability score.

### 2.4 Build applicable techniques list

Include a technique when **any** of the following hold:
- Its API pattern matches the service's verified API surface
- The corresponding STRIDE category appears in the customer threat profile

Mark each technique either `"HIGH"` (direct API pattern match) or `"MEDIUM"`
(indirect pattern, e.g., bridge from STRIDE without a direct API hit). Drop
techniques with no API match and no customer-profile alignment. Target:
15-25 applicable techniques per service.

---

## Step 3: Build STRIDE-to-ATT&CK Bridge Entries

Using `stride-to-attack-bridge.json`, for each STRIDE category in the customer profile
(or all 6 if no customer profile):

```json
{
  "stride_category": "Spoofing",
  "mitigations_referenced": ["M-AgentRuntime.0"],
  "attack_tactics": ["TA0001", "TA0006"],
  "attack_techniques": ["T1078", "T1078.004", "T1199"]
}
```

Only include techniques from the bridge that are also in the applicable_techniques list.

---

## Step 4: Build Tactic Coverage Summary

Group applicable techniques by ATT&CK tactic:

```json
{
  "TA0001": {
    "name": "Initial Access",
    "technique_count": 3,
    "applicability_high": 2,
    "applicability_medium": 1,
    "techniques": ["T1078.004", "T1190", "T1199"]
  }
}
```

---

## Step 5: Write Output

Write `.service-approval/<slug>/02-research/research-attack-surface.json`:

```json
{
  "phase": "research-attack-surface",
  "schema_version": "1.0",
  "service": "<service-name>",
  "attack_matrix_version": "16.1",
  "customer_stride_profile": {
    "Spoofing": {
      "mitigations_referenced": ["M-AgentRuntime.0"],
      "indicators": ["confused deputy", "role assumption"]
    }
  },
  "stride_to_attack_bridge": [
    {
      "stride_category": "Spoofing",
      "mitigations_referenced": ["M-AgentRuntime.0"],
      "attack_tactics": ["TA0001", "TA0006"],
      "attack_techniques": ["T1078", "T1078.004"]
    }
  ],
  "applicable_techniques": [
    {
      "technique_id": "T1078.004",
      "technique_name": "Cloud Accounts",
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "applicability": "HIGH",
      "applicability_reason": "Service uses IAM roles for execution (Create<Resource> $.roleArn). Confused deputy prevention required.",
      "api_surface_evidence": ["Create<Resource>", "Update<Resource>"],
      "stride_categories": ["Spoofing", "Elevation of Privilege"],
      "framework_controls": ["AC-2", "AC-3", "AC-6", "IA-2", "IA-5", "IA-8"],
      "framework_objectives": ["IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06", "IAM-12"]
    }
  ],
  "tactic_coverage_summary": {
    "TA0001": {
      "name": "Initial Access",
      "technique_count": 3,
      "applicability_high": 2,
      "applicability_medium": 1,
      "techniques": ["T1078.004", "T1190", "T1199"]
    }
  }
}
```

**Schema rules:**
- `phase` MUST be `"research-attack-surface"`
- `applicable_techniques` MUST be a non-empty array
- Every technique MUST have: `technique_id`, `technique_name`, `tactic_id`, `tactic_name`, `applicability`, `applicability_reason`, `api_surface_evidence`
- `technique_id` MUST match pattern `T\d{4}(\.\d{3})?`
- `applicability` MUST be `"HIGH"` or `"MEDIUM"` (LOW is filtered out)
- `framework_controls` and `framework_objectives` come from the active crosswalk data file (default: `data/attack-nist-ccm-crosswalk.json` for MITRE→CCMv4/NIST)
- `stride_categories` lists which STRIDE categories this technique maps to (from bridge)

---

## Validate Output

Output validation runs automatically via PostToolUse hook (validate_state.py Check S14).

## Print Summary

```
Research (ATT&CK Attack Surface) complete:
  Service: {service-name}
  ATT&CK matrix version: {version}
  Customer STRIDE profile: {N categories found | none}
  Applicable techniques: {N} (HIGH: {N}, MEDIUM: {N})
  Tactics covered: {N}/{total ATT&CK Cloud tactics}
  STRIDE bridge entries: {N}
  Output: .service-approval/<slug>/02-research/research-attack-surface.json
```
