---
name: intake
description: >
  Precursor intake phase for the Service Approval pipeline. Collects service name and input type.
  Produces intake-manifest.json consumed by all downstream phases.
  Supports file-based input (intake YAML) for repeatable, batch-friendly execution.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--threat-model-file=<path>] [--framework-specification=<text>] [--from-intake=<file>] [--interactive] [--no-mcp]"
---

# Service Approval — Intake

Collect and validate inputs before the pipeline begins. This phase runs before Phase 0
(Assess) and produces a manifest that configures the downstream pipeline.

## Required AWS Threat Model input — all intake modes

Real AWS Threat Model exports MUST remain local runtime inputs. NEVER commit or
upload them to the repository, copy them into tracked directories, or bundle them
with the plugin. Prefer an external `--threat-model-file` path and read it in
place. Keep model-derived runtime state under the ignored `.service-approval/`
tree. Repository tests may contain synthetic fixtures only.

You MUST obtain a matching AWS Threat Model JSON export before completing intake.
This applies to interactive, CLI, `--from-intake`, auto-discovered YAML, and resumed
runs for every service. Only local input collection may proceed before this gate;
do not invoke MCP or dispatch Assess/Research until it passes.

Resolve `--threat-model-file` (or YAML `input.threat_model_file`) first; otherwise
discover the export in the supplied input folder (YAML `input.folder`, default
`./input/`). Run the installed plugin's `tools/validate/validate_threat_model_input.py`:

```bash
python3 tools/validate/validate_threat_model_input.py \
  --service "<service>" --input-folder "<input-folder>"
```

Add `--threat-model-file "<path>"` for an explicit selection. Use an absolute
script path when the plugin is installed outside the working directory. Relative
input paths are resolved against the user's working directory in every mode,
including YAML intake; the YAML file's directory is not the path base.

The validator checks readable JSON, service identity in `metadata.name` /
`metadata.identifiers`, and non-empty top-level `entities`, `mitigations`, and
`threats` arrays with required record fields. Implementations are optional.
It does not establish authenticity or verify the model's AWS capability claims;
those claims still pass through Research/Validate.

On nonzero exit, STOP and request a valid matching export; non-interactive runs
must report the failure and stop. Never offer a skip/MCP-only/MITRE-only input
fallback or fabricate an export. Multiple matching exports require an explicit
selection. Framework and mitigation-report files alone do not satisfy the gate.
No flag, saved boolean (`input.threat_model: true`), or prior output bypasses it.

On success, persist the returned absolute path as `inputs.threat_model_file`,
set `inputs.has_custom_threat_model: true`, and include the selected path in
`inputs.input_files` with `type: "threat_model"`. Revalidate the written manifest
with `--manifest "<manifest-path>"` before handing it to Assess. All downstream
consumers MUST read this selected export, not rediscover the first JSON file.

---

## Background — What This Tool Does

The **Service Approval Pipeline** generates a complete set of AWS security controls for any
AWS service. It produces:

| Category | What you get |
|----------|--------------|
| **Proactive controls** | CFN Guard rules, CloudFormation hooks, Checkov policies, OPA policies |
| **Preventive controls** | SCPs, RCPs, declarative policies, permission boundaries, tag policies, resource policies, KMS key policies |
| **Detective controls** | AWS Config rules (with Lambda handlers), EventBridge rules, CloudWatch alarms, Access Analyzer configurations |
| **Responsive controls** | References to pre-authored AWS SSM Automation runbooks with how-to-use guides |
| **Framework mapping** | Controls mapped to CCMv4 objectives (other frameworks are out of scope for now) |
| **Threat model** | MITRE ATT&CK technique mapping with tactic coverage analysis (always included) |

The pipeline verifies every claim via MCP servers (no hardcoded training data), maps controls
to your chosen compliance framework, and produces recommended controls that you apply
yourself — each anchored to a published AWS reference.

**Typical output:** per-service files across 4 control categories (preventive,
proactive, detective, responsive), a framework coverage matrix, and a
final Summary Report.

---

## Input Modes

### Mode 1: Explicit intake file

```bash
service-approval --from-intake=path/to/my-service.yaml
```

Reads the YAML at the given path. No interactive prompts unless required fields
are missing. CLI flag wins over auto-discovery.

### Mode 2: Auto-discovered project intake (recommended for repeated runs)

If `./service-approval-intake.yaml` exists in the user's current working
directory, it is loaded automatically. The user is shown a summary and given
two choices: **[U]se as-is** or **[E]dit a field** (see "Existing Intake Flow"
below). This is the path most users hit on their second and subsequent runs.

### Mode 3: Interactive (first-time path)

When no intake YAML is found and no flags are provided, present the full intake
form. After the user confirms, **offer to save** the answers to
`./service-approval-intake.yaml` so the next run can auto-discover them.

### Mode 4: CLI flags

```bash
service-approval --service=s3 ./input --framework=ccmv4
```

All required fields provided via flags — no prompts needed. `--interactive`
forces the full prompt flow even when a YAML or manifest exists (escape hatch).

**`--no-mcp`** (default off): when present, record `pipeline_flags.no_mcp = true`
in the intake manifest. This is the single switch that puts every downstream
phase into **No-MCP mode** — facts are verified over the web (WebFetch/WebSearch
against the `rules/web-access.md` allowlist) instead of via MCP servers. MCP is
the default; only set this when the user passes `--no-mcp` (CLI) or `options.no_mcp:
true` (intake YAML). The flag is honored non-interactively and is not prompted for.

---

## Discovery Rules

Resolution order, highest priority first:

1. **`--from-intake=<path>` flag** — explicit, always honored.
2. **`./service-approval-intake.yaml` in CWD** — auto-discovered. Show summary,
   prompt `[U]se as-is / [E]dit`.
3. **None found** — fall through to the interactive form (first-time path).

**Plugin-repo guard:** Files inside the installed plugin directory
(`skills/intake/intake-template.yaml`, `skills/intake/defaults.yaml`, anything
under the plugin root) are **never** auto-loaded as user intake. They are
templates and org defaults, not user data. Reject any auto-discovery path that
resolves inside the plugin install dir; if `--from-intake` explicitly points
there, warn and refuse.

`--interactive` short-circuits steps 1 and 2 — always run the full prompt flow.

---

## Existing Intake Flow

When `./service-approval-intake.yaml` is found (and `--interactive` was not
passed), render a digestible summary and prompt:

```
┌─ Existing intake found: ./service-approval-intake.yaml ─┐
│  Service:        {friendly_name} ({service-id})         │
│  Framework:      {framework_type}                       │
│  ATT&CK Mapping: {Yes | No}                             │
└─────────────────────────────────────────────────────────┘

[U]se as-is   [E]dit a field   (default: U)
```

- **Use as-is** (default): revalidate the recorded AWS Threat Model file using the
  mandatory gate above, write and validate the manifest, then continue to Phase 0.
- **Edit a field**: walk the user through the intake fields one at a time with
  current values pre-filled. The user accepts each (Enter) or overrides. After
  edits, write the updated YAML back to `./service-approval-intake.yaml` and
  continue.

There is no "fresh start" option in this prompt. To start over, the user
deletes `./service-approval-intake.yaml` or passes `--interactive`.

---

## First-Time Save Prompt

After the interactive form completes (Mode 3), before writing the runtime
manifest, ask:

```
Save these answers to ./service-approval-intake.yaml so future runs skip
the prompts? (Y/n)
```

If yes, serialize the collected fields into the YAML schema from
`intake-template.yaml` and write to the user's CWD. Do **not** write into the
plugin repo.

---

## Environment-Adaptive Input Protocol

The form below is rendered **interactively** — one question at a time, waiting
for the user's answer before continuing. How you do that depends on what your
runtime offers. Pick the right branch on first use and stick with it for the
whole intake.

### Branch detection

| Signal | Branch |
|--------|--------|
| Your tool list includes `AskUserQuestion` (Claude Code) | Use **Branch A** |
| Your tool list includes any sanctioned blocking ask-user primitive (a future Kiro elicitation tool, an MCP elicitation tool, etc.) | Use **Branch A** with that tool's name in place of `AskUserQuestion` |
| Neither — you're in a chat pane (Kiro IDE, generic CLI, GitHub Copilot chat) | Use **Branch B** |

Do not invent a tool that isn't present. If unsure, fall through to Branch B.

### Branch A — Sanctioned ask-user tool available

For each question in "Intake Form Fields" below:

1. Call `AskUserQuestion` (or the equivalent primitive) **once** with that
   single question.
2. Use the question wording from this file verbatim as the `question` field.
3. Convert the question's enumerated choices into the tool's option list
   when the tool supports structured options; otherwise put the choices in
   the question text.
4. Do not bundle multiple questions into one call. One field per call.
5. Do not infer answers from earlier conversation context. If the user
   mentioned a value in passing, still ask — pre-fill it as the default
   option, but require an explicit selection.
6. Skip a question only when its value was supplied by a CLI flag or
   `--from-intake=<file>`. Announce the skip once
   ("Using `--service=s3` from CLI, skipping service prompt") then move on.

After all questions are answered, render the **User Confirmation** summary
(see that section below) and ask one final `AskUserQuestion` — "Proceed?
[Y/n]" — before any write to `intake-manifest.json`.

### Branch B — Chat-pane fallback (no blocking primitive)

Your runtime cannot pause the agent loop to wait for a typed reply. You must
enforce turn-taking yourself or you will silently commit the user to defaults
they never saw.

**Rules:**

1. **Ask one question per turn.** Never bundle questions.
2. **After asking, STOP.** End your turn with the literal marker:

   ```
   >>> WAITING FOR YOUR REPLY — I will not proceed until you answer.
   ```

   Do not call any further tool (`fs_read`, `fs_write`, `execute_bash`, MCP)
   in the same turn after this marker. The next user message is your only
   trigger to continue.
3. **Do not infer answers from earlier context.** If the user's opening
   prompt mentioned a value, re-ask explicitly with it pre-filled
   (e.g. "I see you mentioned S3 — confirm `s3`? [Y/n]").
4. **Do not skip ahead.** Only act on the question you just asked, even if
   the user volunteers extra info for later questions.
5. **Confirmed answers are locked.** Don't silently overwrite a previously
   acknowledged value during a later turn.
6. **The summary is a hard gate.** Before writing
   `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json`, render the
   "User Confirmation" summary box and end with:

   ```
   Type Y to write the manifest, N to revise, or "edit <field>" to change
   one field.

   >>> WAITING FOR YOUR REPLY — I will not write the manifest until you answer.
   ```

   A literal "Y" (case-insensitive) is the only trigger to write the file.
7. **Skip a question only on CLI-flag / `--from-intake` evidence.** Same
   rule as Branch A — announce the skip once, then move on.

### Question order (both branches)

1. Step 0 — Input folder and export location
2. Step 1 — Service name
3. Step 2 — Required AWS Threat Model and optional supporting inputs
4. Step 3 — Additional options
5. Final summary (always — never skipped)

---

## Intake Form Fields

Present this form when running interactively. Fields marked **(required)** must be answered.

### 0. Input folder and export location

Use the explicitly supplied folder or `./input/`. If it is missing and no
`--threat-model-file` was supplied, STOP and ask the user to provide the AWS
Threat Model JSON export for their service. Do not create an empty folder and
continue, seed a framework as a substitute, or download/fabricate a model.

An explicit export path can be outside the input folder. When supplied, continue
to collect the service name, then validate the file with the mandatory gate.
In non-interactive mode, missing input is an error that halts the run.

---

### 1. Service Name (required)

```
What AWS service should we generate security controls for?
Examples: s3, lambda, bedrock-agentcore-control, kms, ecs, dynamodb
```

- Accept any valid AWS service identifier (lowercase, hyphenated)
- If the user provides a friendly name (e.g., "Amazon S3"), normalize to the service ID (`s3`)
- Validate the service exists by checking `data/sar-slugs.json` for a matching entry

### 2. AWS Threat Model (required) and supporting inputs

```
Provide the path to the AWS Threat Model JSON export for this service.
The pipeline cannot continue without it.

You may also provide a control framework or an existing mitigation report.
```

- If the path was supplied by flag/YAML or exactly one matching export was
  discovered, run the mandatory gate without asking for the same path again.
- Record the input folder and the validated absolute `inputs.threat_model_file`.
- If a custom control framework is provided, detect the framework type:
  - Filename contains "CCMv4" or "ccm" → `ccmv4`
  - Any other framework filename (NIST, CIS, ISO) → warn and ignore;
    those frameworks are out of scope for the current pipeline.
- If no framework file is provided, leave `framework_type` unset
  (the user's intake reply determines whether CCMv4 is included).

### 3. Elaborate on your control framework (optional — only when a custom framework is provided)

**Skip this step entirely when no custom control framework was provided** (see §2 /
`has_custom_framework`). When one *is* provided, offer the user a chance to describe
it in their own words before mapping — this is free text with no required format, and
it helps the Map phase interpret non-obvious conventions:

```
You've provided a custom control framework. Would you like to add any details
about how it's structured before we map it? (optional — press Enter to skip)
For example: how control IDs and sub-control IDs are formatted, which column holds
the control text, how requirements are grouped, or which controls matter most.
```

**Inline / non-interactive:** the same text can be supplied directly on the invocation
with `--framework-specification "<free text>"` (or in the intake YAML as
`inputs.framework_specification`). When the flag is present, skip this prompt and
record its value verbatim.

- Record the text verbatim as `inputs.framework_specification` (a single string).
  Leave it `null` when no custom framework was provided or the user skips.
- Do not parse, validate, or reshape the text — pass it through untouched so the
  Map phase can read it alongside the framework file.

### 4. Additional Options (optional)

```
Additional options:
  [ ] Include MITRE ATT&CK threat mapping (adds ~15 min to pipeline)
  [ ] Generate artifact dependency matrix (ARTIFACT-FLOW-MATRIX.md)
```

---

## Output

**CRITICAL:** Intake runs BEFORE the canonical service slug is known (slug is derived by Phase 0 Assess from the SAR `service_prefix`). Therefore, intake writes to a staging directory indexed by timestamp.

Compute the staging timestamp:

```bash
STAGING_TS=$(date -u +"%Y-%m-%dT%H-%M-%SZ")
STAGING_DIR=".service-approval/_staging/${STAGING_TS}"
mkdir -p "${STAGING_DIR}/00-intake"
```

Or using Python:

```python
from datetime import datetime, timezone
from pathlib import Path
staging_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
staging_dir = Path(f".service-approval/_staging/{staging_ts}/00-intake")
staging_dir.mkdir(parents=True, exist_ok=True)
manifest_path = staging_dir / "intake-manifest.json"
```

Write to `.service-approval/_staging/<timestamp>/00-intake/intake-manifest.json`:

```json
{
  "schema_version": "2.1.0",
  "generated_at": "{ISO-8601 timestamp}",
  "staging_timestamp": "{STAGING_TS}",
  "service": {
    "name": "{service-name}",
    "friendly_name": "{AWS Service Friendly Name}",
    "sar_slug": "{slug from sar-slugs.json}",
    "service_prefix": "{IAM prefix}",
    "candidate_slug": "{lowercase, hyphenated service name from user input}"
  },
  "inputs": {
    "input_folder": "{path or null when an explicit export outside a folder is supplied}",
    "has_custom_threat_model": true,
    "threat_model_file": "{validated absolute path to the AWS Threat Model JSON export}",
    "has_custom_framework": true|false,
    "framework_type": "ccmv4 | null",
    "framework_file": "{path or null}",
    "framework_specification": "{customer's free-text description of their control format/structure, or null}",
    "has_mitigation_report": true|false,
    "input_files": [
      {"path": "...", "type": "threat_model|framework|mitigation_report|context"}
    ]
  },
  "output": {
    "include_attack_surface": true|false,
    "include_artifact_matrix": true|false
  },
  "pipeline_flags": {
    "service": "{service-name}",
    "input_folder": "{path or null}",
    "framework": "{type}",
    "framework_file": "{path or null}",
    "include_unverified": false,
    "clean": false,
    "no_mcp": false
  }
}
```

**Staging → Canonical Promotion:** Phase 0 (Assess) will atomically promote this staging directory to `.service-approval/<slug>/` after deriving the canonical slug from the SAR `service_prefix`. The promotion is described in Phase 0's Step 0b.

---

## User Confirmation

After collecting inputs, present a summary:

```
┌─────────────────────────────────────────────────────────────┐
│  SERVICE APPROVAL — Intake Summary                          │
├─────────────────────────────────────────────────────────────┤
│  Service:        {friendly_name} ({service-id})             │
│  Input:          {description of inputs}                    │
│  Framework:      {framework_type}                           │
│  Framework spec: {"provided" | "none"}                      │
│  ATT&CK Mapping: {Yes | No}                                 │
└─────────────────────────────────────────────────────────────┘

Proceed? (Y/n)
```

---

## Error Handling

| Condition | Action |
|-----------|--------|
| Service not found in `sar-slugs.json` | Warn user, attempt SAR page lookup via MCP. If found, continue. If not, halt. |
| `./input/` folder missing | Accept an explicit external export path, or stop and request the required AWS Threat Model. No empty-input fallback. |
| Plugin root cannot be located for seeding | Warn, disable choices [3] and [5], keep [1]/[2]/[4] available |
| CSA auto-download returns HTML / non-xlsx | Delete partial file, fall back to opening browser + printing URL, wait for user to drop file |
| Input folder path invalid | Ask user to correct the path |
| Intake YAML file not found | Fall back to interactive mode |
| Intake YAML missing required fields | Report which fields are missing, halt |

---

## Downstream Consumption

| Phase | What it reads from intake-manifest.json |
|-------|----------------------------------------|
| Phase 0 (Assess) | `service`, `inputs.input_folder`, `service.sar_slug`, `staging_timestamp` (to locate staging dir for promotion), `pipeline_flags.no_mcp` |
| Phase 1 (Research) | `service`, `inputs.*`, `output.include_attack_surface`, `pipeline_flags.no_mcp` |
| Phase 2 (Validate) | `service`, `pipeline_flags.no_mcp` |
| Phase 3 (Map) | `inputs.framework_type`, `inputs.framework_file`, `inputs.framework_specification` (optional customer guidance on control format/structure) |
| Phase 4 (Recommended Guidance) | `service`, `inputs.include_unverified`, `pipeline_flags.no_mcp` |
| Phase 5 (Summarize) | Full manifest for report metadata |

`pipeline_flags.no_mcp` (default `false`) is the single switch for **No-MCP
mode**: when `true`, the phases above verify facts over the web per
`rules/web-access.md` instead of calling MCP. See each skill's "No-MCP mode"
subsection.

---

## Print Summary

```
Intake complete:
  Service: {friendly_name} ({service-id})
  SAR slug: {slug}
  Inputs: {N} files ({types})
  Framework: {framework_type}
  Staging: .service-approval/_staging/{STAGING_TS}/00-intake/intake-manifest.json

Canonical service slug will be derived in Phase 0 (Assess).
Ready for Phase 0.
```
