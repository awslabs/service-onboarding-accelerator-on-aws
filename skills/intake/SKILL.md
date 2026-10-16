---
name: intake
description: >
  Precursor intake phase for the Service Approval pipeline. Collects service name and input type.
  Produces intake-manifest.json consumed by all downstream phases.
  Supports file-based input (intake YAML) for repeatable, batch-friendly execution.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--framework-specification=<text>] [--from-intake=<file>] [--interactive] [--no-mcp]"
---

# Service Approval — Intake

Collect and validate inputs before the pipeline begins. This phase runs before Phase 0
(Assess) and produces a manifest that configures the downstream pipeline.

## Published AWS Threat Model prerequisite — all intake modes

For a NEW run, you MUST retrieve the latest matching model from the public
[Threat Models for AWS Services](https://github.com/aws/threat-models-for-aws-services)
release before completing intake. This applies to interactive, CLI, and YAML
new runs. A resumed run reuses its existing runtime manifest and snapshot; do not
fetch or replace it. Do not dispatch Assess/Research or perform MCP preflight until the
gate passes. Service availability comes from the live release manifest, never a
bundled service list or `data/sar-slugs.json`.

After collecting the requested service, run the installed plugin's helper
(use its absolute script path when installed outside the working directory):

```bash
python3 tools/validate/fetch_threat_model.py --service "<service>" \
  --output ".service-approval/_sources/selected-inputs.json"
```

The helper resolves current `main`, follows the release manifest's data/report
paths at that commit, verifies SHA-256 hashes, validates service metadata and the
consumed JSON shape, and checks readable report headings. It emits an **inputs
fragment**, not an intake manifest. Merge its `threat_model_file`,
`threat_model_source`, and `has_custom_threat_model` fields into intake's `inputs`
without changing them. Add the downloaded absolute path to `inputs.input_files`
as `type: "threat_model"`. The legacy `has_custom_threat_model` field means a
model is present; the source is now AWS's public release.

The snapshot lives in its own unique directory under ignored
`.service-approval/_sources/<commit>/`, outside
the staging directory so promotion to the canonical slug does not break its
absolute path. Do not commit downloaded models or derived runtime state; use
synthetic fixtures in tests. Optional supporting files still come from the input
folder. A missing input folder is acceptable when no supporting file was requested.

On JSON model retrieval, hash, identity, format, or service availability errors,
STOP. Readable-report and internal-reference defects are advisory: surface the
helper warnings, continue with usable JSON, and preserve the findings in the
source provenance. No acceptance flag or confirmation is required. Do not fall back to local files, stale snapshots, MITRE-only input, or a
fabricated model. `--threat-model-file` and YAML `input.threat_model_file` are no
longer supported as input overrides: report that the model must be fetched from
AWS and stop if one was explicitly supplied. Files in the input folder cannot
authorize an unsupported service. Model capability claims still require the
normal Research/Validate verification.

Validate the completed staging manifest before handing it to Assess:

```bash
python3 tools/validate/validate_threat_model_input.py --manifest "<manifest-path>"
```

For an existing runtime manifest, run the same local validation command before
resuming. It rechecks the original snapshot hash and never reads upstream.
Upstream changes or outages do not affect the run. Missing or altered local bytes
halt the run; restore the exact original snapshot or explicitly start a new run.
See [source lifecycle](../../docs/THREAT-MODELS.md).

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

- **Use as-is** (default): fetch the latest published AWS Threat Model using the
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

1. Step 0 — Optional supporting input folder
2. Step 1 — Service name
3. Step 2 — Published AWS Threat Model and optional supporting inputs
4. Step 3 — Additional options
5. Final summary (always — never skipped)

---

## Intake Form Fields

Present this form when running interactively. Fields marked **(required)** must be answered.

### 0. Optional supporting input folder

Use the explicitly supplied folder or `./input/` for optional supporting documents.
A missing default folder is acceptable. If an explicitly supplied supporting folder
or file does not exist, report that input error rather than silently ignoring it.
Keep user documents in the ignored `input/`, `inputs/`, `input-*/`, `input_*/`, or
`runs/` workspace conventions, or use a path outside the repository. Only the
shipped `input/CCMv4-sample.xlsx` and `input/sar-slugs.json` belong in Git; do not
overwrite those examples with customer content or force-add runtime inputs.
Relative input paths resolve from the working directory, not the YAML location.
Do not request or create a local threat
model: intake retrieves it from the published AWS release after the service is known.

---

### 1. Service Name (required)

```
What AWS service should we generate security controls for?
Examples: s3, lambda, bedrock-agentcore-control, kms, ecs, dynamodb
```

- Accept any valid AWS service identifier (lowercase, hyphenated)
- Pass friendly names or service identifiers to the fetch helper; it matches model metadata.
- Use the returned namespace. Do not reject a newly published service because it is absent from the bundled SAR slug map; Assess discovers SAR after this gate.

### 2. Published AWS Threat Model and supporting inputs

Run the mandatory retrieval gate above without asking the user for a model file.
Show the resolved namespace and published source link. Record the returned inputs
fragment and optional supporting folder. An explicit `--framework-file` is the
authoritative customer framework. Detect its identity from the file and record
`framework_type: custom` when it is not a recognized built-in framework. Preserve
the customer's IDs and wording; do not substitute CCMv4 for a supplied custom
file. Map evaluates custom objectives directly against AWS Threat Model-backed
controls; optional CCM guidance matches do not determine coverage or uncertainty.
Leave the framework type unset when none was supplied.

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
    "input_folder": "{optional supporting folder or null}",
    "has_custom_threat_model": true,
    "threat_model_file": "{downloaded absolute snapshot path}",
    "threat_model_source": {"...": "copy the helper output object verbatim"},
    "has_custom_framework": true|false,
    "framework_type": "ccmv4 | nist | cis | iso | custom | null",
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
| Service absent from published manifest | Stop. Local exports and flags cannot bypass availability. |
| `./input/` folder missing | Continue with published model retrieval; supporting inputs are optional. |
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
