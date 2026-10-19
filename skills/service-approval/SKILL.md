---
name: service-approval-v3
description: Orchestrate the service-approval agents (Intake → Assess → Research → Validate → Map → Recommended Guidance → Summarize) to generate AWS security controls for any AWS service
disable-model-invocation: false
argument-hint: '[./input-folder] [--service=<name>] [--questions=<file>] [--include-unverified] [--clean] [--framework=<ccmv4|nist|cis|iso>] [--framework-file=<path>] [--framework-specification=<text>] [--from-intake=<file>] [--interactive] [--no-mcp]'
---

# Service Approval — Orchestrator v3

Coordinate the service-approval agents to produce a complete set of AWS security controls
for any AWS service.

**Pipeline**: Intake → Assess → Research (4 sub-skills) → Validate → Map (4 sub-skills) → Recommended Guidance (2 sub-skills) → Summarize

The pipeline produces recommended security controls (preventive, detective,
proactive, and responsive guidance) that the customer applies themselves. It
does not deploy, test, or attest against a live account.

## Installed plugin and working directory

The caller's initial working directory owns all `.service-approval/` state.
The plugin installation owns bundled code, schemas, skills, and reference data.
Keep the working directory at the user's workspace when running packaged tools;
invoke scripts by absolute path under the plugin root and use that root on
`PYTHONPATH` for module commands. Do not change into the installation to make a
relative command work. If a helper must change directory, carry the original
absolute workspace in `SERVICE_APPROVAL_WORKSPACE`. `tools.paths.workspace_root`
resolves runtime output; `tools.paths.repo_root` continues to resolve assets.

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Optional supporting documents and control framework | `./input/` |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`) | Required if no folder |
| `--include-unverified` | Allow unverified items in generation | false |
| `--questions=<file>` | Path to SITCO Bar Questions file (.docx or .txt) — passed to Phase 0 | None |
| `--clean` | Clear the selected service’s phase output after retrieval and slug resolution; preserve source snapshots | false |
| `--framework=<type>` | Control framework type (ccmv4, nist, cis, iso) — passed to Map phase | auto-detect |
| `--framework-file=<path>` | Explicit path to framework file — passed to Map phase | auto-detect from input folder |
| `--framework-specification="<text>"` | Free-text description of a custom framework's structure (control/sub-control ID format, column layout, grouping) — recorded as `inputs.framework_specification` and read by the Map phase | None (only relevant with a custom framework) |
| `--from-intake=<file>` | Path to intake YAML — Intake reads this instead of prompting | None |
| `--interactive` | Force Intake's interactive form even when other flags would satisfy it | false |
| `--no-mcp` | Run without MCP servers — verify every fact over the web (WebFetch/WebSearch against the `rules/web-access.md` allowlist) instead of calling MCP. Threaded into `intake-manifest.json` as `pipeline_flags.no_mcp`; each phase follows its **No-MCP mode** fallback. | false (MCP is the default) |

## Agnosticism Guardrails (apply to every sub-skill)

This pipeline is explicitly **AWS-service-agnostic** and **control-framework-agnostic**. Every
skill, sub-skill, validator, and generated artifact MUST honor these rules. They are binding
on all agents executing any phase of the pipeline.

### Service agnosticism

1. **No hardcoded service names in generic skills.** The service name (`Amazon ECS`,
   `AWS Lambda`, `Amazon S3`, etc.) is ALWAYS a runtime argument passed via `--service=<name>`.
   It never appears as a literal in skill files, validator code, or rule descriptions — only
   in examples explicitly labeled as illustrative (e.g., "e.g. `ecs:Create*`"). Service
   prefixes in rule bodies must come from `validated.json` / `sar-facts.json`, not assumption.

2. **Service-specific data belongs in data files, not code.** Lookup tables (`sar-slugs.json`,
   consumer specs, CFN prefixes) MUST live as JSON/YAML data files that any service can
   extend. Code that iterates these files must emit a WARNING on an unknown key — never
   silently skip.

3. **Sub-skills must read service identifiers from state.** `validated.json` has `service`
   and `capabilities.iam.service_prefix`. Sub-skills must read both from there, not infer
   them. The SAR page is the ground truth for any service-specific fact.

### Framework agnosticism

1. **No hardcoded framework names or objective IDs in generic skills.** Framework domain
   names (`CEK-03`, `IAM-04`, `AC-2`, `CIS 1.1`) appear ONLY in `map-parse-framework` and
   `map-framework-mapping` skills, which dispatch on the `--framework=<type>` argument. Never
   in `generate-*` skills, never in validators.

2. **Customer framework is supplied at runtime.** Every pipeline run takes
   `--framework-file=<path>` pointing at a customer-provided file (xlsx/json/md). No
   framework ships bundled except as a schema/parser reference.

### No service-specific helper scripts

Agents executing any phase MUST NOT create service-specific helper scripts in `scripts/`,
`.service-approval/<slug>/`, or `service-approval-plugin/`. If a one-off computation is
needed:
- Keep it inline in the agent's task (Python `python3 -c "..."` or Bash)
- Or write it under `/tmp/` for the duration of the run
- Never commit or persist a file named `build-<service>-*.py`, `fix-<service>-*.sh`, or
  similar. Durable tooling belongs in the plugin's own `tools/` tree and must be generic
  across services.

### Enforcement

- Every generic skill in this pipeline MUST state its agnosticism in its own header if it
  adds any consumer/service logic. If it cannot be generic (e.g., `map-parse-framework`
  for CCMv4), it MUST be a dedicated sub-skill that dispatches on argument.
- If an agent notices a rule, table, or validator check that would need rewriting to run
  on a different AWS service or a different framework, flag it as a CONTRADICTS-AGNOSTICISM
  finding and stop until resolved.

---

## Pipeline Audit Log

**Every phase logs to a single consolidated file:**

```
.service-approval/<slug>/pipeline.log
```

This is the primary debugging artifact. Hooks (PostToolUse, Stop,
check_phase_complete), MCP calls, skill lifecycle (start/end/retry/halt),
and subprocess invocations all append to the same file in chronological
order. When something breaks, `tail -50 .service-approval/<slug>/pipeline.log`
shows the failure plus the last few causally-relevant events.

**Line format:**

```
<UTC-iso8601> [<phase>] [<source>:<verdict>]  <message> [k=v ...]
```

**Sources:**
- `hook:post-tool-use` / `hook:stop` / `hook:check-phase-complete` — validation hooks
- `mcp:<server>` — MCP calls (verdict `call` or `response`)
- `skill:<skill-name>` — skill lifecycle (verdict `start` / `end` / `retry` / `halt`)
- `script:<script-name>` — subprocess invocations (merge-domain-mappings.py, etc.)

**How skills emit events:**

Skills SHOULD log a `start` event at the top and an `end` (or `halt`) event
at the bottom — this is what makes `pipeline.log` useful for debugging
("which phase started, when did it finish, did it halt?"). Coverage is
being added to skills incrementally; today the canonical example is
`skills/map-assemble/SKILL.md`. Until every skill emits these events,
gaps in `pipeline.log` mean "skill ran without lifecycle logging," not
"phase didn't run." Use the bash CLI:

```bash
# At skill start:
python3 -m tools.validate.log --slug <slug> --phase <NN-phase> \
    --source skill:<skill-name> --verdict start \
    --message "<one-line summary of what this run will do>"

# At skill end:
python3 -m tools.validate.log --slug <slug> --phase <NN-phase> \
    --source skill:<skill-name> --verdict end \
    --message "<one-line summary of outcome>"

# When retrying (e.g. after a hook auto-fix):
python3 -m tools.validate.log --slug <slug> --phase <NN-phase> \
    --source skill:<skill-name> --verdict retry \
    --message "<reason>" --extra attempt=2
```

**Backward compatibility:** the old `mcp-calls.log` is still written as
a shadow file (whenever an `mcp:*` event lands in pipeline.log, it's
mirrored to `mcp-calls.log` too). Tools that grep `mcp-calls.log`
continue to work; new tooling should read `pipeline.log`.

---

## Prerequisites

### Mandatory published AWS Threat Model gate

Before MCP preflight or downstream work, distinguish a **new run** from a
**resume**. If this service has saved runtime intake and no explicit fresh-run
request (`--clean`), reuse that run and its manifest. Do not fetch, run fresh
Intake, replace the manifest, or rerun completed phases merely because the chat
resumed. Ambiguous service/run selection must be resolved before dispatch.

You MUST keep historical archives under `.service-approval/_archive/` outside
run selection. For a pre-upgrade run that cannot satisfy the current intake or
reporting checks, explain `python3 tools/archive_run.py --slug <slug> --reason
upgrade` and the [upgrade procedure](../../docs/THREAT-MODELS.md#upgrade-existing-workspaces).
Archive only a run the user explicitly wants to retire, then start a fresh run.
A finalized marker does not exempt an active run from P0/P14. You MUST preserve
the helper's `intake_verification` seal because it authenticates online intake;
do not replace it with caller-supplied publication claims.

For a NEW run only, follow Intake's prerequisite and run:

```bash
python3 tools/validate/fetch_threat_model.py --service "<service>" \
  --output ".service-approval/_sources/selected-inputs.json"
```

Copy the returned inputs fragment into Intake, retaining all source provenance.
The helper resolves current `main`, follows the release manifest, verifies the
JSON hash/identity/shape, and saves a unique snapshot. Fetch once per new run;
parallel sub-skills MUST NOT fetch independently. Unpublished services, failed
JSON retrieval, malformed JSON, wrong-service data, or a JSON hash mismatch stop
new intake. Local exports, flags, and MITRE data cannot substitute for a model.
Readable-report failures and dangling source references are ADVISORY: surface the
helper's findings and continue with the valid JSON. Never fabricate missing links.

Validate the staging manifest with `validate_threat_model_input.py --manifest
"<manifest-path>"`. During every later phase and on resume, validate ONLY the saved
snapshot, without contacting GitHub:

```bash
python3 tools/validate/validate_threat_model_input.py --slug "<slug>"
```

Upstream edits, removal, or outages do not affect an existing run. Missing or
modified local snapshot bytes remain a hard stop: restore the exact pinned bytes
or explicitly start a new run. Never replace a snapshot beneath prior outputs.
The deprecated `--refresh` validator flag is an offline compatibility alias.

After Research, Validate, Map, and after writing the final summary, run:

```bash
python3 tools/validate/audit_threat_model.py --slug "<slug>"
```

This recomputes source-to-stage mitigation accounting, writes the integrity JSON
and companion report, and inserts a concise source/processing appendix at the
end of framework mapping. It removes obsolete banners from the catalog and
summary. Warnings do not
stop the run. P14 rejects stale or omitted disclosure, not the existence of
findings. Use documented manual-guidance/not-applicable/unresolved dispositions
rather than inventing controls just to fill coverage. Keep alias/UUID pairs exact.

Explicit `--threat-model-file` / YAML input overrides remain unsupported. Input
folders contain optional supporting documents, not the authoritative model.
For `--clean`, fetch first, then clear only the selected service's phase tree at
Assess Step 0b. Preserve snapshots, new staging intake, and other services.
See [THREAT-MODELS.md](../../docs/THREAT-MODELS.md).

### MCP Pre-flight Check

After the AWS Threat Model gate passes, verify all required MCP servers are available. Run this check
automatically — do not ask the user. Install any that are missing.

Required MCPs (all from https://github.com/awslabs/mcp):

| Name | Transport | Endpoint / Command |
|------|-----------|-------------------|
| `awsknowledge` | HTTP | `https://knowledge-mcp.global.api.aws` |
| `aws-documentation` | stdio | `uvx awslabs.aws-documentation-mcp-server@1.1.28` |

`mitre-attack` is optional and omitted from default client configs. Do not install
or require it during preflight. Without user opt-in, use the bundled ATT&CK
snapshot. See [MCP configuration](../../docs/MCP.md).

**Step 1 — Detect environment** (reuse the same logic as Environment Detection below):
- `Agent` tool in tool list → Claude Code
- `KIRO_AGENT` env var set → Kiro
- `GITHUB_COPILOT` env var set → GitHub Copilot (VS Code)
- Otherwise → Generic (Aider, Continue, other)

**Step 2 — Check and install missing MCPs:**

**Claude Code:**
```bash
INSTALLED=$(claude mcp list 2>/dev/null)
for MCP in awsknowledge aws-documentation; do
  echo "$INSTALLED" | grep -q "$MCP" && echo "OK: $MCP" || echo "MISSING: $MCP"
done
```
For each MISSING entry, run the corresponding add command:
```bash
claude mcp add --transport http awsknowledge https://knowledge-mcp.global.api.aws
claude mcp add aws-documentation -- uvx awslabs.aws-documentation-mcp-server@1.1.28
```
After adding any MCP, inform the user: "Added missing MCP servers: <list>. They are now active."

**Step 3 — Handle MCPs that are registered but failing to connect:**
If any MCP is listed but shows "Failed to connect" or is unreachable, warn the user:
```
MCP degraded coverage:
  aws-documentation UNREACHABLE — Research and Validate will fall back to web search.
```
Do NOT block execution — continue with degraded coverage and note it in the final report.

**Kiro:**

> **Update (2026-05-18):** the Kiro CLI 2.0 (`kiro-cli`) install path was
> removed from `install.sh`. Path 1 below describes the legacy symlink
> install that is no longer wired automatically; Path 2 (manual IDE install
> via the Powers panel) is the supported flow today. Kiro CLI 2.0 may
> remain as a manually-installed runtime — the runtime decision is being
> re-evaluated.

Kiro has two install paths (see `install.sh`); MCP-config handling differs between them.

**Path 1 — Power install (CLI 2.0, recommended).** If the user installed via
`kiro-cli power install --local powers/service-approval`, the Power bundles its own
MCP config at `powers/service-approval/mcp.json` and registers it with Kiro
automatically. **Do NOT hand-edit `~/.kiro/settings/mcp.json`** — that would shadow or
duplicate the Power-bundled entries. Detect the Power install with:

```bash
kiro-cli power list 2>/dev/null | grep -q "service-approval" && echo "Power installed" || echo "Power NOT installed"
```

If the Power is installed:
- The MCPs are already wired via `powers/service-approval/mcp.json` (generated from
  `manifest.yaml` by `tools/sync-ide-configs.py`). No action needed at runtime.
- If MCPs appear unreachable in Kiro, instruct the user to run
  `kiro-cli power install --local <repo>/powers/service-approval` again to re-register
  the Power, then restart Kiro.

**Path 2 — Manual IDE install.** If the user installed by copying
`powers/service-approval/{steering,ide/*}` → `.kiro/` (the path `install.sh` falls back
to when `kiro-cli` is not available), Kiro reads `~/.kiro/settings/mcp.json` for MCP
config. Detect this path by:

```bash
test -d .kiro && ! kiro-cli power list 2>/dev/null | grep -q "service-approval" && echo "Manual install"
```

For each missing MCP under Path 2, add it to `~/.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "awsknowledge":       { "type": "http", "url": "https://knowledge-mcp.global.api.aws" },
    "aws-documentation":  { "command": "uvx", "args": ["awslabs.aws-documentation-mcp-server@1.1.28"], "env": {"FASTMCP_LOG_LEVEL": "ERROR", "AWS_DOCUMENTATION_PARTITION": "aws"} }
  }
}
```

Merge (do not overwrite existing entries). Write back the updated file.
After writing, inform the user: "Added missing MCP servers to
`~/.kiro/settings/mcp.json`: <list>. Restart Kiro if this is the first time adding them."

**If neither path is detected:** the Power is not installed. Instruct the user to run
`./install.sh` from the repo root, then restart Kiro.

**GitHub Copilot (VS Code):**
Copilot in VS Code reads workspace-scoped `.vscode/mcp.json` automatically.
The repo ships this file generated from `manifest.yaml` via
`tools/sync-ide-configs.py`, so no install action is needed at runtime —
only verification.

```bash
test -f .vscode/mcp.json && echo "OK: .vscode/mcp.json present" || echo "MISSING: .vscode/mcp.json"
```

If present:
- Inform the user: "Copilot will auto-discover MCP servers from
  `.vscode/mcp.json` when this repo is opened in VS Code. If Copilot is
  already running, reload the window (Cmd/Ctrl+Shift+P → 'Developer:
  Reload Window') to pick up changes."
- Note: Copilot's MCP schema uses `{"servers": {...}}` (NOT
  `{"mcpServers": {...}}` like other clients). The sync tool already
  emits the correct schema; do not hand-edit.

If absent:
- Tell the user: "Run `python3 tools/sync-ide-configs.py` to regenerate
  `.vscode/mcp.json` from `manifest.yaml`, then reload the VS Code
  window."

**Generic (Aider, Continue, other):**
Print instructions for each missing MCP and continue — do not block execution:
```
Missing MCP servers detected. Add these to your IDE's MCP configuration:
  awsknowledge:       { "type": "http", "url": "https://knowledge-mcp.global.api.aws" }
  aws-documentation:  { "command": "uvx", "args": ["awslabs.aws-documentation-mcp-server@1.1.28"] }
See: https://github.com/awslabs/mcp
Continuing with degraded MCP coverage — some steps may fall back to web search.
```

- [ ] If `--clean` was passed, retrieve the latest model first and defer removal
  until Assess Step 0b resolves the canonical slug. Remove only that service's
  previous phase tree before promoting the new intake. Preserve `_sources/`, the
  new staging intake, `plans/`, and every other service. Never use a wildcard
  deletion of `.service-approval/` because it would delete the validated snapshot.

- [ ] For an existing run being resumed, perform the mandatory offline snapshot check
  before using cached output. For an explicitly fresh run (`--clean`), fetch a new
  inputs fragment and regenerate all phases; do not refresh the discarded run.
  Without `--clean`, preserve existing phase state and do not silently replace its
  intake or model. Only an explicit new run adopts upstream changes.

- [ ] Phase 0 Intake + Assess will create the service-specific directories automatically.
  No pre-creation needed. The canonical slug is derived after SAR facts are loaded.

- [ ] Validate required input:
  If no `./input-folder` AND no `--service` AND no `--from-intake`, the Intake
  phase below will prompt the user interactively. If Intake is running in
  non-interactive mode (e.g., `--from-intake=<file>`) and required fields are
  missing, Intake halts with an error. Do NOT try to resolve the service name
  here — defer to Intake.

## Environment Detection

Detect execution environment to choose parallelism strategy:

```bash
env | grep -E 'KIRO_AGENT|GITHUB_COPILOT' 2>/dev/null
```

Additionally: check whether the `Agent` tool appears in your available tool list.
If it does, treat this as Claude Code regardless of env var results.

Decision logic:
- `Agent` tool available in tool list → **Claude Code — use Parallel Mode** (see below)
- `KIRO_AGENT` env var set → **Kiro — Sequential Mode**
- `GITHUB_COPILOT` env var set → **GitHub Copilot — Sequential Mode**
- No signals detected → **Sequential Mode** (safe default)

---

## Sequential Mode (default for all non-Claude-Code clients)

Run each phase in order. Pass all relevant flags through.

### Intake (Precursor — Mandatory)
Follow ALL instructions in `skills/intake/SKILL.md` exactly.
Pass: input folder, `--service`, published-model inputs fragment,
`--from-intake` if provided, `--interactive` if provided,
`--no-mcp` if provided, and any of `--framework`, `--framework-file` the user
supplied at the orchestrator level (Intake uses them to pre-fill its form /
intake manifest).

When done: verify `.service-approval/_staging/<ts>/00-intake/intake-manifest.json`
exists before proceeding (it gets promoted to `<slug>/00-intake/` by Phase 0
Step 0b after slug derivation). From that manifest, resolve the effective
`--service`, `--framework`, `--framework-file`, and input folder.

**Intake runs for new runs.** A resume reuses the saved runtime manifest. For a new
run, the intake skill decides whether to prompt
interactively or short-circuit:

- If `./service-approval-intake.yaml` exists in the user's CWD and
  `--interactive` was not passed, the skill renders a summary and prompts
  `[U]se as-is / [E]dit`. "Use as-is" is the short-circuit path.
- If `--from-intake=<path>` is provided, the skill reads that file (no prompts).
- Otherwise the skill runs the full interactive form and offers to save the
  answers to `./service-approval-intake.yaml`.

**Plugin-repo guard:** Files inside the installed plugin
(`skills/intake/intake-template.yaml`, `skills/intake/defaults.yaml`) are never
auto-loaded as user intake — they are templates/defaults shared across users.

`--clean` removes only the selected service’s previous phase tree at Assess
Step 0b, after successful retrieval and slug resolution. It preserves source
snapshots, the new staging intake, other services, and the user’s intake YAML.

### Phase 0: Assess (Mandatory)
Follow ALL instructions in `skills/assess/SKILL.md` exactly.
Pass: input folder path (from intake), `--service` flag, `--questions` flag if provided.
When done: verify these files exist before proceeding:
- `.service-approval/<slug>/01-assess/sar-facts.json`
- `.service-approval/<slug>/01-assess/checkpoint-results.json`
- `.service-approval/<slug>/01-assess/assessment-summary.md`

**Skip condition**: Phase 0 is skipped ONLY if all three assessment artifacts already
exist (from a previous `/assess` run). There is no flag to skip assessment.

### Phase 1: Research (3+1 sub-skills, sequential in this mode)

**Step 1a — Mitigations:**
Follow ALL instructions in `skills/research-mitigations/SKILL.md`.
Pass: `./input-folder`, `--service`.
Wait for `.service-approval/<slug>/02-research/research-mitigations.json`.

**Step 1b — Capabilities:**
Follow ALL instructions in `skills/research-capabilities/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/<slug>/02-research/research-capabilities.json`.

**Step 1c — API Surface:**
Follow ALL instructions in `skills/research-api-surface/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/<slug>/02-research/research-api-surface.json`.

**Step 1d — Threat Attack Surface (mandatory):**
Follow ALL instructions in `skills/research-attack-surface/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/<slug>/02-research/research-attack-surface.json`.
**Always runs.** MITRE ATT&CK threat analysis is mandatory for every service onboarding.
Read the required export selected by `inputs.threat_model_file`. MITRE ATT&CK
Cloud data and additional customer documents enrich that export; they never
replace it. Missing or invalid source input halts the pipeline.

**Step 1e — Merge:**
Run the merge step from `skills/research/SKILL.md` → "Merge Step" section.
Verify `.service-approval/<slug>/02-research/research.json` exists and has `schema_version: "3.0"`.

### Phase 2: Validate
Follow ALL instructions in `skills/validate/SKILL.md` exactly.
When done: verify `.service-approval/<slug>/03-validate/validated.json` exists before proceeding.

### Phase 3: Map (4 sub-skills, sequential in this mode)

**Step 3a — Parse Framework:**
Follow ALL instructions in `skills/map-parse-framework/SKILL.md`.
Pass: `--framework` and `--framework-file` flags if provided.
Wait for `.service-approval/<slug>/04-map/map-framework-parsed.json`.

**Step 3b — Generate Controls:**
Follow ALL instructions in `skills/map-generate-controls/SKILL.md`.
Pass: `--service`.
Wait for `.service-approval/<slug>/04-map/map-controls-generated.json`.

**Step 3c — Framework Mapping:**
Follow ALL instructions in `skills/map-framework-mapping/SKILL.md`.
For **CCMv4** (a `data/domain-mapping-guidance/ccmv4.json` guidance file exists),
map **per domain**: handle each of the 17 CCMv4 domains in its own focused pass
loaded with only that domain's objectives + that domain's guidance + the shared
controls, write each as a partial to `04-map/_domains/<DOMAIN>.json`, then run the
deterministic merge `python3 scripts/merge-domain-mappings.py --slug <slug>`.
For **non-CCMv4** frameworks (no guidance file), run the single-pass behavior.
Either way, wait for `.service-approval/<slug>/04-map/map-framework-mapped.json`.

**Step 3d — Assemble:**
Follow ALL instructions in `skills/map-assemble/SKILL.md`.
Verify these files exist before proceeding:
- `.service-approval/<slug>/04-map/mapping-results.json`
- `.service-approval/<slug>/04-map/controls-catalog.md`
- `.service-approval/<slug>/04-map/framework-mapping.md`

### Phase 4: Recommended Guidance (2 sub-skills, sequential in this mode)

**Step 4a — Preventive/Proactive (gated sub-pipeline, run in order):**
1. `skills/generate-preventive-recommend/SKILL.md` — mechanism + anchor decision per
   objective → `<slug>/05-recommended-guidance/preventive-plan.json` (the gate).
2. The authors for each `GENERATE_*` row: `skills/generate-preventive-scp/SKILL.md`,
   `skills/generate-preventive-rcp/SKILL.md`, `skills/generate-preventive-iam/SKILL.md`
   (these also emit proactive artifacts per `skills/generate-preventive/SKILL.md`).
3. `skills/generate-preventive-rootcause/SKILL.md` — prove anchored + enforcing; route
   non-preventable objectives to detective.
Pass: `--service`, `--include-unverified` if set.
Wait for `<slug>/05-recommended-guidance/preventive/` and `<slug>/05-recommended-guidance/proactive/` to be populated.

**Step 4b — Detective/Responsive:**
Follow ALL instructions in `skills/generate-detective/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `<slug>/05-recommended-guidance/detective/` and `<slug>/05-recommended-guidance/responsive/` to be populated.

**Step 4c — Final Validation:**
Run the final validation from `skills/generate/SKILL.md` → "Final Validation" section.

### Phase 5: Summarize
Follow ALL instructions in `skills/summarize/SKILL.md` exactly.
Report the summary of findings to the user (this report issues no verdict).

---

## Parallel Mode (Claude Code only — Agent tool available)

Leverage the Agent tool to parallelize independent sub-skills within each phase.

### Intake (Precursor — Mandatory)
Always dispatch Intake — the intake skill itself decides whether to prompt or
short-circuit (see "Discovery Rules" in `skills/intake/SKILL.md`):

- If `./service-approval-intake.yaml` exists in CWD and `--interactive` was not
  passed, the skill renders a summary and prompts `[U]se as-is / [E]dit`.
- If `--from-intake=<path>` is set, the skill reads that path with no prompts.
- Otherwise the skill runs the full interactive form and offers to save.

Dispatch Intake as a foreground subagent with the full text of
`skills/intake/SKILL.md`, plus input folder, `--service`, published-model inputs fragment,
`--from-intake`, `--interactive`, and
any pre-Intake CLI flags the user passed (`--framework`, `--framework-file`).
Wait for `.service-approval/_staging/<ts>/00-intake/intake-manifest.json` (Intake's pre-promotion landing zone).

Plugin-repo files (`skills/intake/intake-template.yaml`,
`skills/intake/defaults.yaml`) are never auto-loaded as user intake. `--clean`
clears the entire `.service-approval/` tree (all per-slug service dirs and
any `_staging/` snapshots) but does not touch the user's
`./service-approval-intake.yaml`.

### Phase 0: Assess (Mandatory)
If all 3 assessment artifacts (`sar-facts.json`, `checkpoint-results.json`,
`assessment-summary.md`) already exist, skip (previous
`/assess` run).
Otherwise: dispatch Assessor as foreground subagent.
Wait for all 3 assessment artifacts.

### Phase 1: Research (3+1 sub-skills in parallel)

Dispatch all 4 research sub-skills simultaneously as background subagents:

```
Agent 1: research-mitigations (background)
  Prompt: Full text of skills/research-mitigations/SKILL.md + input folder + --service flag
  Output: research-mitigations.json

Agent 2: research-capabilities (background)
  Prompt: Full text of skills/research-capabilities/SKILL.md + --service flag
  Output: research-capabilities.json

Agent 3: research-api-surface (background)
  Prompt: Full text of skills/research-api-surface/SKILL.md + --service flag
  Output: research-api-surface.json

Agent 4: research-attack-surface (background, mandatory)
  Prompt: Full text of skills/research-attack-surface/SKILL.md + --service flag
  Output: research-attack-surface.json
  Note: Always dispatched — MITRE ATT&CK analysis is mandatory for every service.
  Reads inputs.threat_model_file; MITRE ATT&CK Cloud matrix supplements the required export.
  If it fails, halt the pipeline — attack surface analysis is required.
```

**IMPORTANT:** Dispatch all 4 in a single message with 4 Agent tool calls.
Do NOT set `model` parameter — let subagents inherit the caller's model.

When all 4 complete, run the merge step from `skills/research/SKILL.md`:
- Combine the 4 required partial JSONs into `research.json`
- Merge `research-attack-surface.json` data into `attack_surface`
- Run the validation script
- If CRITICAL cross-reference errors exist (actions missing from both operations[] and
  permission_only_actions[]), re-dispatch the api-surface agent with the missing action list

### Phase 2: Validate
Dispatch Validator as foreground subagent.
Provide full text of `skills/validate/SKILL.md`.
Wait for `validated.json`.

### Phase 3: Map (4 sub-skills, 2 parallel + 2 sequential)

**Steps 3a+3b: Parallel dispatch**

Dispatch both independent sub-skills simultaneously as background subagents:

```
Agent 3a: map-parse-framework (background)
  Prompt: Full text of skills/map-parse-framework/SKILL.md + framework flags
  Output: map-framework-parsed.json

Agent 3b: map-generate-controls (background)
  Prompt: Full text of skills/map-generate-controls/SKILL.md + --service flag
  Output: map-controls-generated.json
```

**IMPORTANT:** Dispatch both in a single message with 2 Agent tool calls.

**Step 3c: Framework mapping (after 3a+3b complete)**

This is the most reasoning-heavy step. The dispatch shape depends on the framework:

***CCMv4 — per-domain fan-out + deterministic merge.*** A single 197-objective
pass produces keyword-driven mis-maps; instead map each domain in its own focused
context. Dispatch **one mapping subagent per CCMv4 domain** (17: A&A, AIS, BCR,
CCC, CEK, DCS, DSP, GRC, HRS, IAM, IPY, IVS, LOG, SEF, STA, TVM, UEM), each loaded
with ONLY: that domain's objectives from `map-framework-parsed.json`, that
domain's guidance from `data/domain-mapping-guidance/ccmv4.json`, the full
`map-controls-generated.json` (controls are shared), and the per-objective
reasoning rules from `skills/map-framework-mapping/SKILL.md`.

```
Agent 3c.<DOMAIN> (one per domain — parallelizable):
  Prompt: Full text of skills/map-framework-mapping/SKILL.md
          + "Map ONLY domain <DOMAIN>. Objectives: <that domain's entries>.
             Guidance: <that domain's ccmv4.json entry>."
  Output: 04-map/_domains/<DOMAIN>.json   (this domain's framework_mapping[] partial)
```

Dispatch the domains in batches that respect the **concurrency cap** — Parallel
Mode runs at most a handful of background subagents at once, so launch them in
waves (e.g. groups of ~4) rather than 17 at once. Do NOT set `model` — subagents
inherit the caller's model. When all 17 partials exist, run the deterministic
merge (no subagent — it is pure assembly):

```bash
python3 scripts/merge-domain-mappings.py --slug <slug>
```

The merge concatenates partials in canonical domain order, recomputes the coverage
summary + cross-domain quality gates (Rule 2 spray / Rule 3 / Rule 5 / 6 / 7), and
writes `map-framework-mapped.json`. Wait for that file.

***Non-CCMv4 — single foreground pass*** (no guidance file for the active
framework, e.g. NIST 800-53 / CIS / ISO):

```
Agent 3c: map-framework-mapping (foreground)
  Prompt: Full text of skills/map-framework-mapping/SKILL.md
  Input: map-framework-parsed.json + map-controls-generated.json
  Output: map-framework-mapped.json
```

Either path MUST run in foreground (or complete fully) before Step 3d, so the
quality gates are satisfied. The output contract is identical for both paths.

**Step 3d: Assembly (foreground, after 3c completes)**

Dispatch as foreground subagent:

```
Agent 3d: map-assemble (foreground)
  Prompt: Full text of skills/map-assemble/SKILL.md
  Input: All 3 intermediate files + validated.json
  Output: mapping-results.json + controls-catalog.md + framework-mapping.md
```

Wait for `mapping-results.json`, `controls-catalog.md`, `framework-mapping.md`.

**Step 3e: Mapping review gate (foreground subagent, after 3d completes)**

Before generation consumes the mapping, dispatch a foreground review subagent to
check the mapping is well-grounded and citable. Log the gate lifecycle and run
each validator, capturing its exit code:

```bash
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source skill:map-review --verdict start \
    --message "mapping review gate: citability + prose budget"

python3 tools/validate/validate_control_mappings.py --slug <slug>; cm=$?
python3 tools/validate/lint_control_prose.py --slug <slug> --strict; lp=$?
python3 tools/validate/validate_mapping_semantics.py --slug <slug>; ms=$?
python3 tools/validate/validate_threat_model_facts.py --slug <slug> --strict; cf=$?
python3 tools/validate/validate_domain_applicability.py --slug <slug>; da=$?
python3 tools/validate/validate_domain_mapping_accuracy.py --slug <slug>; ma=$?
python3 tools/validate/validate_control_dedup.py --slug <slug>; cd=$?
```

`validate_domain_mapping_accuracy.py` reads the sibling `applicability-matrix.json`
(written by `compute-applicability-matrix.py` in Step 2b) when present, so its
category-applicability and coverage-ceiling checks are active. It is the single
deterministic backstop for per-objective mapping accuracy: denied-class mis-maps,
`default_na`-without-override, category-not-applicable, coverage over the
mechanism-class ceiling, and confident-MAPPED-without-citation (which must be
`UNCERTAIN` instead). An `UNCERTAIN` row is advisory — surfaced, never failed.

It reports: objectives flagged with no catalog/reference support, and any control
prose that exceeds the verified-language budget or over-claims. The prose lint
walks both `mapping-results.json` **and** the rendered `controls-catalog.md` /
`framework-mapping.md` siblings, so it catches a banned/overreach phrase that
was introduced only at render time (the `.md` making a claim stronger than the
source JSON — an "upward re-wording" divergence). It runs `--strict`, so a prose
finding gates the map phase: re-word the offending control to objective level and
re-render before generation consumes the mapping. The cross-check's purpose is to
confirm every mapping can point to a citation (AWS Threat Model mitigation, reference
example, Control Catalog, or a service-specific doc) before any control is authored.

**Persist the review artifact** so the gate leaves a machine-readable trace —
write `.service-approval/<slug>/04-map/mapping-review.json`:

```json
{
  "_metadata": {"service": "<service>", "gate": "post-map", "generated": "service-approval v3.0.0"},
  "validators": [
    {"name": "validate_control_mappings", "exit_code": 0, "blocking": false},
    {"name": "lint_control_prose", "exit_code": 0, "blocking": true},
    {"name": "validate_mapping_semantics", "exit_code": 0, "blocking": false},
    {"name": "validate_threat_model_facts", "exit_code": 0, "blocking": true},
    {"name": "validate_domain_applicability", "exit_code": 0, "blocking": false},
    {"name": "validate_domain_mapping_accuracy", "exit_code": 0, "blocking": false},
    {"name": "validate_control_dedup", "exit_code": 0, "blocking": false}
  ],
  "flagged": [
    {"objective_id": "IAM-04", "issue": "no catalog/reference support", "severity": "advisory"}
  ]
}
```

`validate_mapping_semantics` runs the deterministic S1/S2/S3 checks (every
satisfied-by control id resolves, every mapped objective id exists in the parsed
framework, no control claims an action/condition key absent from `validated.json`).
`validate_threat_model_facts` confirms every AWS Threat Model-cited row (a map/framework-mapping
citation with `source == "threat_model"`, or a preventive-plan citation with
`type == "threat_model"`) names a mitigation alias that exists in the provided AWS Threat Model
export, whose governed operations are consistent with the control's actions, and
whose quoted `mitigation_statement` (when present) appears verbatim in the
export. It runs `--strict` here, so a fabricated alias, drifted operation, or
non-verbatim statement blocks the map phase; MAPPED rows are checked and
UNCERTAIN rows are exempt. `validate_mapping_semantics` is advisory (reported in
`mapping-review.json`); the AWS Threat Model-facts check also runs in the post-generate gate.

Then log the outcome:

```bash
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_control_mappings \
    --verdict $([ $cm -eq 0 ] && echo pass || echo warn) --message "control→catalog cross-check"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:lint_control_prose \
    --verdict $([ $lp -eq 0 ] && echo pass || echo fail) --message "control prose language budget (JSON + rendered .md)"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_mapping_semantics \
    --verdict $([ $ms -eq 0 ] && echo pass || echo warn) --message "semantic mapping checks (S1/S2/S3)"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_threat_model_facts \
    --verdict $([ $cf -eq 0 ] && echo pass || echo warn) --message "AWS Threat Model-factual citation check"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_domain_applicability \
    --verdict $([ $da -eq 0 ] && echo pass || echo warn) --message "framework-domain applicability check"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_domain_mapping_accuracy \
    --verdict $([ $ma -eq 0 ] && echo pass || echo warn) --message "per-objective domain mapping-accuracy check"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source script:validate_control_dedup \
    --verdict $([ $cd -eq 0 ] && echo pass || echo warn) --message "control de-duplication count guard"
python3 -m tools.validate.log --slug <slug> --phase 04-map \
    --source skill:map-review --verdict end \
    --message "mapping review gate complete" --extra artifact=mapping-review.json
```

`validate_control_dedup` re-derives each control's canonical identity (the same key
`map-assemble` Phase 0 collapses on) and confirms no two controls in
`mapping-results.json` still share it — i.e. the de-duplication held. It prints
`distinct_controls` / `total_controls`; after Phase 0 these are equal. A finding means
a duplicate survived assembly (investigate the collapse), not that the mapper should
re-map.

`validate_domain_applicability` (CCMv4-specific) flags any platform/infra-config
control (CloudFormation Guard, Config rule, SCP, RCP, tag policy) mapped to an
application-code AIS objective (AIS-02/04/05), any N/A-by-default domain objective
(DCS/UEM/BCR/IPY, TVM-10-class) marked MAPPED without an `applicability_justification`
+ `reference_url` override, and any resource-tag control mapped to a
data-sensitivity-classification objective (DSP-03/04). N/A-by-default within that
scope is read per-objective from `data/domain-mapping-guidance/ccmv4.json`, so a
guidance-`mappable` objective (e.g. BCR-04, satisfied by multi-AZ resilience) is no
longer blanket-flagged.

`validate_domain_mapping_accuracy` (CCMv4-specific) is the per-objective accuracy
backstop for the per-domain mapping: it reads the same guidance file and, for every
mapped objective, flags a control whose mechanism class is in that objective's
`deny_mechanisms` (and not in `allow_mechanisms`) — e.g. a TLS control mapped to
IVS-07 (migration *process*), a misconfiguration-detective control mapped to LOG-12
(access-event logging), or an access-control/layer-sharing control mapped to STA-12
(supply-chain agreements) — plus any `default_na` objective mapped without the
override fields. Both are advisory here (reported in `mapping-review.json`; promote
to a hard gate once the guidance is proven on real runs); a finding means the mapper
over-claimed — re-map the flagged objective to N/A (or add a justified override)
before generation consumes the mapping.

The control→catalog cross-check (`validate_control_mappings`) is **advisory** —
surface its flagged items and proceed. The prose lint (`lint_control_prose
--strict`) is a **hard gate**: a non-zero exit means a control over-claims in the
JSON or the rendered `.md`, so fix the prose and re-render before generation
consumes the mapping.

### Phase 4: Recommended Guidance (2 families in parallel; preventive is a sequenced sub-pipeline)

Dispatch the 2 control families simultaneously as background subagents. The
**preventive family is one agent that runs its own sub-pipeline in order** — the
recommender gate, the reference-anchored authors, then the root-cause critic —
because each step gates the next and must not be parallelized.

```
Agent 4: generate-preventive (background) — runs the preventive sub-pipeline IN ORDER:
  1. Full text of skills/generate-preventive-recommend/SKILL.md  → preventive-plan.json (gate)
  2. For each GENERATE_* row, the matching author:
       skills/generate-preventive-scp/SKILL.md
       skills/generate-preventive-rcp/SKILL.md
       skills/generate-preventive-iam/SKILL.md
     (authors also emit proactive artifacts per skills/generate-preventive/SKILL.md)
  3. Full text of skills/generate-preventive-rootcause/SKILL.md   → prove anchored + enforcing
  Pass: --service + --include-unverified
  Output: <slug>/05-recommended-guidance/preventive/ + <slug>/05-recommended-guidance/proactive/

Agent 5: generate-detective (background)
  Prompt: Full text of skills/generate-detective/SKILL.md + --service + --include-unverified
  Output: <slug>/05-recommended-guidance/detective/ + <slug>/05-recommended-guidance/responsive/
```

**IMPORTANT:** Dispatch both families in a single message with 2 Agent tool calls.
The preventive agent runs its sub-skills sequentially within that one agent.

When both complete, run the final validation from `skills/generate/SKILL.md`.

**Detective top-up for routed objectives.** Because detective runs in parallel
with preventive here, it cannot see the routing the preventive critic writes at
the end of its sub-pipeline. After both agents complete, if
`<slug>/05-recommended-guidance/detective-routing.json` exists with any `routed[]` entry
whose `covered_by` is null, re-dispatch `generate-detective` for a top-up pass to
cover those objectives (its "Routed-from-preventive objectives" section). Then
confirm the loop is closed:

```bash
python3 tools/validate/validate_detective_routing.py --slug <slug>
```

**Step 4-review: Generation review gate (foreground subagent, after generation completes)**

Before summarizing, dispatch a foreground review subagent to prove every generated
preventive artifact is both in the mapping and properly enforcing. Log the gate
lifecycle and run each validator, capturing its exit code:

```bash
python3 -m tools.validate.log --slug <slug> --phase 05-recommended-guidance \
    --source skill:generate-review --verdict start \
    --message "generation review gate: anchor + enforcement + scope"

python3 tools/validate/validate_reference_anchor.py --slug <slug>;   ra=$?
python3 tools/validate/validate_citation_coverage.py --slug <slug>;  cc=$?
python3 tools/validate/validate_preventability.py --slug <slug>;      pv=$?
python3 tools/validate/validate_enforcement.py --slug <slug> --strict; en=$?
python3 tools/validate/validate_action_scope.py --slug <slug> --strict; as=$?
python3 tools/validate/validate_cross.py .service-approval/<slug>/05-recommended-guidance; cx=$?
python3 tools/validate/validate_detective_routing.py --slug <slug>;   dr=$?
python3 tools/validate/validate_threat_model_facts.py --slug <slug> --strict; cf=$?
```

`validate_citation_coverage` is the sibling of `validate_reference_anchor` for the
non-preventive families: it proves every authored artifact under
`05-recommended-guidance/{detective,proactive,responsive}/` carries a resolvable
citation — a repo anchor (`_metadata.reference` resolving to a reference-index
example) or a doc anchor (`_metadata.citation` of type `aws_doc` with an
MCP-verified AWS documentation URL). It is a **hard gate** (it also runs in the
Stop hook as P12).

**Conflict / contradiction detection (deterministic pre-filter → clean-subagent judge).**
First run the deterministic pre-filter, which surfaces candidate statement pairs that
share a gated action with opposing posture (an SCP/RCP/IAM Deny vs. an IAM Allow the
same principal is expected to hold, or two Denies gating the same action with
incompatible condition keys):

```bash
python3 tools/validate/detect_control_conflicts.py --slug <slug> \
    > .service-approval/<slug>/05-recommended-guidance/conflict-report.json
```

Then dispatch a **clean review subagent** (Agent tool, no prior context) whose sole job
is to confirm or dismiss each candidate. Give it ONLY the generated control set and the
candidate list; it returns the final `conflict-report.json` (`{pairs:[{a,b,kind,
explanation,severity}], verdict}`, `verdict ∈ {NO_CONFLICTS, CONFLICTS_FOUND}`). The
judge confirms/explains — it does not re-scan from scratch. Advisory at first (surface
the confirmed pairs in the report); it can become a hard gate later.

It reports: any authored preventive artifact lacking a resolvable reference anchor;
any artifact marked not-anchored without an explicit reason; any `source_control_id`
that does not trace back to `mapping-results.json`; any URL-cited preventive artifact
(one whose `_metadata.reference` or `_metadata.citation` carries a `url`) missing a
non-empty `_metadata.applicability` (both `applies_to` and `usage_notes`) — the block
that tells the customer what the cited policy targets and where not to apply it; any
statement that is not evaluable (request-time key in a resource-based policy, malformed
Resource ARN, key that does not apply to the gated action); any authored Deny action
absent from the recommender's reviewed set; any permission-boundary that emits without
the org prerequisite; and any objective that should be routed to detective.

The anchor, enforcement, action-scope, and cross checks are **hard gates** (they
also run in the Stop hook — P3/P8/P9/P10 + X4); the routing summary is advisory.

**Persist the review artifact** — write
`.service-approval/<slug>/05-recommended-guidance/generation-review.json`:

```json
{
  "_metadata": {"service": "<service>", "gate": "post-generate", "generated": "service-approval v3.0.0"},
  "validators": [
    {"name": "validate_reference_anchor", "exit_code": 0, "blocking": true},
    {"name": "validate_citation_coverage", "exit_code": 0, "blocking": true},
    {"name": "validate_preventability", "exit_code": 0, "blocking": false},
    {"name": "validate_enforcement", "exit_code": 0, "blocking": true},
    {"name": "validate_action_scope", "exit_code": 0, "blocking": true},
    {"name": "validate_cross", "exit_code": 0, "blocking": true},
    {"name": "validate_detective_routing", "exit_code": 0, "blocking": false},
    {"name": "validate_threat_model_facts", "exit_code": 0, "blocking": true},
    {"name": "conflict_detection", "exit_code": 0, "blocking": false}
  ],
  "flagged": []
}
```

Then log each validator's outcome and close the gate:

```bash
for v in "reference_anchor:$ra:1" "citation_coverage:$cc:1" "preventability:$pv:0" \
         "enforcement:$en:1" "action_scope:$as:1" "cross:$cx:1" \
         "detective_routing:$dr:0" "threat_model_facts:$cf:1"; do
  name=${v%%:*}; rest=${v#*:}; code=${rest%%:*}
  python3 -m tools.validate.log --slug <slug> --phase 05-recommended-guidance \
      --source script:validate_$name \
      --verdict $([ $code -eq 0 ] && echo pass || echo fail) --message "generation gate check"
done
python3 -m tools.validate.log --slug <slug> --phase 05-recommended-guidance \
    --source skill:generate-review --verdict end \
    --message "generation review gate complete" --extra artifact=generation-review.json
```

**Build the coverage rollups.** After the gate, produce the deterministic,
file-backed accounting for both the preventive family and the other three
families — each row traceable to its control id and citation:

```bash
python3 tools/validate/build_preventive_coverage.py --slug <slug>
python3 tools/validate/build_citation_coverage.py --slug <slug>
```

`build_preventive_coverage.py` reads `preventive-plan.json` +
`preventive/rootcause-report.json` and writes
`.service-approval/<slug>/05-recommended-guidance/preventive-coverage.json`.
`build_citation_coverage.py` walks `05-recommended-guidance/{detective,proactive,responsive}/`
and writes `citation-coverage.json` — every artifact → its repo/doc citation. The
numbers are deterministic (no prose narration); Summarize surfaces them.

Surface the findings before Summarize so the report's confidence-actions section can
state which checks ran and passed.

### Phase 5: Summarize
Dispatch Summarizer as foreground subagent.
Wait for `SUMMARY-REPORT.md`.

### Parallelism Summary

```
Intake                    (1 agent, foreground — precursor)
Phase 0: Assess          (1 agent, foreground)
Phase 1: Research         (4 agents in parallel, then merge)
  1a: Mitigations         (background) ─┐
  1b: Capabilities        (background) ─┤
  1c: API Surface         (background) ─┤
  1d: ATT&CK Surface      (background) ─┤
                                        └─ 1e: Merge (foreground)
Phase 2: Validate         (1 agent, foreground)
Phase 3: Map              (2 agents in parallel, then per-domain fan-out + merge)
  3a: Parse Framework     (background) ─┐
  3b: Generate Controls   (background) ─┤
                                        ├─ 3c: Framework Mapping
                                        │     CCMv4: 1 subagent per domain (waves) → merge
                                        │     other: 1 foreground pass
                                        └─ 3d: Assemble          (foreground)
Phase 4: Recommended Guidance (2 agents in parallel, then validate)
Phase 5: Summarize        (1 agent, foreground)
```

Total agents: up to 12, but with 3 parallelization windows that significantly
reduce wall-clock time.

If any agent fails to complete, proceed to Summarizer with partial results.
Summarizer marks the incomplete agent as INCOMPLETE in the report.

---

## Final Output

```
Service Approval complete.
Report: .service-approval/<slug>/06-summarize/SUMMARY-REPORT.md
Controls: .service-approval/<slug>/05-recommended-guidance/
Summary of findings: see report (no verdict issued)
```

Generated alias/UUID mismatches and invalid dispositions remain authoring errors:
repair them against the unambiguous snapshot before final disclosure. P14 rejects
those errors even when listed, while source defects and honest unresolved
coverage remain advisory.
