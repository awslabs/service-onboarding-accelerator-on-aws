Plans dir needs to be created, which implementation will do. I have enough. Now I'll produce the comprehensive plan as the final message.

---

# Evidence & Attestation System — Comprehensive Implementation Plan

**Destination file (to be created by implementation team, not by this planning pass):** `/Users/tamg/WorkDocs/Builder/service-onboarding/.service-approval/plans/evidence-attestation.md`

**Scope:** Two tightly-coupled features executed as a single coordinated effort.

**Branch:** `feature/evidence-attestation` (already created, tip `eaf7fde`).

**Cutover:** Hard (no dual-path phase). New runs only; one legacy `state-agentcore-20260512/` snapshot already exists and is ignored (read-only archive).

---

## 0. Executive Summary

Two changes ship together:

1. **Layout reorg** — `.service-approval/state/` (flat) → `.service-approval/<service-slug>/<NN>-<phase>/` (per-service, per-phase). Every skill, validator, hook, and script that reads/writes state files is updated in lockstep. Controls fold from `.service-approval/controls/<family>/` into `.service-approval/<service>/05-generate/<family>/`.
2. **Phase 7 Evidence Runner** — a new `/evidence` skill that, after Phase 6 summarize, runs service-agnostic AWS CLI probes against resources deployed by this workflow, persists raw stdout/stderr, produces a control → CLI → verdict matrix, and writes an `attestation-report.md` + `attestation-results.json` + human-readable `attestation.md` audit guide.

These are coupled because Phase 7 consumes the new per-service tree (`05-generate/` for artifacts, `06-test/` for stack IDs, `04-map/mapping-results.json` for the control roster) and writes into `08-evidence/`. Shipping them in one pass avoids a stale intermediate state.

**Regression safety strategy:** parallel agent worktrees, each owning a disjoint file surface, all converging on the `feature/evidence-attestation` branch via `worktree-merge` after an integration smoke test on Lambda (the current known-good pipeline tip).

---

## 1. Architecture — End-to-end folder layout

```
.service-approval/
├── plans/                                         # NEW — design docs (this plan)
│   └── evidence-attestation.md
├── _staging/                                      # NEW — intake buffer before service-slug known
│   └── <timestamp>/
│       └── 00-intake/
│           └── intake-manifest.json
├── <service-slug>/                                # e.g. awslambda, bedrock-agentcore, s3
│   ├── attestation.md                             # NEW — review guide (Feature 1)
│   ├── mcp-calls.log                              # MOVED from state/ — service-scoped audit log
│   ├── 00-intake/
│   │   └── intake-manifest.json
│   ├── 01-assess/
│   │   ├── sar-facts.json
│   │   ├── checkpoint-results.json
│   │   ├── assessment-summary.md
│   │   ├── assessment-questionnaire.md            # optional (if --questions)
│   │   ├── iac-support.json
│   │   └── domains/
│   │       ├── IAM-research.md
│   │       ├── LOGGING-research.md
│   │       ├── INFRA-research.md
│   │       ├── DATA-research.md
│   │       └── INCIDENT-research.md
│   ├── 02-research/
│   │   ├── research-mitigations.json
│   │   ├── research-capabilities.json
│   │   ├── research-api-surface.json
│   │   ├── research-attack-surface.json           # mandatory — MITRE ATT&CK
│   │   ├── botocore-schema.json                   # transient — gitignored
│   │   ├── botocore-mutability.json               # transient — gitignored
│   │   ├── botocore-gateable.json                 # transient — gitignored
│   │   └── research.json                          # merged
│   ├── 03-validate/
│   │   └── validated.json
│   ├── 04-map/
│   │   ├── map-framework-parsed.json
│   │   ├── map-controls-generated.json
│   │   ├── map-framework-mapped.json
│   │   ├── mapping-results.json
│   │   ├── controls-catalog.md
│   │   └── framework-mapping.md
│   ├── 05-generate/                               # WAS .service-approval/controls/
│   │   ├── preventive/
│   │   ├── proactive/
│   │   ├── detective/
│   │   ├── responsive/
│   │   └── iac/
│   │       ├── cloudformation/
│   │       ├── terraform/
│   │       ├── terraform-modules/
│   │       ├── cdk/
│   │       └── cdktf/
│   ├── 06-test/
│   │   ├── test-results.json
│   │   └── deploy-logs/
│   │       ├── tf-plan.log
│   │       ├── tf-apply.log
│   │       ├── cfn-deploy.log
│   │       ├── cfn-describe-stack-events.log
│   │       └── deployed-resources.json            # NEW — ARNs/stack IDs for Phase 7
│   ├── 07-summarize/
│   │   └── APPROVAL-REPORT.md
│   ├── 08-evidence/                               # NEW — Feature 2
│   │   ├── attestation-report.md
│   │   ├── attestation-results.json
│   │   ├── cli-commands.json
│   │   ├── summary.md
│   │   ├── cli-outputs/
│   │   │   ├── CTRL-ACC-PRO-007--lambda-get-function-configuration.log
│   │   │   └── ...
│   │   ├── iac-time-evidence/
│   │   │   ├── cfn-guard.log
│   │   │   ├── opa-eval.log
│   │   │   ├── checkov.log
│   │   │   └── cfn-lint.log
│   │   └── deploy-evidence/
│   │       └── (copied/linked from 06-test/deploy-logs/)
│   └── smoke-test-N.md                            # per-service iteration reports
└── (no other top-level files in new layout)
```

**Design decisions (resolved):**

- **Number-prefixed dirs (`01-assess/`) not bare (`assess/`).** Prefixes guarantee sort order, give reviewers a natural read sequence, and let validators dispatch on prefix (see §3). Prefix width is 2 digits (room for 00-99; we use 00-08).
- **Fold `controls/` into `05-generate/`.** Simpler, service-scoped, aligns with the "each phase produces its outputs" mental model. The `05-generate/` layout preserves the four category subdirs so existing generators only change path prefix.
- **`smoke-test-N.md` stays at `<service>/` (not `08-evidence/`).** Iteration reports are cross-phase artifacts authored during debugging; they are service-scoped, not phase-scoped.
- **`mcp-calls.log` moves to `<service>/mcp-calls.log`.** Currently under `state/`; the log is service-scoped and spans every phase's MCP calls. Keeping it at the service root avoids duplicating per-phase or forcing validators to choose which phase's copy is canonical.
- **`attestation.md` at `<service>/` root (not in `08-evidence/`).** It's the reviewer's manifest/guide for the entire service tree; placing it at root means a reviewer opens `<service>/attestation.md` first and that doc points them at each phase subdir.
- **`plans/` and `_staging/` at `.service-approval/` root.** `plans/` is repo-lifecycle (design docs, cross-service); `_staging/` is the intake landing zone before the service slug is known.

---

## 2. Service-slug Derivation Algorithm

**The problem:** Intake runs first but the canonical `service_prefix` (e.g., `lambda`, `bedrock-agentcore`) only lands in `sar-facts.json` at the end of Phase 0 (Assess). A naive solution would delay intake artifact writes until Phase 0 completes — but intake needs to persist inputs, interactive answers, and chosen flags before Phase 0 starts.

**Resolution:** Two-step staging.

### Step A — Intake writes to `_staging/<iso-timestamp>/`

```
.service-approval/_staging/2026-05-13T11-30-00Z/
  00-intake/
    intake-manifest.json
```

Intake computes a **candidate slug** from the `--service` flag (always lowercase, hyphenated, no spaces) and records it inside `intake-manifest.json.service.candidate_slug`. It does NOT create `<service>/` yet because Phase 0 may discover the user-provided name is a synonym or alias (e.g., `lambda` → authoritative `awslambda` in SAR).

### Step B — Assess canonicalizes and promotes

Phase 0 Step 0 (SAR pre-read) already resolves the service against `data/sar-slugs.json` + SAR page. After sar-facts.json is written, the first line of Phase 0 Step 0b (new):

```python
# Canonical slug derivation
slug = derive_canonical_slug(
    sar_facts.service,             # e.g. "AWS Lambda"
    sar_facts.service_prefix,      # e.g. "lambda"
    intake_manifest.service.name,  # e.g. "lambda" from user flag
)
# Rule: prefer service_prefix, lowercased, hyphens-for-whitespace, strip prefix words
# "lambda"                          -> "awslambda"
# "bedrock-agentcore"               -> "bedrock-agentcore"
# "bedrock-agentcore-control"       -> "bedrock-agentcore-control"
# "s3"                              -> "s3"
# "kms"                             -> "kms"
```

**Canonical slug rules** (codified as `tools/slug.py::derive_canonical_slug`):

1. Start from `sar_facts.service_prefix` (always lowercase IAM prefix — authoritative).
2. If prefix is a recognized AWS "umbrella" (e.g., `lambda`), prefix with `aws` to match user examples (`awslambda`). Umbrella list lives in `data/slug-umbrellas.json` — extensible.
3. Multi-word product IDs keep internal hyphens (`bedrock-agentcore`).
4. Strip disallowed chars (anything not `[a-z0-9-]`).
5. Validate: `^[a-z0-9][a-z0-9-]{0,62}$` (fs-safe, git-safe, s3-key-safe).

Then:

```bash
# Atomic promotion from staging to canonical
mv .service-approval/_staging/<timestamp>/ .service-approval/<slug>/
```

If `.service-approval/<slug>/` already exists (re-run), and `--clean` was passed, it's deleted first. Otherwise assess logs `Reusing existing <slug>/ tree` and merges — specifically it rewrites `<slug>/00-intake/intake-manifest.json` with the new manifest and overwrites `01-assess/*` from the staging copy.

**Edge case: user runs `/intake` but never runs `/assess`.** The `_staging/` tree persists. A new `tools/cleanup-staging.py` (runnable via `make clean`) removes `_staging/*` older than 7 days.

**Edge case: service name collision.** Two users running different services with the same slug (unlikely but possible). The staging timestamp acts as the pre-resolution namespace, so two concurrent intakes never collide.

---

## 3. Path Migration Matrix

Every skill, validator, hook, and script is updated. The matrix below is authoritative — implementation agents MUST change every path in lockstep. "Old" always means `.service-approval/state/<name>` unless otherwise noted.

| # | Skill / Tool / Script | File(s) Written / Read | Old Path | New Path |
|---|-----------------------|------------------------|----------|----------|
| 1 | `skills/intake/SKILL.md` | `intake-manifest.json` (W) | `state/intake-manifest.json` | `_staging/<ts>/00-intake/intake-manifest.json` |
| 2 | `skills/assess/SKILL.md` | `sar-facts.json` (W) | `state/sar-facts.json` | `<slug>/01-assess/sar-facts.json` |
| 3 | `skills/assess/SKILL.md` | `checkpoint-results.json` (W) | `state/checkpoint-results.json` | `<slug>/01-assess/checkpoint-results.json` |
| 4 | `skills/assess/SKILL.md` | `iac-support.json` (W) | `state/iac-support.json` | `<slug>/01-assess/iac-support.json` |
| 5 | `skills/assess/SKILL.md` | `assessment-summary.md` (W) | `state/assessment-summary.md` | `<slug>/01-assess/assessment-summary.md` |
| 6 | `skills/assess/SKILL.md` | `assessment-questionnaire.md` (W) | `state/assessment-questionnaire.md` | `<slug>/01-assess/assessment-questionnaire.md` |
| 7 | `skills/assess/SKILL.md` | domain research (W) | `out/domains/<D>-research.md` | `<slug>/01-assess/domains/<D>-research.md` |
| 8 | `skills/research-mitigations/SKILL.md` | `research-mitigations.json` (W); reads `assessment-summary.md`, `sar-facts.json` | `state/research-mitigations.json` | `<slug>/02-research/research-mitigations.json` |
| 9 | `skills/research-capabilities/SKILL.md` | `research-capabilities.json` (W); reads `sar-facts.json`, `checkpoint-results.json`, `mcp-calls.log` | `state/research-capabilities.json` | `<slug>/02-research/research-capabilities.json` |
| 10 | `skills/research-api-surface/SKILL.md` | `research-api-surface.json`, `botocore-schema.json`, `botocore-mutability.json`, `botocore-gateable.json` (W); reads `sar-facts.json` | `state/research-api-surface.json` etc. | `<slug>/02-research/research-api-surface.json` etc. |
| 11 | `skills/research-attack-surface/SKILL.md` | `research-attack-surface.json` (W) | `state/research-attack-surface.json` | `<slug>/02-research/research-attack-surface.json` |
| 12 | `skills/research/SKILL.md` (merge step) | `research.json` (W); reads 3 partials | `state/research.json` | `<slug>/02-research/research.json` |
| 13 | `skills/validate/SKILL.md` | `validated.json` (W); reads `research.json`, `sar-facts.json`, `checkpoint-results.json` | `state/validated.json` | `<slug>/03-validate/validated.json` |
| 14 | `skills/map-parse-framework/SKILL.md` | `map-framework-parsed.json` (W) | `state/map-framework-parsed.json` | `<slug>/04-map/map-framework-parsed.json` |
| 15 | `skills/map-generate-controls/SKILL.md` | `map-controls-generated.json` (W); reads `validated.json`, `sar-facts.json` | `state/map-controls-generated.json` | `<slug>/04-map/map-controls-generated.json` |
| 16 | `skills/map-framework-mapping/SKILL.md` | `map-framework-mapped.json` (W); reads `map-framework-parsed.json`, `map-controls-generated.json` | `state/map-framework-mapped.json` | `<slug>/04-map/map-framework-mapped.json` |
| 17 | `skills/map-assemble/SKILL.md`, `scripts/map-assemble.py` | `mapping-results.json`, `controls-catalog.md`, `framework-mapping.md` (W); reads all map-* files + `validated.json` | `state/mapping-results.json` etc. | `<slug>/04-map/mapping-results.json` etc. |
| 18 | `skills/generate-preventive/SKILL.md` | writes `preventive/*`, `proactive/*`; reads `mapping-results.json`, `validated.json` | `.service-approval/controls/{preventive,proactive}/` | `<slug>/05-generate/{preventive,proactive}/` |
| 19 | `skills/generate-detective/SKILL.md` | writes `detective/*`, `responsive/*`; reads `mapping-results.json`, `validated.json` | `.service-approval/controls/{detective,responsive}/` | `<slug>/05-generate/{detective,responsive}/` |
| 20 | `skills/generate-iac/SKILL.md` | writes `iac/*`; reads `mapping-results.json`, `validated.json`, `iac-support.json` | `.service-approval/controls/iac/` | `<slug>/05-generate/iac/` |
| 21 | `skills/generate/SKILL.md` (final validation) | reads all `05-generate/` | `.service-approval/controls/` | `<slug>/05-generate/` |
| 22 | `skills/test/SKILL.md`, `scripts/smoke-deploy-test.sh` | writes `test-results.json`, `deploy-logs/*`, `deployed-resources.json`; reads `05-generate/iac/` | `state/test-results.json`, logs to stdout | `<slug>/06-test/test-results.json`, `<slug>/06-test/deploy-logs/` |
| 23 | `skills/summarize/SKILL.md` | `APPROVAL-REPORT.md` (W); reads most state files | `.service-approval/APPROVAL-REPORT.md` | `<slug>/07-summarize/APPROVAL-REPORT.md` |
| 24 | `skills/evidence/SKILL.md` (NEW) | `08-evidence/*` (W); reads `mapping-results.json`, `validated.json`, `deployed-resources.json`, `05-generate/` tree | — | `<slug>/08-evidence/` |
| 25 | `skills/service-approval/SKILL.md` (orchestrator) | no writes; all `test -f` checks, `mkdir -p`, `rm -rf` | `.service-approval/state`, `.service-approval/controls`, `.service-approval/APPROVAL-REPORT.md` | `<slug>/**/*` (parametrized on slug) |
| 26 | `tools/validate/validate_state.py` | no writes; discovers sibling files via `os.path.dirname(file_path)` | any `.service-approval/state/` sibling | **No change** — already file-path-agnostic; siblings remain colocated per phase |
| 27 | `tools/validate/validate_controls.py::_find_state_dir` | walks up looking for `.service-approval/state/` | hardcoded | rewritten to walk up to `<slug>/` then pick `04-map/` for mapping-results / `03-validate/` for validated.json (see §3.1) |
| 28 | `tools/validate/validate_cross.py::_find_state_dir` | assumes `controls_dir parent + /state` | `controls/../state` | rewritten: `controls_dir parent + /04-map` (or pass `--state-dir` explicitly) |
| 29 | `tools/validate/validate_deployable.py` | reads from controls dir via argv | `controls_dir` param | **No change at call site** — caller passes `<slug>/05-generate/`; file-path-agnostic inside |
| 30 | `tools/validate/validate_kms_consumers.py` | detects `.service-approval/controls/iac/` via path substring | hardcoded | update substring to `/05-generate/iac/` (and keep legacy `/controls/iac/` as additional match for in-flight migration only during single worktree, no dual-path at merge time) |
| 31 | `tools/validate/hook_post_tool_use.py` | path-substring dispatch `/.service-approval/controls/` vs `/.service-approval/state/` | hardcoded | rewrite dispatch: if path matches `.service-approval/<slug>/05-generate/` → controls validator; else if `.service-approval/<slug>/0[1-7]-*/` → state validator |
| 32 | `tools/validate/hook_stop.py` | `controls_dir = cwd/.service-approval/controls` | hardcoded | scan `.service-approval/*/` for any dir containing `05-generate/`, iterate (handles multi-service repos) |
| 33 | `tools/validate/validate_pipeline_integrity.py` | `state_dir`, `controls_dir`, `iac_dir`, `APPROVAL-REPORT.md` | hardcoded | rewrite `validate_pipeline(root)` to iterate `root/.service-approval/*/` service dirs; per-service apply the same checks |
| 34 | `scripts/smoke-check-traceability.py` | `STATE_DIR`, `CONTROLS_DIR` | hardcoded top-level constants | add `--service=<slug>` CLI arg; resolve to `<slug>/04-map/` + `<slug>/05-generate/` |
| 35 | `scripts/smoke-validate-state.py` | `--state-dir` default `.service-approval/state` | argv default | default changes to `.service-approval/<slug>/` + phase dispatch (accepts `--phase=0..7`) |
| 36 | `scripts/smoke-deploy-controls.py` | `--controls-dir`, `--state-dir` defaults | argv defaults | defaults `<slug>/05-generate/` + `<slug>/04-map/`; add `--service=<slug>` |
| 37 | `scripts/smoke-deploy-test.sh` | `CONTROLS_DIR=".service-approval/controls/iac"` | shell var | shell var becomes `CONTROLS_DIR="${1:?service slug required}/05-generate/iac"` with explicit slug arg |
| 38 | `scripts/smoke-validate-controls.sh` | reads from `.service-approval/controls/` | shell var | similar — require slug arg, derive path |
| 39 | `.github/hooks/pipeline-integrity/validate.sh` | `test -d ".service-approval/state"` | hardcoded | update check: `test -n "$(ls -d .service-approval/*/ 2>/dev/null | head -1)"` |
| 40 | `manifest.yaml` (no direct path refs) | — | — | no changes |
| 41 | `tools/sync-ide-configs.py` | — | — | no path changes; but regenerates `powers/**`, so upstream steering file changes flow through |
| 42 | `powers/service-approval/steering/phase-research.md` | `fileMatchPattern: "**/.service-approval/state/research*.json"` | glob | `"**/.service-approval/*/02-research/research*.json"` |
| 43 | `powers/service-approval/steering/phase-validate.md` | `fileMatchPattern: "**/.service-approval/state/validated.json"` | glob | `"**/.service-approval/*/03-validate/validated.json"` |
| 44 | `powers/service-approval/steering/phase-map.md` | `fileMatchPattern: "**/.service-approval/state/map*.json"` | glob | `"**/.service-approval/*/04-map/map*.json"` + `"**/.service-approval/*/04-map/mapping-results.json"` |
| 45 | `powers/service-approval/steering/phase-generate.md` | `fileMatchPattern: "**/.service-approval/controls/**"` | glob | `"**/.service-approval/*/05-generate/**"` |
| 46 | `powers/service-approval/steering/pipeline.md`, `headless.md`, `structure.md`, `tech.md` | narrative refs | hardcoded | find-and-replace `state/` → `<service>/` with example slug + `controls/` → `<service>/05-generate/` |
| 47 | `powers/service-approval/POWER.md` | narrative | `.service-approval/state/mcp-calls.log` | `.service-approval/<service>/mcp-calls.log` |
| 48 | `powers/service-approval/agents-src/*.yaml` (14 agents) | paths embedded in prompts | `.service-approval/state/*` | update all 14 yaml prompts; then `tools/generate-kiro-agents.py` regenerates `cli/agents/*.json` + `ide/agents/*.md` |
| 49 | `powers/service-approval/ide/agents/*.md`, `cli/agents/*.json` | generated from `agents-src/*.yaml` | — | regenerated by #48 — no manual edits |
| 50 | `powers/service-approval/ide/hooks/post-tool-use.kiro.hook` | path pattern | `.service-approval/state/` | `.service-approval/*/0[1-7]-*/` |
| 51 | `.github/agents/service-approval.agent.md` | narrative | `.service-approval/state/` | rewrite to new layout |
| 52 | `.github/copilot-instructions.md` | narrative | `.service-approval/state/` | rewrite |
| 53 | `.github/prompts/service-approval.prompt.md` | narrative | `.service-approval/state/` | rewrite |
| 54 | `.github/plugins/service-approval/README.md` | narrative | `.service-approval/state/` | rewrite |
| 55 | `gemini-extension/commands/service-approval.toml`, `gemini-extension/GEMINI.md` | narrative | `.service-approval/state/` | rewrite |
| 56 | `commands/service-approval.md` | narrative | `.service-approval/` examples | rewrite |
| 57 | `AGENTS.md`, `README.md`, `CLAUDE.md` | narrative + tree diagram | `.service-approval/state/` etc. | rewrite all tree diagrams + path refs |
| 58 | `docs/TESTING-KIRO.md` | narrative | `.service-approval/` | rewrite |
| 59 | `rules/service-approval-safety.md` | safety list | `.service-approval/` paths | review — ensure no hardcoded path constraints |
| 60 | `.gitignore` | ignores | — | add `.service-approval/_staging/` to ignore; keep `.service-approval/*/05-generate/iac/**/node_modules/`, `.terraform/` patterns (already generic) |
| 61 | `tools/validate/test_*.py` (7 files) | test fixtures | in-memory or `tmpdir` | rewrite fixtures to new layout; tests that build synthetic state dirs must mimic `<slug>/0N-phase/` |
| 62 | Skill `test-results.json` schema sidecar (read by test skill, summarize) | extends with `deployed_resources[].arn`, `stack_id` | no change to schema | schema unchanged; tester populates `stack_id`, per-resource ARNs into `06-test/deployed-resources.json` (§4 consumption) |

### 3.1 Sibling-Discovery Rewrite Rules

Three validators walk the filesystem to find siblings. The rewrite preserves **colocation within a phase** so sibling lookups remain one-hop:

- **validate_state.py**: already uses `os.path.dirname(file_path)` → the phase dir. Within the map phase, `map-controls-generated.json`, `map-framework-parsed.json`, `map-framework-mapped.json`, `mapping-results.json` are all in `04-map/`. Siblings resolve correctly. **validated.json is in `03-validate/`, NOT `04-map/`.** Current validator looks for validated.json inside the same state dir when validating controls-generated — this breaks. **Fix:** `check_controls_generated` and `check_framework_mapped` walk up one level (`04-map/` → `<slug>/`) then into `03-validate/` for validated.json. Add a helper `_load_sibling_phase(state_dir, phase_prefix, filename)` that takes e.g. `"03-validate"` + `"validated.json"`.

- **validate_controls.py**: `_find_state_dir` walks up looking for `.service-approval/state/`. Rewrite to: walk up until the current dir's parent contains a child matching `0[0-9]-*/` pattern (the service root), then resolve `<service-root>/04-map/` as the "state dir" for mapping-results.json and `<service-root>/03-validate/` for validated.json. The function returns a dict `{"map": <path>, "validate": <path>, "assess": <path>}` rather than a single path, and `load_state_files` reads from the appropriate entry.

- **validate_cross.py**: `_find_state_dir(controls_dir)` currently does `parent(controls_dir)/state`. Rewrite: `parent(controls_dir)` IS the service root; resolve `<root>/04-map/` and `<root>/03-validate/` explicitly.

### 3.2 mcp-calls.log placement

Currently every skill writes to `.service-approval/state/mcp-calls.log`. The file is service-scoped (every MCP call during the run) but phase-agnostic. New home: `<slug>/mcp-calls.log`. `validate_pipeline_integrity.check_mcp_log` rewrites the lookup to `<slug>/mcp-calls.log` (iterates service dirs).

During the intake phase, there is no slug yet. Intake's MCP log (if any — there usually isn't, intake is deterministic) writes to `_staging/<ts>/mcp-calls.log`, promoted to `<slug>/mcp-calls.log` by the assess promotion step.

---

## 4. CLI Command Synthesis Rules

Phase 7 Evidence runs one CLI check per control and stores the raw output. Every command must:
- Target ONLY resources deployed by this workflow (ARN-scoped or stack-scoped).
- Emit deterministic JSON to stdout.
- Have a machine-checkable pass/fail predicate.

**Input state:** `<slug>/04-map/mapping-results.json` (control roster), `<slug>/03-validate/validated.json` (API surface + gateable_by metadata), `<slug>/06-test/deployed-resources.json` (stack ID + per-resource ARNs from Phase 5 deploy), `<slug>/01-assess/sar-facts.json` (service_prefix).

### 4.1 The `parameters_controlled` decoder (service-agnostic)

Every control has `parameters_controlled[]` of the form `$.<service-prefix>/<Operation>.<json-path>`. Example:
- `$.lambda/CreateFunction.KMSKeyArn` → `lambda:CreateFunction` request's `KMSKeyArn` property
- `$.lambda/TagResource.Tags` → `lambda:TagResource` request's `Tags` property

The decoder extracts three pieces:
```python
def decode_parameter_path(pc: str) -> tuple[str, str, str]:
    # pc like "$.lambda/CreateFunction.KMSKeyArn"
    # returns ("lambda", "CreateFunction", "KMSKeyArn")
    _, rest = pc.split("$.", 1)
    svc_op, *param_parts = rest.split(".", 1)
    service_prefix, operation = svc_op.split("/", 1)
    param_path = param_parts[0] if param_parts else ""
    return service_prefix, operation, param_path
```

This is the **core service-agnostic primitive**. Every CLI synthesis rule below consumes it.

### 4.2 Per-(scope, category, mechanism) CLI synthesis rules

The distinct mechanisms observed in the current Lambda pipeline (11 total) map to 6 synthesis families:

| Family | Mechanisms | Applies to (scope, category) cells | CLI rule |
|---|---|---|---|
| **F1 — Resource GET probe** | CloudFormation Guard, CloudFormation Hook, OPA Policy (PRO), AWS Config Rule (DET), Compensating Control Documentation | (ACC, PRO), (ACC, DET), (ACC, PRO) | `aws <service> describe-<resource>` on the deployed resource ARN; check that `parameters_controlled[]` properties are set to compliant values |
| **F2 — IAM simulate** | SCP, IAM Identity Policy, IAM Permission Boundary | (ORG, PRV), (ACC, PRV) | `aws iam simulate-custom-policy` / `simulate-principal-policy` with the non-compliant param values in `--context-entries` → expect `implicitDeny` / `explicitDeny` |
| **F3 — Config compliance poll** | AWS Config Rule (only) | (ACC, DET) | `aws configservice describe-compliance-by-config-rule --config-rule-names <rule>` + `get-compliance-details-by-config-rule` → expect rule exists AND compliant resource is `COMPLIANT` |
| **F4 — SSM document check** | SSM Automation, Lambda Remediation | (ACC, COR) | `aws ssm describe-document --name <doc>` → expect `Status=Active`; plus `aws ssm describe-association` for scheduled invocations |
| **F5 — CloudWatch alarm state** | CloudWatch Alarm | (ACC, DET) | `aws cloudwatch describe-alarms --alarm-names <a>` → expect present AND `StateValue in {OK, INSUFFICIENT_DATA}` for the non-firing baseline |
| **F6 — IaC-time supplemental** | CloudFormation Guard (static), OPA Policy (static), Checkov | (ACC, PRO) static half | NOT_CLI_VALIDATABLE at runtime; captured from `iac-time-evidence/` — verdict is PASS iff the Phase 4 lint pass succeeded |

### 4.3 Concrete synthesis algorithm

```python
def synthesize_cli(control: dict, validated: dict, deployed: dict, sar: dict) -> CliCheck:
    scope = control["scope"]            # ORG | ACC | RES
    category = control["category"]      # PRO | PRV | DET | COR
    mechanism = control["mechanism"]
    pc_list = control.get("parameters_controlled", [])
    actions = control.get("actions", [])
    resource_types = control.get("resource_types", [])

    # Decode first parameter to get (service_prefix, operation, property)
    if pc_list:
        svc, op, prop = decode_parameter_path(pc_list[0])
    else:
        svc = sar["service_prefix"]; op = None; prop = None

    # Family dispatch
    if mechanism in ("CloudFormation Guard", "CloudFormation Hook", "OPA Policy", "Compensating Control Documentation") and category == "PRO":
        # F1 — most PRO controls guard a create-time property.
        # The runtime evidence is: the resource was deployed WITH the property set compliant.
        # Pair with an IaC-time check (F6).
        return f1_resource_get_probe(svc, op, prop, deployed, resource_types) + f6_iac_time(control)

    if mechanism == "AWS Config Rule" and category == "DET":
        return f3_config_compliance(control, deployed)

    if mechanism in ("SCP", "IAM Identity Policy", "IAM Permission Boundary"):
        return f2_iam_simulate(control, actions, pc_list, deployed)

    if mechanism in ("SSM Automation", "Lambda Remediation") and category == "COR":
        return f4_ssm_doc_check(control, deployed)

    if mechanism == "CloudWatch Alarm":
        return f5_cloudwatch_alarm(control, deployed)

    # Fallback
    return CliCheck(verdict="NOT_CLI_VALIDATABLE",
                    reason=f"No synthesis rule for mechanism '{mechanism}' at ({scope}, {category})")
```

### 4.4 Family detail — F1 (Resource GET probe)

For a control like `CTRL-ACC-PRO-007` "Function must have VpcConfig set" on `AWS::Lambda::Function`:

```python
def f1_resource_get_probe(svc, op, prop, deployed, resource_types):
    # Find the deployed resource ARN matching resource_types[0]
    rt = resource_types[0]  # e.g. "AWS::Lambda::Function"
    arn = deployed.find_arn_by_cfn_type(rt)  # from 06-test/deployed-resources.json

    # Map AWS::Lambda::Function -> aws lambda get-function-configuration
    # Use a data table: data/cfn-to-describe-api.json keyed by CFN type
    describe_cmd = CFN_DESCRIBE[rt]   # e.g. ["lambda", "get-function-configuration", "--function-name"]
    cmd = ["aws", describe_cmd[0], describe_cmd[1], describe_cmd[2], name_from_arn(arn)]

    # Predicate: property MUST be set (non-null)
    query = f"--query {jsonpath_to_jmespath(prop)}"
    return CliCheck(
        command=" ".join(cmd + [query]),
        predicate=f"result != null and result != ''",
        verdict_on_match="PASS",
        verdict_on_mismatch="FAIL",
    )
```

The service-agnostic piece: `data/cfn-to-describe-api.json` is a lookup table (not code) — e.g.:

```json
{
  "AWS::Lambda::Function": { "service": "lambda", "operation": "get-function-configuration", "name_param": "--function-name", "name_source": "FunctionName" },
  "AWS::S3::Bucket":       { "service": "s3api",   "operation": "get-bucket-encryption",    "name_param": "--bucket",           "name_source": "BucketName" },
  "AWS::KMS::Key":         { "service": "kms",     "operation": "describe-key",             "name_param": "--key-id",           "name_source": "KeyId" }
}
```

This file grows by entry as new services onboard. An unknown CFN type emits a WARN + NOT_CLI_VALIDATABLE rather than silently failing.

### 4.5 Family detail — F2 (IAM simulate)

For a control like `CTRL-ORG-PRV-001` "SCP denies CreateFunction without KMSKeyArn":

```python
def f2_iam_simulate(control, actions, pc_list, deployed):
    # Build negative context: what should be DENIED
    # Example: attempt lambda:CreateFunction with no KmsKeyArn
    context_entries = build_negative_context(pc_list)  # e.g. --context-entries "ContextKeyName=lambda:KmsKeyArn,ContextKeyValues=,ContextKeyType=string"
    role_arn = deployed.execution_role_arn   # the role deployed by our workflow
    cmd = [
        "aws", "iam", "simulate-principal-policy",
        "--policy-source-arn", role_arn,
        "--action-names", *actions,
        "--context-entries", context_entries,
    ]
    return CliCheck(
        command=" ".join(cmd),
        predicate="EvaluationResults[].EvalDecision in ('implicitDeny', 'explicitDeny')",
        verdict_on_match="PASS",
        verdict_on_mismatch="FAIL",
    )
```

For SCPs not attached to an account used by the workflow, `simulate-principal-policy` with a placeholder principal (the test-run role ARN) is used to verify the SCP's logic; the OU-scoped enforcement is evidenced separately via `aws organizations list-policies-for-target`.

### 4.6 Family detail — F3 (Config compliance poll)

```python
def f3_config_compliance(control, deployed):
    rule_name = extract_rule_name_from_artifact(control)  # from 05-generate/detective/config-rules.json _metadata
    cmd = ["aws", "configservice", "get-compliance-details-by-config-rule",
           "--config-rule-name", rule_name]
    # Expect: deployed compliant resource appears with COMPLIANT; non-compliant negative-test resource appears with NON_COMPLIANT
    return CliCheck(
        command=" ".join(cmd),
        predicate="EvaluationResults[?EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId == deployed.function_name].ComplianceType == 'COMPLIANT'",
        verdict_on_match="PASS",
        verdict_on_mismatch="FAIL",
    )
```

### 4.7 Family detail — F4 (SSM)

```python
def f4_ssm_doc_check(control, deployed):
    doc_name = extract_doc_name_from_artifact(control)
    cmd = ["aws", "ssm", "describe-document", "--name", doc_name]
    return CliCheck(
        command=" ".join(cmd),
        predicate="Document.Status == 'Active' and Document.DocumentFormat != null",
        verdict_on_match="PASS",
        verdict_on_mismatch="FAIL",
    )
```

### 4.8 Family detail — F5 (CloudWatch alarm)

```python
def f5_cloudwatch_alarm(control, deployed):
    alarm_name = extract_alarm_name_from_artifact(control)
    cmd = ["aws", "cloudwatch", "describe-alarms", "--alarm-names", alarm_name]
    return CliCheck(
        command=" ".join(cmd),
        predicate="MetricAlarms[0].StateValue in ('OK', 'INSUFFICIENT_DATA')",
        verdict_on_match="PASS",
        verdict_on_mismatch="FAIL",
    )
```

### 4.9 Family detail — F6 (IaC-time supplemental)

Not a CLI runtime check. The Phase 4 `tools/validate/validate_deployable.py` run already produces logs. `/evidence` copies those logs into `08-evidence/iac-time-evidence/`:

- `cfn-guard.log` — from `cfn-guard validate` (invoked inside `validate_deployable`)
- `opa-eval.log` — from `opa eval` on generated `.rego` policies
- `checkov.log` — from `checkov -f <template>`
- `cfn-lint.log` — from `cfn-lint`

Verdict: `PASS` iff the corresponding lint tool's exit code was 0 in the Phase 4/5 run. Controls labeled as IaC-time-only (CloudFormation Guard rule file, etc.) reference these logs as their evidence instead of a runtime CLI.

### 4.10 NOT_CLI_VALIDATABLE controls

The plan must make explicit that every control is enumerated. Controls that genuinely cannot be CLI-validated get:

```json
{
  "control_id": "CTRL-ACC-PRO-007",
  "verdict": "NOT_CLI_VALIDATABLE",
  "reason": "Guard rule is template-time only; runtime verification is covered by CTRL-ACC-PRO-010 (the runtime KmsKeyArn GET probe).",
  "supplemental_evidence": "08-evidence/iac-time-evidence/cfn-guard.log"
}
```

This is NOT the default bucket. A control reaches `NOT_CLI_VALIDATABLE` ONLY if the synthesis function returns that verdict explicitly (i.e., no family matched or the family declared the control intrinsically non-runtime). The `/evidence` summary reports `NOT_CLI_VALIDATABLE_count` separately from `FAIL_count` so a reviewer can tell the difference between "we couldn't check" and "we checked and it failed".

### 4.11 Negative tests — proving the guardrail actually fires

For PRV controls and DET controls, the evidence is incomplete without a negative test. The skill supports an optional `--with-negative-tests` flag that:

1. Deploys a second, **intentionally non-compliant** resource alongside the compliant one (same stack, suffix `-nonconform`).
2. For DET controls: `get-compliance-details-by-config-rule` should show this one as `NON_COMPLIANT`.
3. For PRV controls: `simulate-principal-policy` with the non-conforming params should return `implicitDeny`.
4. For PRO controls: `cloudformation deploy` of the nonconform template should FAIL with a Guard/Hook rejection.

Negative tests are off by default (extra deploy cost + time). When enabled, each control gains a second CLI log `<ctrl>--negative.log`. `attestation-results.json` records both verdicts; only when both pass does the control earn `verdict=PASS_WITH_NEGATIVE`.

---

## 5. Evidence Artifact Schemas

### 5.1 `<slug>/08-evidence/cli-commands.json`

Authoritative mapping of control → generated CLI command. Produced FIRST (before execution) so a reviewer can audit commands before they run.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "schema_version": "1.0",
  "service": "AWS Lambda",
  "service_slug": "awslambda",
  "generated_at": "2026-05-13T11:30:00Z",
  "stack_id": "arn:aws:cloudformation:us-east-1:123456789012:stack/smoke-test-1747142400/...",
  "deployed_resources_ref": "../06-test/deployed-resources.json",
  "commands": [
    {
      "control_id": "CTRL-ACC-PRO-010",
      "family": "F1-resource-get",
      "synthesis_source": "parameters_controlled[0]=$.lambda/CreateFunction.KMSKeyArn",
      "command": "aws lambda get-function-configuration --function-name smoke-test-1747142400-fn --query KMSKeyArn --output json",
      "predicate": {"type": "jmespath", "expression": "not_null(@)"},
      "expected_pass": "KmsKeyArn is a non-empty ARN string",
      "expected_fail": "KmsKeyArn is null or empty",
      "output_log": "cli-outputs/CTRL-ACC-PRO-010--lambda-get-function-configuration.log"
    }
  ],
  "not_cli_validatable": [
    {
      "control_id": "CTRL-ACC-PRO-007",
      "reason": "CFN Guard rule operates at template-parse time; runtime equivalent is CTRL-ACC-PRO-010.",
      "supplemental_evidence": "iac-time-evidence/cfn-guard.log"
    }
  ]
}
```

**JSON Schema** (abbreviated, deposited at `schemas/cli-commands.schema.json`):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas/cli-commands.schema.json",
  "type": "object",
  "required": ["schema_version", "service", "service_slug", "generated_at", "stack_id", "commands", "not_cli_validatable"],
  "properties": {
    "schema_version": {"type": "string", "const": "1.0"},
    "service": {"type": "string", "minLength": 1},
    "service_slug": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$"},
    "generated_at": {"type": "string", "format": "date-time"},
    "stack_id": {"type": "string", "pattern": "^arn:aws:cloudformation:"},
    "commands": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["control_id", "family", "command", "predicate", "output_log"],
        "properties": {
          "control_id": {"type": "string", "pattern": "^CTRL-(ORG|ACC|RES)-(PRO|PRV|DET|COR)-\\d{3}$"},
          "family": {"type": "string", "enum": ["F1-resource-get", "F2-iam-simulate", "F3-config-compliance", "F4-ssm-doc", "F5-cw-alarm", "F6-iac-time"]},
          "synthesis_source": {"type": "string"},
          "command": {"type": "string", "minLength": 1},
          "predicate": {
            "type": "object",
            "required": ["type", "expression"],
            "properties": {
              "type": {"enum": ["jmespath", "regex", "exit_code", "jsonpath"]},
              "expression": {"type": "string"}
            }
          },
          "expected_pass": {"type": "string"},
          "expected_fail": {"type": "string"},
          "output_log": {"type": "string"}
        }
      }
    },
    "not_cli_validatable": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["control_id", "reason"],
        "properties": {
          "control_id": {"type": "string"},
          "reason": {"type": "string", "minLength": 20},
          "supplemental_evidence": {"type": "string"}
        }
      }
    }
  }
}
```

### 5.2 `<slug>/08-evidence/attestation-results.json`

Machine-readable verdict per control. Produced after command execution.

```json
{
  "schema_version": "1.0",
  "service": "AWS Lambda",
  "service_slug": "awslambda",
  "evidence_run_id": "2026-05-13T11:35:00Z",
  "stack_id": "arn:aws:cloudformation:us-east-1:123456789012:stack/...",
  "overall_verdict": "PASS",
  "counts": {
    "total_controls": 100,
    "pass": 87,
    "fail": 0,
    "not_cli_validatable": 13,
    "error": 0
  },
  "results": [
    {
      "control_id": "CTRL-ACC-PRO-010",
      "verdict": "PASS",
      "family": "F1-resource-get",
      "command": "aws lambda get-function-configuration ...",
      "exit_code": 0,
      "stdout_size_bytes": 127,
      "stderr_size_bytes": 0,
      "output_log": "cli-outputs/CTRL-ACC-PRO-010--lambda-get-function-configuration.log",
      "predicate_result": true,
      "predicate_evaluation": "result='arn:aws:kms:...' matches 'not_null(@)'",
      "elapsed_ms": 412,
      "timestamp": "2026-05-13T11:35:04Z"
    },
    {
      "control_id": "CTRL-ACC-PRO-007",
      "verdict": "NOT_CLI_VALIDATABLE",
      "reason": "Guard rule is template-time only.",
      "supplemental_evidence": "iac-time-evidence/cfn-guard.log",
      "iac_time_exit_code": 0
    }
  ]
}
```

**Schema** at `schemas/attestation-results.schema.json` — similar structure, enforces `verdict in {PASS, FAIL, NOT_CLI_VALIDATABLE, ERROR, PASS_WITH_NEGATIVE}`, `counts.total == pass + fail + not_cli_validatable + error`, etc.

### 5.3 `<slug>/08-evidence/attestation-report.md` (human-readable)

Control matrix table per category × scope, with status glyphs and links to raw output logs.

### 5.4 `<slug>/08-evidence/summary.md`

Top-level two-paragraph overview (verdict, coverage %, deploy success, key failures) for fast triage.

### 5.5 `<slug>/attestation.md` — the reviewer's audit guide (Feature 1)

Single file authored by `/summarize` (enhanced) + `/evidence`. Describes every artifact in the service tree:

```markdown
# Attestation Guide — AWS Lambda Service Approval

Generated 2026-05-13 by service-approval v3.1.0 on branch feature/evidence-attestation.
Verdict: APPROVED. Evidence: 100 controls, 87 PASS, 0 FAIL, 13 NOT_CLI_VALIDATABLE.

## How to review this directory

This tree substantiates the claim "AWS Lambda can be deployed compliantly against {framework}."
Each numbered phase directory contains one layer of the chain of custody:

### 00-intake/intake-manifest.json
- What: Operator-provided input (service name, framework, inputs folder).
- Upstream: Human operator (see inputs[].path values).
- Downstream: every phase reads service.name + framework settings.
- Claim it substantiates: "This run targeted AWS Lambda against CCMv4 with no customer threat model."

### 01-assess/sar-facts.json
- What: Authoritative IAM facts scraped from the AWS Service Authorization Reference page.
- Upstream: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html (source URL captured in file).
- Downstream: 02-research/research-capabilities.json, 03-validate/validated.json, 04-map/map-generate-controls, 05-generate/preventive (IAM actions, condition keys).
- Claim it substantiates: "Every IAM action and condition key referenced in generated controls exists on the SAR page for this service."

### 01-assess/checkpoint-results.json
- What: 9 factual checkpoint answers (RCP support, FIPS endpoints, Declarative policies, etc.).
- Upstream: 9 authoritative AWS doc URLs (captured in file).
- Downstream: 03-validate (SCP/RCP expressibility gates), 04-map, 05-generate.
- Claim it substantiates: "The service's capability boundary matches what AWS publicly documents."

### 01-assess/assessment-summary.md
- What: 5-domain CAF assessment with GAPS compliance matrix.
- Upstream: domains/*.md intermediate research + SAR + checkpoints.
- Downstream: 07-summarize/APPROVAL-REPORT.md Security Posture Assessment section.
- Claim it substantiates: "All known security posture gaps for this service were identified before control generation."

### 02-research/research.json (merged)
- What: Unified research bundle — existing mitigations + service capabilities + API surface + attack techniques.
- Upstream: research-mitigations.json, research-capabilities.json, research-api-surface.json, research-attack-surface.json (all same dir), each MCP-verified against awsknowledge / aws-documentation.
- Downstream: 03-validate/validated.json.
- Claim it substantiates: "Every capability and API we plan to control was verified against live AWS documentation on the run date."

### 03-validate/validated.json
- What: Post-MCP-verification view of research.json with per-item verification_note strings.
- Upstream: 02-research/research.json.
- Downstream: 04-map/map-controls-generated.json, 05-generate/* (condition keys, parameter paths, mutability).
- Claim it substantiates: "Every downstream control is grounded in an MCP-confirmed fact, not model guesswork."

### 04-map/mapping-results.json
- What: Final control inventory + threat-mitigation map + framework coverage.
- Upstream: validated.json, map-framework-parsed.json, map-controls-generated.json, map-framework-mapped.json (all previously emitted).
- Downstream: 05-generate/* (each generator reads the control roster), 08-evidence (CLI synthesis reads controls[]).
- Claim it substantiates: "The control set maps deterministically onto the customer's compliance framework, with every mapping rationale captured."

### 05-generate/{preventive,proactive,detective,responsive,iac}/
- What: Deployable artifacts — SCPs, Config rules, Lambda remediators, CFN/Terraform/CDK/CDKTF templates.
- Upstream: mapping-results.json, validated.json, iac-support.json.
- Downstream: 06-test (deployed), 08-evidence (validated via CLI probes).
- Claim it substantiates: "Every control in mapping-results.json has at least one deployable artifact."

### 06-test/test-results.json + deploy-logs/
- What: Phase 5 deployment outcome: deploy + verify + teardown cycle for each IaC format.
- Upstream: 05-generate/iac/**.
- Downstream: 08-evidence (reads deployed-resources.json for ARNs).
- Claim it substantiates: "The compliant-resource template actually deploys against a real AWS account and tears down cleanly."

### 07-summarize/APPROVAL-REPORT.md
- What: Customer-facing verdict with coverage matrix and traceability tables.
- Upstream: EVERY file above.
- Downstream: human reviewer.
- Claim it substantiates: "Here is the synthesized answer to 'Is this service approvable?' with evidence pointers."

### 08-evidence/
- What: Post-deploy runtime verification that each mapped control is actually enforced.
- Upstream: mapping-results.json (control roster), test-results.json (deployed resource ARNs), validated.json (API surface).
- Downstream: final reviewer.
- Claim it substantiates: "The generated controls aren't just written — they demonstrably fire in AWS against a live stack."
  - attestation-report.md — the control × verdict matrix
  - attestation-results.json — machine-readable form of the above
  - cli-commands.json — every CLI command and its predicate (auditable BEFORE execution)
  - cli-outputs/*.log — raw stdout/stderr of each probe
  - iac-time-evidence/ — supplemental linting output from Phase 4/5
  - deploy-evidence/ — copies from 06-test/deploy-logs/ to keep evidence co-located
  - summary.md — top-level triage digest

## Verification commands for an independent reviewer

To re-run every CLI probe without re-deploying:
  python3 tools/evidence/replay.py --service=awslambda --commands-file=<slug>/08-evidence/cli-commands.json --stack-id=<...>

To re-verify that every schema-bearing file is well-formed:
  python3 tools/validate/validate_state.py <slug>/01-assess/sar-facts.json
  python3 tools/validate/validate_state.py <slug>/03-validate/validated.json
  python3 tools/validate/validate_state.py <slug>/04-map/mapping-results.json
  python3 tools/validate/validate_evidence.py <slug>/08-evidence/attestation-results.json

## Source citations

- Service Authorization Reference: {sar_url}
- CloudFormation Template Reference: {cfn_ref_url}
- AWS Config Resource Types: https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html
- Compliance framework parsed: {framework_source_file}
```

This `attestation.md` is authored programmatically by a new helper in `/evidence` (template-driven; slots filled from state files), NOT hand-written per run.

---

## 6. The `/evidence` Skill — detailed spec

**File:** `skills/evidence/SKILL.md` (NEW)

**Frontmatter:**
```yaml
---
name: evidence
description: Run live AWS CLI probes against deployed compliant resources to prove each mapped control is enforced. Produces control x CLI x verdict matrix. Phase 7 of the pipeline.
disable-model-invocation: false
argument-hint: '[--service=<slug>] [--env=<profile>] [--with-negative-tests] [--replay] [--dry-run]'
---
```

**Preconditions:**
- `06-test/test-results.json` exists AND `test_results.passed == true`
- `06-test/deployed-resources.json` exists (new requirement on /test skill)
- `04-map/mapping-results.json` exists
- `03-validate/validated.json` exists

**Steps:**

1. **Service resolution** — `--service` flag or read from intake-manifest / sar-facts. Set `$SLUG = awslambda`.

2. **Load control roster** — read `mapping-results.json.controls[]` (100 controls in current Lambda run).

3. **Synthesize CLI commands** — for each control, run `tools/evidence/synthesize.py` (new) which dispatches to families F1–F6. Write `cli-commands.json` BEFORE executing anything — gives the reviewer the plan.

4. **Integrity gate** — validate `cli-commands.json` against `schemas/cli-commands.schema.json`. Every control from mapping-results.json.controls[] must appear either in `commands[]` or `not_cli_validatable[]`. If any are missing → ERROR halt.

5. **Execute probes** — for each entry in `commands[]`:
   - Run the command with a 30s per-command timeout.
   - Capture stdout + stderr + exit_code.
   - Persist to `cli-outputs/<ctrl-id>--<slug>.log` (text file with stdout header + stderr footer separated by a marker).
   - Evaluate the predicate against stdout (JMESPath via `jmespath` Python package, regex via `re`, or exit_code directly).
   - Record verdict + evaluation detail into attestation-results.json.

6. **Copy IaC-time evidence** — from the Phase 4/5 validate_deployable run logs (which get written to `06-test/deploy-logs/` now), copy into `08-evidence/iac-time-evidence/`. If the Phase 5 tester is run with `--dry-run`, Tier 1 logs still exist and still count as evidence for PRO controls.

7. **Copy deploy evidence** — hardlink/copy `06-test/deploy-logs/*` into `08-evidence/deploy-evidence/`. This keeps all evidence under `08-evidence/` for audit packaging.

8. **Write attestation-report.md** — template-rendered markdown control matrix.

9. **Write summary.md** — 2-paragraph human digest.

10. **Author `<slug>/attestation.md`** — render the template from §5.5 with live data.

11. **Update 07-summarize/APPROVAL-REPORT.md** — append an Evidence section linking to `08-evidence/` (or regenerate APPROVAL-REPORT.md with the new section; user's existing flow has `/summarize` emit this, but we let `/evidence` do a second pass to avoid a forward-dependency loop).

**Outputs:**
```
<slug>/08-evidence/cli-commands.json
<slug>/08-evidence/attestation-report.md
<slug>/08-evidence/attestation-results.json
<slug>/08-evidence/summary.md
<slug>/08-evidence/cli-outputs/*.log  (one per executed command)
<slug>/08-evidence/iac-time-evidence/*.log  (copied from 06-test/ + Phase 4 validate_deployable)
<slug>/08-evidence/deploy-evidence/*.log    (copied from 06-test/deploy-logs/)
<slug>/attestation.md
```

**New supporting files:**
- `tools/evidence/synthesize.py` — CLI command synthesizer (families F1-F6)
- `tools/evidence/execute.py` — command runner with predicate evaluator
- `tools/evidence/replay.py` — re-run commands against same stack for independent audit
- `tools/evidence/render_report.py` — attestation-report.md writer
- `tools/evidence/render_attestation.py` — `<slug>/attestation.md` writer
- `tools/validate/validate_evidence.py` — schema validator for attestation-results.json + cli-commands.json
- `schemas/cli-commands.schema.json`
- `schemas/attestation-results.schema.json`
- `data/cfn-to-describe-api.json` — CFN resource type → `aws <svc> describe-<r>` lookup (extend per service)

---

## 7. Regression Test Matrix

Every layer gets an automated regression check BEFORE merging to `main`. Tests run via `pytest tools/validate/` (existing CI gate).

| # | Test | Asserts | File |
|---|------|---------|------|
| R1 | `test_slug_derivation` | slug("AWS Lambda", "lambda") == "awslambda"; slug for multi-word products preserves hyphens; invalid chars rejected | `tools/validate/test_slug.py` (NEW) |
| R2 | `test_intake_staging_promotion` | intake writes to `_staging/<ts>/00-intake/`; assess promotes to `<slug>/`; stale `_staging/` cleaned by cleanup tool | `tools/validate/test_intake_promotion.py` (NEW) |
| R3 | `test_validate_state_new_layout` | validate_state.py accepts `<slug>/04-map/mapping-results.json`; sibling lookups find `<slug>/03-validate/validated.json` | extend `tools/validate/test_validate_state.py` |
| R4 | `test_validate_cross_new_layout` | validate_cross.py accepts `<slug>/05-generate/` as controls_dir; resolves `<slug>/03-validate/` + `<slug>/04-map/` | extend `tools/validate/test_validate_pipeline_integrity.py` |
| R5 | `test_hook_post_tool_use_dispatch` | hook dispatches correctly on `.service-approval/<slug>/05-generate/...` → validate_controls; on `.service-approval/<slug>/04-map/...` → validate_state | extend existing test (currently not present, add) |
| R6 | `test_hook_stop_multi_service` | hook_stop iterates all `<slug>/` dirs found at repo root; doesn't crash when zero exist | new |
| R7 | `test_pipeline_integrity_per_service` | integrity checks run per-service; MCP log path resolved to `<slug>/mcp-calls.log` | extend existing |
| R8 | `test_cli_synthesis_f1` | F1 synthesis of CTRL-ACC-PRO-010 emits a valid `aws lambda get-function-configuration` command | new, `tools/evidence/test_synthesize.py` |
| R9 | `test_cli_synthesis_f2` | F2 synthesis of CTRL-ORG-PRV-001 emits a valid `simulate-principal-policy` with correct context-entries | new |
| R10 | `test_cli_synthesis_f3..f6` | each family emits valid commands on fixtures | new |
| R11 | `test_cli_synthesis_full_coverage` | for every control in fixture `mapping-results.json`, either a command is emitted or a NOT_CLI_VALIDATABLE entry with reason >= 20 chars | new |
| R12 | `test_attestation_results_schema` | schema rejects missing verdict, malformed counts, verdict not in enum | new |
| R13 | `test_cli_commands_schema` | schema rejects bad predicate type, missing output_log | new |
| R14 | `test_end_to_end_lambda_smoke` | run `/service-approval` against Lambda fixture input, verify every expected file exists at new paths (dry-run, no AWS calls) | new end-to-end smoke; uses pre-recorded MCP responses fixture |
| R15 | `test_sync_ide_configs_no_drift` | existing gate — verifies `tools/sync-ide-configs.py --check` exits 0 after narrative doc edits | existing CI step, re-runs after doc rewrites |
| R16 | `test_legacy_path_refs_gone` | grep repo for `.service-approval/state/` — ONLY in plan/design docs and git history refs (no skill / script / validator hits) | new `test_no_legacy_path_refs.py` |
| R17 | `test_attestation_md_template` | rendering `attestation.md` with a fixture `<slug>/` produces stable output matching golden file | new |
| R18 | `test_deployed_resources_schema` | new `06-test/deployed-resources.json` has stack_id + resources[] with arn+cfn_type | new `test_deployed_resources.py` |

**Pre-merge gate:** R1–R18 all green + full `pytest tools/` + `python3 tools/sync-ide-configs.py --check` + `bash install.sh --check`.

---

## 8. Worktree Split — 6 parallel agents

Uses the `workshop-studio:split-work` pattern. Each worktree has a disjoint file surface and an explicit exclusion list. Branch names: `feature/evidence-attestation-W1` … `W6`. All converge back into `feature/evidence-attestation` via `worktree-merge` in the order given in §9.

### W1 — Foundations (blocks everything else)

**Files it owns (write access):**
- `tools/slug.py` (NEW) — canonical slug derivation
- `tools/paths.py` (NEW) — single-source path resolver: `service_root(slug)`, `phase_dir(slug, phase_name)`, `mcp_log(slug)`, `staging_dir(ts)`
- `data/slug-umbrellas.json` (NEW)
- `data/cfn-to-describe-api.json` (NEW)
- `schemas/cli-commands.schema.json` (NEW)
- `schemas/attestation-results.schema.json` (NEW)
- `schemas/deployed-resources.schema.json` (NEW)
- `tools/validate/validate_evidence.py` (NEW)
- `tools/validate/_schemas.py` — extend `SCHEMAS` dict with new entries
- `tools/validate/test_slug.py` (NEW)
- `tools/validate/test_paths.py` (NEW)

**Files EXCLUDED (no touch):**
- All `skills/**`
- `tools/validate/validate_state.py`, `validate_controls.py`, `validate_cross.py`, `validate_pipeline_integrity.py`, `validate_deployable.py`, `validate_kms_consumers.py`, `hook_*.py`
- All `scripts/**`
- All `powers/**`, `.github/**`, `gemini-extension/**`, `commands/**`
- `AGENTS.md`, `README.md`, `CLAUDE.md`, `docs/**`

**Exit criteria:** tests R1 green; `tools/paths.py` importable; schemas valid under draft-2020-12.

### W2 — Validators + Hooks rewrite

**Files it owns:**
- `tools/validate/validate_state.py` (sibling-discovery helpers)
- `tools/validate/validate_controls.py` (_find_state_dir rewrite)
- `tools/validate/validate_cross.py` (sibling discovery)
- `tools/validate/validate_pipeline_integrity.py` (per-service iteration)
- `tools/validate/validate_deployable.py` (no path change, but add unit test hooks)
- `tools/validate/validate_kms_consumers.py` (path substring update)
- `tools/validate/hook_post_tool_use.py` (dispatch rewrite)
- `tools/validate/hook_stop.py` (per-service iteration)
- `tools/validate/test_validate_state.py`, `test_validate_pipeline_integrity.py`, `test_validate_controls.py`, `test_validate_deployable.py`, `test_validate_kms_consumers.py`
- `tools/validate/test_no_legacy_path_refs.py` (NEW)
- `.github/hooks/pipeline-integrity/validate.sh` (presence check update)

**Files EXCLUDED:**
- All `skills/**`
- `tools/slug.py`, `tools/paths.py` (owned by W1 — imports only)
- All `scripts/**`
- `powers/**`, `.github/agents/**`, `.github/copilot-instructions.md`, `.github/prompts/**`, `.github/plugins/**`
- `gemini-extension/**`, `commands/**`
- Narrative docs

**Exit criteria:** tests R3, R4, R5, R6, R7, R16 green. Uses W1 helpers via import.

### W3 — Skill files rewrite (path-only)

**Files it owns:**
- `skills/intake/SKILL.md` + `intake-template.yaml`
- `skills/assess/SKILL.md` (add Step 0b: slug derivation + staging promotion)
- `skills/research/SKILL.md`
- `skills/research-mitigations/SKILL.md`
- `skills/research-capabilities/SKILL.md`
- `skills/research-api-surface/SKILL.md`
- `skills/research-attack-surface/SKILL.md`
- `skills/validate/SKILL.md`
- `skills/map/SKILL.md`
- `skills/map-parse-framework/SKILL.md`
- `skills/map-generate-controls/SKILL.md`
- `skills/map-framework-mapping/SKILL.md`
- `skills/map-assemble/SKILL.md`
- `skills/generate/SKILL.md`
- `skills/generate-preventive/SKILL.md`
- `skills/generate-detective/SKILL.md`
- `skills/generate-iac/SKILL.md`
- `skills/test/SKILL.md` (+ `deployed-resources.json` emission spec)
- `skills/summarize/SKILL.md` (path + append Evidence section link)
- `skills/service-approval/SKILL.md` (orchestrator — add Phase 7, parametrize paths on slug)

**Files EXCLUDED:**
- `skills/evidence/**` (W4)
- `tools/**`, `scripts/**`, `schemas/**`, `data/**`
- `powers/**`, `.github/**`, `gemini-extension/**`, `commands/**`
- Top-level narrative docs

**Exit criteria:** every SKILL.md's `test -f` and `mkdir -p` updated to use `<slug>/<NN>-phase/` pattern; tests R14 (dry-run end-to-end) green; sync-ide-configs not yet run (W6).

### W4 — Evidence skill + runner

**Files it owns:**
- `skills/evidence/SKILL.md` (NEW)
- `tools/evidence/__init__.py` (NEW)
- `tools/evidence/synthesize.py` (NEW) — F1–F6 dispatchers
- `tools/evidence/execute.py` (NEW)
- `tools/evidence/replay.py` (NEW)
- `tools/evidence/render_report.py` (NEW)
- `tools/evidence/render_attestation.py` (NEW) — writes `<slug>/attestation.md`
- `tools/evidence/templates/attestation.md.j2` (NEW) — Jinja2 template
- `tools/evidence/templates/attestation-report.md.j2` (NEW)
- `tools/evidence/templates/summary.md.j2` (NEW)
- `tools/evidence/test_synthesize.py` (NEW) — R8–R11
- `tools/evidence/test_execute.py` (NEW)
- `tools/evidence/test_render.py` (NEW) — R17
- `tools/evidence/fixtures/` (NEW) — sample `mapping-results.json`, `validated.json`, `deployed-resources.json` for unit tests

**Files EXCLUDED:**
- `skills/**` except `skills/evidence/`
- `tools/**` except `tools/evidence/`, `tools/slug.py` (import only), `tools/paths.py` (import only)
- `schemas/**` except the two new schemas (owned by W1 — read via import)
- Narrative docs

**Exit criteria:** `/evidence` skill loadable; tests R8–R13 + R17 green against fixture; can produce `08-evidence/` tree from a fixture `<slug>/` input.

### W5 — Scripts + CI

**Files it owns:**
- `scripts/smoke-deploy-controls.py` (arg defaults + slug resolver)
- `scripts/smoke-deploy-test.sh` (slug arg + path vars)
- `scripts/smoke-validate-controls.sh`
- `scripts/smoke-validate-state.py`
- `scripts/smoke-check-traceability.py`
- `scripts/map-assemble.py` (it does read `.service-approval/state/`; paths update)
- `.gitignore` (add `_staging/`)
- `Makefile` (add `make clean-staging`)

**Files EXCLUDED:**
- `skills/**`, `tools/**` (except script-adjacent imports)
- `powers/**`, docs

**Exit criteria:** scripts accept `--service=<slug>`; default fallbacks graceful when a single `<slug>/` exists under `.service-approval/`.

### W6 — Narrative docs + client-specific configs

**Files it owns:**
- `AGENTS.md`, `README.md`, `CLAUDE.md`
- `docs/**`
- `powers/service-approval/POWER.md`, `steering/*.md`, `agents-src/*.yaml` (14 files)
- `powers/service-approval/cli/agents/*.json`, `ide/agents/*.md`, `ide/hooks/post-tool-use.kiro.hook` (regenerated from agents-src + sync-ide-configs)
- `commands/service-approval.md`
- `.github/agents/service-approval.agent.md`
- `.github/copilot-instructions.md`
- `.github/prompts/service-approval.prompt.md`
- `.github/plugins/service-approval/README.md`
- `.github/hooks/pipeline-integrity/README.md`
- `gemini-extension/commands/service-approval.toml`
- `gemini-extension/GEMINI.md`
- `rules/service-approval-safety.md`
- Run `python3 tools/sync-ide-configs.py` and verify clean

**Files EXCLUDED:**
- `skills/**`, `tools/**`, `scripts/**`, `schemas/**`, `data/**`
- `manifest.yaml` (no changes needed)

**Exit criteria:** R15 (`sync-ide-configs --check`) green; tree diagrams in every doc match §1.

---

## 9. Convergence Order

Dependency graph:

```
W1 (foundations)
 ├─> W2 (validators) ──┐
 ├─> W3 (skills) ──────┤
 ├─> W4 (evidence) ────┼─> W6 (docs — reads all other worktrees' work)
 └─> W5 (scripts) ─────┘
```

**Merge sequence into `feature/evidence-attestation`:**

1. **W1 first** — everyone imports from `tools/slug.py`, `tools/paths.py`. Blocks all others.
2. **W2, W3, W4, W5 in parallel after W1** — no cross-file conflicts between them (disjoint surfaces).
3. **W6 LAST** — touches docs/configs derived from (or referencing) other worktrees. Runs `sync-ide-configs.py` as its final step to regenerate generated IDE configs. If agents-src was touched by W6 and clients haven't re-synced, the `sync-drift` CI gate fails.

**Integration test after each merge:**
- After W1: `pytest tools/validate/test_slug.py test_paths.py` + schema validation.
- After W2: full `pytest tools/validate/`.
- After W3: end-to-end dry-run smoke test R14 (Lambda fixture, no AWS calls).
- After W4: evidence-skill unit tests + end-to-end dry-run for `/evidence`.
- After W5: re-run R14 exercising new script paths.
- After W6: `sync-ide-configs --check` + full test suite + `install.sh --check`.

**Merge gate (full):** All R1–R18 green + lint clean + `sync-ide-configs --check` clean + fresh Lambda smoke-test-2.md produced with identical verdict.

---

## 10. Rollback Plan

The reorg is disruptive; a rollback path must exist.

**Rollback primitive:** `feature/evidence-attestation` is a branch off `integration/plugin-convergence-2026-05-13` (tip `eaf7fde`). Rollback = `git checkout <prior>` + redeploy plugin configs.

**Partial-ship scenarios:**

| Scenario | Detection | Remediation |
|---|---|---|
| W1 merged, W2 fails mid-merge | `pytest tools/validate/` fails | `git revert <W2 merge commit>`; W1 + `tools/paths.py` + `tools/slug.py` are additive and don't break old code (nothing imports them yet) — safe to leave. |
| W1+W2+W3 merged but W4 (evidence) incomplete | `/evidence` skill missing; rest of pipeline works on new layout | Do nothing — `/evidence` is opt-in. Orchestrator's Phase 7 is guarded by `if skill("evidence") exists`. |
| W1+W2+W3 merged, production run catastrophically breaks | end-to-end smoke fails on integration | `git revert` W2 and W3 as a pair (in reverse order). W1 additive-only remains. |
| Schema drift discovered post-merge | `validate_state.py` rejects a valid legacy file during audit | Schema helpers already accept both flat and phased layouts (W1 schemas are additive; validate_state.py sibling lookups use `os.path.dirname` which works for both). If a customer has a legacy `state/` tree, point them at a `tools/migrate-legacy-state.py` (W5 ships this utility — see below). |

**Legacy migration utility (ships in W5):**

`tools/migrate-legacy-state.py` — one-shot script for users with a `.service-approval/state/` + `.service-approval/controls/` tree. Reads `state/sar-facts.json`, derives slug, creates `<slug>/` tree, moves files into phase dirs. Idempotent. Emits a `.service-approval/.MIGRATED-<ts>` marker so repeated runs noop. Not invoked automatically — user runs it explicitly.

**No dual-path in code.** Per user spec, hard cutover. The migration utility is the rollforward path; the revert is the rollback path. No `if os.path.isdir(".service-approval/state"): ... else: ...` conditionals anywhere.

---

## 11. Known Risks & Mitigations

| # | Risk | Probability | Impact | Mitigation |
|---|------|-------------|--------|------------|
| 1 | sync-ide-configs regenerates agents from agents-src but agents-src narrative still references old paths | Medium | CI failure on W6 merge | Part of W6's checklist is to grep `agents-src/**` for `/state/` and `/controls/` after the find-and-replace pass. Run `sync-ide-configs` + `sync-ide-configs --check` before push. |
| 2 | Multiple services co-resident (user runs Lambda then S3 without `--clean`) — `<slug>/` trees coexist, but `hook_stop.py` iterates all of them on every run and validates both | Medium | Validation noise, possibly false failures if a prior `<slug>/` is stale | `hook_stop.py` new behavior: iterate `<slug>/` dirs but only process one whose `mcp-calls.log` mtime is within the last 24h (active run); otherwise skip and log. |
| 3 | `/evidence` can't find a deployed resource ARN because `/test` was skipped (`--dry-run`) | High | Phase 7 can't run | Skill precondition fails gracefully → `summary.md` says "Phase 5 was skipped; evidence deferred. Run `/test --env=<profile>` then `/evidence` to complete." No data written to 08-evidence/ to avoid half-states. |
| 4 | CLI command for a PRV control uses `simulate-principal-policy` but the SCP isn't attached to an account we control | High | Always looks like `implicitDeny` regardless of SCP being correct | Document clearly in `attestation-report.md`: SCP controls get `PASS_SIMULATED` not `PASS`; separate `PASS_ATTACHED` verdict available only if `aws organizations list-policies-for-target` shows the policy attached. |
| 5 | `cfn-to-describe-api.json` missing an entry for a new service — F1 synthesis fails | High | NOT_CLI_VALIDATABLE for every resource of that type | Explicit WARN + record in `summary.md.warnings[]`; don't block. User can add an entry and re-run. Add a coverage test: "for every `resource_types[]` value in `fixtures/mapping-results.json`, an entry exists in `cfn-to-describe-api.json`." |
| 6 | Per-service-dir explosion on a mono-repo running 20 services | Low | Disk usage, slow `rglob` | Accept — running 20 services is the target use case. Iteration performance is O(slugs × phases) which caps at <1000 dirs for 20 services. |
| 7 | Cross-service references (e.g., `validate_cross.py` accidentally picks up a neighbor service's controls dir when given ambiguous path) | Low | False validation errors | `_find_state_dir` rewrite is strict: walks until it finds a `04-map/` sibling. An ambiguous dir (no `04-map/` child) returns None and the validator bails with a clear error. |
| 8 | CI pytest runs in `/tmp/` without a `.service-approval/` tree — tests that scan filesystem break | Medium | CI red | R14 and R16 explicitly create fixture trees in `tmpdir` fixtures; nothing relies on repo-relative `.service-approval/`. |

---

## 12. Deliverables Checklist (for implementation tracking)

- [ ] W1 merged: slug + paths + schemas + evidence validators — Critical blocker.
- [ ] W2 merged: all 6 validator + 2 hook files rewritten; R3-R7, R16 green.
- [ ] W3 merged: 20 skill files updated; R14 (dry-run end-to-end) green.
- [ ] W4 merged: `/evidence` skill + runners + `attestation.md` template; R8-R13, R17 green.
- [ ] W5 merged: 7 scripts + Makefile + gitignore; legacy migration utility shipped.
- [ ] W6 merged: narrative docs updated; sync-ide-configs clean; R15 green.
- [ ] Final gate: full-repo `pytest`, `install.sh --check`, clean Lambda end-to-end smoke with `smoke-test-2.md` produced showing verdict parity with `smoke-test-1.md`.
- [ ] Post-merge: run evidence against Lambda stack; publish `08-evidence/` as the reference exemplar.

---

### Critical Files for Implementation

- /Users/tamg/WorkDocs/Builder/service-onboarding/skills/service-approval/SKILL.md
- /Users/tamg/WorkDocs/Builder/service-onboarding/tools/validate/validate_state.py
- /Users/tamg/WorkDocs/Builder/service-onboarding/tools/validate/validate_pipeline_integrity.py
- /Users/tamg/WorkDocs/Builder/service-onboarding/scripts/map-assemble.py
- /Users/tamg/WorkDocs/Builder/service-onboarding/tools/sync-ide-configs.py