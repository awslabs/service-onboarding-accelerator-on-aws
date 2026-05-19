# Changelog

All notable changes to the service-approval pipeline are documented here.

## [Unreleased] — integration/2026-05-18

### Fixed
- **Stop-hook 17-hour identical-failure loop** — added two prevention
  mechanisms: a `[pipeline:complete:<VERDICT>]` terminal-state sentinel
  emitted by `summarize` and `evidence` that exempts finalized runs from
  P1 (MCP-call-count gate), and a 3-fail snooze backstop in
  `tools/validate/hook_stop.py` that suppresses identical hook:stop:fail
  loops with no progress between fires.
- **Verdict-tag bash transform** — single-pass `tr` did not fold spaces
  in `APPROVED with exceptions`; switched to two-pass uppercase + space-or-hyphen → underscore.
- **Evidence verdict extraction** — grep regex did not match the actual
  `## Verdict` H2 + bold line shape; switched to awk extraction with
  parens-strip canonicalization for `APPROVED (test not run)`.
- **License divergence** — `POWER.md` and `powers/README.md` said MIT;
  aligned with `LICENSE`/`manifest.yaml` at Apache-2.0.
- **R16 controls-side regex** — symmetrized with state-side close-quote
  alternation; literal `Path(".service-approval/controls")` no longer evades.
- **R16 trip-case drift** — production patterns and trip-case patterns
  unified into module-level constants.
- **`_action_matches_wildcard_only`** — dropped glob-expansion branch
  (SAR data is incomplete; literal-only matching keeps the carve-out tight).
- **`_load_wildcard_only_actions` empty-prefix guard** — bare actions
  with no prefix and an empty fallback no longer enter the set as `:Action`.
- **Manifest path drift** — `manifest.yaml clients.kiro` paths now match
  the actual filesystem layout (`cli/agents/`, `ide/agents/`, `ide/hooks/`).
- **Stale `hooks/stop.json` references** in 7 docs replaced with
  `ide/hooks/stop.kiro.hook` (real path under `powers/service-approval/`).

### Changed
- **Framework scope narrowed** to CCMv4 for interactive intake;
  multi-framework parsing remains via `--framework=<type>` CLI flag for
  advanced operators. Updated marketing/metadata across `manifest.yaml`,
  `README.md`, `POWER.md`, `powers/README.md`, `pipeline.md`, plus scope
  notes in `summarize`, `map`, `map-parse-framework` SKILL.md.
- **Pipeline integrity validator docstring** — added P1 sentinel
  exemption note; corrected `_load_wildcard_only_actions` docstring
  about cross-service floor.

### Removed
- **kiro-cli install code path** from `install.sh`. The Kiro IDE manual
  install is now the supported flow; cascade docs (`docs/TESTING-KIRO.md`,
  `skills/service-approval/SKILL.md`, `powers/service-approval/README.md`,
  `powers/service-approval/steering/headless.md`) carry deprecation
  banners pending a full kiro-cli runtime decision.

### Added
- **Plugin marketplace registration** in `install-claude.sh` —
  `claude plugin marketplace add` lets `/service-approval` invoke from
  any working directory, not just when this repo is open.
- **Kiro guardrails into install.sh sync path** —
  `block-direct-state-writes.kiro.hook` and
  `service-approval-enforcement.md` now live in
  `powers/service-approval/ide/hooks/` and `steering/`, picked up by
  install.sh's existing `*.kiro.hook` and `*.md` globs.
- **8 unit tests** for snooze logic (threshold, JSON-escape round-trip,
  progress-event reset, sub-threshold count); 4 sentinel-anchoring
  tests; wildcard-only literal-only carve-out tests; empty-prefix guard tests.
- **R16 helper-test fail-closed** — `_git_or_skip()` now used by the
  positive-trip case and the parametrize evasion suite, fail-closed
  under `CI=true`.
- **APPROVAL-REPORT.md H3 → H2 verdict header** — promoted 13 section
  headers in the `summarize` template to match the `evidence` awk
  sentinel emit and `validate_pipeline_integrity` P6 verdict regex
  (both anchor on H2). Tightened the P6 regex with `(?<!#)##(?!#)`
  lookarounds so H3 substring no longer matches as H2.
- **P5 + P6 silent fail-open** — `check_framework_coverage` (P5) and
  `check_verdict_consistency` (P6) now append explicit `P{N} FAIL`
  errors instead of returning `[]` on missing/corrupt input. Same
  Probe 33 fix-shape that closed P2 earlier.
- **Snooze reset semantics** — `_should_snooze` now resets on any
  non-fail event regardless of position; matches the docstring's
  "any non-`hook:stop:fail` event resets" claim.
- **Stop hook + validator docstrings** — `hook_stop.py` rewritten to
  enumerate all three validators (cross + deployable + integrity)
  and the strict-by-default integrity behavior;
  `validate_pipeline_integrity.py` failure-signal block updated to
  note the P1 sentinel exemption for finalized runs and replace P3's
  aspirational "inverted SCP, permissive boundaries" wording with the
  three checks the validator actually performs (mismatched
  StringEquals/StringNotEquals keys, broad Allow on Resource:* without
  Condition, SCP without Deny).
- **P1–P7 cascade across 8 customer-facing surfaces** — `POWER.md`,
  `powers/README.md`, `pipeline.md`, `headless.md`, `manifest.yaml`,
  `.github/hooks/pipeline-integrity/README.md`, `stop.kiro.hook`,
  `tech.md` all now mirror the validator's actual P-check list with
  cultural rules factored to `service-approval-enforcement.md`
  (Hard Rules 5 + 6 added there to close the redirect-target gap).
- **Drift-prone absolute counts dropped** — `TESTING-KIRO.md`,
  `tools/README.md`, `structure.md` replaced "13 sa-*.md /
  9 steering / 18 SKILL.md / 11 JSON Schema files / 205 tests"
  idioms with self-validating wording (e.g.,
  "matches `powers/service-approval/<dir>/`",
  "one *.schema.json per pipeline state file").
- **Skill SKILL.md line-79 cites** — `assess`, `research-api-surface`,
  `research-capabilities`, `validate` replaced
  `validate_pipeline_integrity.py:79` with symbol references to
  `_MCP_CALL_TOKEN_RE` so future docstring rewrites don't re-break.
- **POWER.md sub-skill count** — 20 → 21 (matches on-disk skills/
  count, README.md, pipeline.md, manifest.yaml).
- **Validator fail-close contract** — added an audit-result comment
  block above `validate_pipeline()` documenting the contract for
  every `check_*()` function so future contributors don't re-introduce
  the silent-fail-open pattern.

## [Unreleased] — feature/smoke-test-lambda-e2e

### Added — Consolidated pipeline audit log

A single `pipeline.log` per service captures the full debugging timeline.
One file per service consolidates hooks, MCP calls, skill lifecycle, and
subprocess invocations — `tail -f` shows the run as it progresses,
`grep ":fail" pipeline.log` finds breakages, and event causality is
visible at a glance.

```
.service-approval/<slug>/pipeline.log
```

Line format:

```
<UTC-iso8601> [<phase>] [<source>:<verdict>]  <message> [k=v ...]
```

**Sources logged:**
- `hook:post-tool-use` / `hook:stop` / `hook:check-phase-complete` / `hook:legacy-detected`
- `mcp:<server>` (verdict `call` or `response`)
- `skill:<skill-name>` (verdict `start` / `end` / `retry` / `halt`)
- `script:<script-name>` for subprocess invocations

**Components:**
- `tools/validate/_hook_log.py` — the logger module. Single API
  (`log_event`); convenience helpers (`log_skill`, `log_mcp`, `log_script`);
  backward-compat aliases (`log_hook_fire`, `log_phase_event`) so existing
  callers keep working.
- `tools/validate/log.py` — bash-friendly CLI. Skills call
  `python3 -m tools.validate.log --slug <slug> --phase <NN-phase>
  --source skill:<name> --verdict start|end|retry|halt --message "..."`
  to emit lifecycle events without re-implementing the format.
- All three hooks (`hook_post_tool_use`, `hook_stop`,
  `check_phase_complete`) write to pipeline.log on every fire.
- Backward-compat: MCP events also shadow to `mcp-calls.log` so older
  tools that grep that file keep working. Stop-hook P1 reads MCP count
  from pipeline.log first, falls back to mcp-calls.log.

**Replaces** the earlier per-phase `.hooks.log` design (3 nested files
per phase) — single file is far better for debugging timelines.

**Test count:** 338 → 353 (added 15 tests for the consolidated logger
and P1's pipeline.log integration).

### Added — Pre-phase precondition gate + P7 Stop-hook safety net

- **`tools/validate/check_phase_complete.py`** — new CLI invoked by every
  downstream skill as a precondition. Reads `PHASE_REQUIRED_OUTPUTS` from
  `validate_pipeline_integrity.py` (single source of truth), exits 2 with
  clear errors if any required artifact is missing or below its size
  threshold. Halts the pipeline BEFORE wasting time on a doomed downstream
  phase. Closes the gap where Phase 4 (Generate) would silently start with
  missing Phase 3 (Map) outputs.
- **P7 Stop-hook check** in `validate_pipeline_integrity.py` — safety net
  that runs at end-of-run. Walks each per-slug `<slug>/<NN>-phase/` dir
  and validates declared outputs exist + meet min-size thresholds. Catches
  the case where a contributor edited the per-skill precondition but
  forgot to update the gate.
- **Skills wired** with the precondition gate: map-assemble, generate,
  test, summarize, evidence. Each has a "Hard gate — verify upstream
  phases produced their outputs" block at the top of its Prerequisites
  section that exits 2 if check_phase_complete fails.
- **Test count:** 322 → 338 (added 16 tests for the new CLI + gate).

## [Unreleased] — feature/evidence-attestation (MR !14)

### Added — Phase 7 Evidence

- **New phase: Phase 7 Evidence (`skills/evidence/`)** — runs live AWS CLI probes
  against deployed compliant resources to produce a control × verdict matrix
  proving each mapped control is actually enforced at runtime.
- **6 CLI synthesis families** (service-agnostic, no hardcoded service names):
  F1 resource GET probe, F2 IAM simulate-principal-policy, F3 Config compliance,
  F4 SSM document check, F5 CloudWatch alarm state, F6 IaC-time supplemental.
- **Evidence outputs** at `<slug>/08-evidence/`: `cli-commands.json` (audit-able
  pre-execution), `attestation-results.json` (post-execution verdicts), raw
  `cli-outputs/*.log` per probe, plus `<slug>/attestation.md` reviewer's audit
  guide at the service root.
- **`sa-evidence` agent** registered for Kiro CLI + IDE.

### Added — Per-service per-phase layout

- **Layout reorg:** `.service-approval/state/` (flat) → `.service-approval/<slug>/<NN>-<phase>/`
  (per-service, per-phase). Every skill, validator, hook, and script that
  reads/writes state files updated in lockstep.
- **Controls fold from `.service-approval/controls/<family>/` into
  `.service-approval/<slug>/05-generate/<family>/`.**
- **Slug derivation** (`tools/slug.py`): canonical service slug from SAR
  service_prefix; matches `^[a-z0-9][a-z0-9-]{0,62}$`.
- **Path resolver** (`tools/paths.py`): single-source helpers `phase_dir(slug, phase)`,
  `service_root(slug)`, `staging_dir(ts)`. All paths anchor on `manifest.yaml`
  and validate slug + assert under `.service-approval/` jail.
- **JSON Schemas** (Draft 2020-12): `cli-commands.schema.json`,
  `attestation-results.schema.json`, `deployed-resources.schema.json`.

### Added — Stack lifecycle for Phase 7

- **Phase 5 → Phase 7 keep/teardown semantics:** Phase 5 leaves the deployed
  CFN stack alive when Phase 7 is in scope (passes `--keep` to
  `smoke-deploy-test.sh`). Phase 7 owns teardown — tears down at end of
  evidence collection unless `intake.testing.keep == true`.
- **`teardown_status` field** added to test-results.json + attestation-results.json
  with enum: `completed | skipped_keep_true | failed | not_attempted | deferred_to_phase_7`.

### Changed — Skill semantics

- **Intake precursor**: writes to `.service-approval/_staging/<ts>/00-intake/`
  before slug is known. Phase 0 promotes staging → `<slug>/` after deriving
  the canonical slug from SAR.
- **`testing.keep` semantics**: now controls Phase 7's end-of-run teardown,
  not Phase 5's. Phase 5 always defers when Phase 7 is in scope.

### Added — Drift / regression gates

- **CI sync-drift job** now runs both `tools/sync-ide-configs.py --check`
  and `tools/generate-kiro-agents.py --check` (catches drift between
  `agents-src/*.yaml` and the regenerated cli/ide mirrors).
- **CI unit-tests job** now runs `pytest tools/validate/ tools/evidence/ -q`
  (previously omitted the evidence module's 22 tests).
- **CI shellcheck job** lints `scripts/smoke-deploy-test.sh`, `install.sh`,
  `.githooks/*`.
- **R16 regression test** (`test_no_legacy_path_refs.py`): now fail-closed
  under `CI=true` env var, regex pass for dynamic constructions
  (`Path(".service-approval") / "state"`), strict allowlist (production code
  paths under `skills/`, `powers/`, `scripts/` no longer exempt). Includes
  positive trip-case test.
- **`.githooks/pre-commit`** enforces sync-drift + R16 at commit time.
- **Path traversal defense**: `tools/paths.py` validates slug regex and
  asserts resolved paths stay under `.service-approval/` jail.

### Fixed — Critical security + correctness

- **Shell injection eliminated** in `tools/evidence/execute.py`:
  `subprocess.run(shell=True)` replaced with `shell=False` + `command_argv: list[str]`.
- **F1 → F6 silent downgrade fixed**: empty `parameters_controlled` now
  returns NOT_CLI_VALIDATABLE with `reason_code: "missing-metadata"` instead
  of masquerading as IaC-time-only.
- **F6 reason gameable**: now requires `reason_code` enum + `supplemental_evidence`
  file existence check on disk (where applicable).
- **F2 arbitrary role**: requires explicit `principal_arn` on PRV controls;
  NOT_CLI_VALIDATABLE if 0 or >1 deployed roles can be auto-resolved.
- **F3/F4/F5 invented names**: replaced with deployed-resources lookup by
  cfn_type; NOT_CLI_VALIDATABLE if no deployed resource matches.
- **CLI commands now thread `--region`** from `stack_id` ARN parsing so probes
  hit the same region as the deployed stack.

### Fixed — Correctness

- **Coverage invariant test** parameterized over `(mechanism, category, scope)`
  tuple space (was tautological `len(cli)+len(ncv)==len(controls)`); F5 row
  added to fixture.
- **Jinja2 templates** add markdown-safe sanitizer for CLI stdout/stderr that
  flows into reports (prevents broken matrix tables on AWS error messages).
- **Per-command atomic write** in execute.py + retry+jitter on
  `ThrottlingException` / `RequestLimitExceeded`.
- **Chain-of-custody** (`render_attestation.py`): `pipeline_version`,
  `git_commit`, `operator` resolved from `manifest.yaml` + `git rev-parse HEAD`
  instead of hardcoded placeholders.

### Fixed — Other

- **Legacy `mkdir -p .service-approval/state` runtime refs** removed from
  `skills/map-generate-controls/SKILL.md`, `skills/map-parse-framework/SKILL.md`,
  `skills/research-attack-surface/SKILL.md`.
- **Manifest mismatch**: `manifest.yaml` license aligned to Apache-2.0 (was
  MIT, but LICENSE file is Apache-2.0).
- **`evidence` skill registered** in `manifest.yaml` skills list.
- **Windows installer** (`install.ps1`) now calls `sync-ide-configs.py` +
  `generate-kiro-agents.py` (was missing both).
- **Phase 7 skip artifact**: when Phase 7 is skipped, `08-evidence/phase-skipped.json`
  records the reason instead of leaving an audit hole.
- **`hook_post_tool_use.py`** emits one-time migration warning marker when
  legacy `state/` or `controls/` writes are detected mid-upgrade.
- **Smoke-deploy-test.sh**: per-slug IaC path discovery (was hardcoded
  `.service-approval/controls/iac`); `--keep` flag for Phase 7 handoff;
  `--slug=<slug>` arg with auto-discovery.

## Earlier history

This is the first CHANGELOG entry. See `git log` for pre-MR-!14 history.
