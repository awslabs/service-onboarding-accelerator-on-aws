# Changelog

All notable changes to the service-approval pipeline are documented here.

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
