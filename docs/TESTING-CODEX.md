# Codex compatibility test

On 2026-10-30, Codex completed Intake, Assess, all Research sub-skills, Validate,
Map, Recommended Guidance, and Summarize for Amazon Aurora DSQL with a custom
FINOS CCC relational database framework.

| Test condition | Recorded value |
|----------------|----------------|
| Repository commit | `d9a256ff9a0947d8d3f734597e420293b9c55b09` |
| Runtime | Codex with native subagents and existing MCP connections |
| Python | 3.14.6 in an existing virtual environment |
| Validation | Explicit per-phase validators and Stop-hook execution |
| Source changes during the run | None; generated output corrections were confined to runtime files |

| Check | Result |
|-------|--------|
| Repository validator and research-tool tests | 1,137 passed |
| Generated OPA 1.22.0 / Guard 3.2 synthetic cases | 36 passed |
| Generated detector tests using mocked AWS clients | 16 passed |
| Final combined checks | 27 passed, 0 failed |
| Final per-file artifact validation | 34 files checked, 0 failures |

The run included review and correction of generated artifacts. It initially
stopped at a stale reference to an untracked `CLAUDE.md` assessment checklist,
then continued using the Assess skill's own requirements. The shared checklist
and report-writing instructions are now versioned so future clients can resolve
those prerequisites from a clean checkout.

This record establishes execution with configured tools and explicit gates.
The October run predates the installer/hook integration below. It does not
establish clean-machine onboarding, no-MCP execution, live deployment, or AWS
API policy validation.
Passing checks also does not establish full framework coverage or resolve every
service-capability question.

The detailed evidence bundle remains outside the repository. Customer inputs,
threat-model snapshots, generated runtime state, and the output ZIP are not
included here. Follow [USAGE-CODEX.md](USAGE-CODEX.md) for a new run with your own
framework input; the new run records its own source version and evidence.

## Installer and hook adapter checks

The November 2026 integration adds manifest-generated Codex project configuration
to the common installers and sync command. Regression tests use temporary
workspaces and synthetic model inputs to exercise:

- Default and optional MCP configuration, idempotent sync, and preservation of
  unrelated configuration and hook handlers.
- External workspace setup and execution of generated hook commands from paths
  with spaces and nested Git directories.
- Multi-file patches, moves, deletion/replacement, and missing-model rejection
  before writes.
- Post-write validation of state and controls, including shell edits that preserve
  file size and timestamps, staging intake, and concurrent tool snapshots.
- Stop-time checks for unobserved invalid writes and the shared integrity validator.
- Shell installer install/sync/check/quiet modes and failure propagation.

These tests invoke the adapter with Codex's documented event payloads and execute
the generated commands. They do not grant native hook trust or claim a fresh
automatic end-to-end agent run. Codex's normal project/hook trust review must be
completed in the target client. The PowerShell wiring follows the same helper
and configuration but has not been executed on Windows in this test environment.
