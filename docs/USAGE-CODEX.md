# Using Service Approval with Codex

Codex runs the shared Agent Skills pipeline: Intake → Assess → Research →
Validate → Map → Recommended Guidance → Summarize. It uses the same installer,
manifest, and validators as the other supported clients.

## Setup

Install the [common prerequisites](../README.md#prerequisites), including the
repository's Python requirements and `uv`, then run the common installer:

```bash
./install.sh
# Windows PowerShell: .\install.ps1
```

This generates `.codex/config.toml` (MCP servers) and `.codex/hooks.json`
(validation hooks) from the shared configuration. Open the project in a current
Codex version with lifecycle-hook support. Trust the project and review/trust
the hooks using Codex's **Review hooks** / **Settings → Hooks**, or `/hooks`
in the CLI. Codex requires this review before running non-managed hooks, and
requires another review when definitions change. The installer never grants
trust or changes approval settings.

See [MCP configuration](MCP.md#codex) and
[OpenAI's hook documentation](https://developers.openai.com/codex/hooks).

Codex reads `AGENTS.md` and discovers skills under `.agents/skills/`. This
repository already supplies that discovery symlink. Open the clone in Codex to
work on the harness itself. See [OpenAI's skill documentation](https://developers.openai.com/codex/skills/)
for discovery locations and symlink support.

## External customer workspace

For a customer run, create a separate workspace so inputs, downloaded threat
models, generated state, and review ZIPs stay outside the source checkout.
The following macOS/Linux example starts from the cloned repository root:

```bash
SA_REPO="$(pwd)"
SA_RUN="$HOME/service-approval-runs/dsql"
"$SA_REPO/.venv/bin/python" "$SA_REPO/tools/setup-codex.py" --workspace "$SA_RUN"
```

The helper installs the same MCP/hook configuration and links shared instructions.
It preserves unrelated settings and refuses conflicting instruction files.
Add `--check` to preview without writing. On Windows, use the repository's
`.venv\Scripts\python.exe`; Developer Mode or suitable symlink permissions are
required. Open `SA_RUN` in Codex and complete the same project/hook trust review.
Re-run this helper after pulling updates so the external configuration refreshes.

In the run workspace, ask Codex to resolve the skill symlink to the installed
repository and use:

- The repository virtual environment's Python interpreter.
- The external run workspace as the working directory for every pipeline command.
- Absolute paths for repository scripts and bundled references. For module
  commands (`python -m tools.validate...`), put the repository on `PYTHONPATH`.

For example, in a shell where `SA_REPO` and `SA_RUN` are set as above:

```bash
cd "$SA_RUN"
export PATH="$SA_REPO/.venv/bin:$PATH"
export PYTHONPATH="$SA_REPO${PYTHONPATH:+:$PYTHONPATH}"
```

Set these for each execution environment that runs commands; a shell export does
not configure an already-running Codex session. Agents must pass the equivalent
working directory, interpreter, and module path on their tool calls. Do not
change into the source checkout to run pipeline commands: some final validators
discover runtime state directly from the current working directory.

## Verify setup

Ask Codex to confirm that it can:

1. Read the linked `AGENTS.md` and `.agents/skills/service-approval/SKILL.md`.
2. Import `yaml` and `jsonschema` with the selected Python interpreter.
3. Search AWS documentation through both required MCP servers and read an
   applicable official AWS page with the available documentation tools.
4. Reach GitHub for Intake's published threat-model retrieval.
5. Show the Service Approval PreToolUse, PostToolUse, and Stop hooks as trusted
   and enabled in the native hook settings.

Use the existing connected tools if their names carry a client or plugin prefix.
Match their documented capabilities to the skills' requested operations.
Keep the canonical MCP log entries required by the orchestrator. Setup searches
do not substitute for the service research performed during the run.

`./install.sh --check` checks generated configuration without changing it.
Native trust and connectivity must also be verified in the active session.

## Run the pipeline

Example prompt for an external run workspace:

```text
Read AGENTS.md and follow .agents/skills/service-approval/SKILL.md.
Run the complete pipeline for Amazon Aurora DSQL with --framework=custom
and --framework-file=/absolute/path/to/customer-inputs/ccc-rdms-catalog.md.
Use this external workspace as the working directory and resolve scripts and
references from the linked skill's repository. Use that repository's Python
virtual environment and put the repository on PYTHONPATH for module commands.
Run every phase and review gate, and address all validation feedback.
At completion, give me the summary and package the run outputs into a ZIP
in this workspace for review.
```

Replace the framework path with your own file. These are skill arguments in a
prompt, not Codex CLI flags. Intake retrieves the published AWS Threat Model;
do not supply an unverified local model to replace it.

The orchestrator can use Codex's native subagents for independent research and
review. It respects the available concurrency and waits at phase boundaries.
Where subagents are unavailable, it uses the sequential path and retains the
same checks and review requirements.

## Validation

Trusted project hooks run automatically:

- **PreToolUse:** gate explicit patch/write destinations on the published-model
  prerequisite, including multi-file patches and moves.
- **PostToolUse:** validate edited state and controls. Shell commands are checked
  by comparing content hashes before and after execution inside the active run
  workspace; post-validation cannot undo a write that already occurred.
- **Stop:** recheck phase files and invoke the shared cross-artifact/integrity
  hook before accepting completion.

The adapter uses the repository virtual environment when available. Hooks do not
replace the semantic reviews and phase gates in the skills: the agent still
performs the mapping review, reference/enforcement checks, generation review,
conflict review, and published-model revalidation. Fix failures before downstream
phases consume the output.

Keep shell commands and artifact writes in the selected runtime workspace so
automatic checks can discover them. If hooks are disabled, untrusted, or
unavailable in the client version, enable/review them in Codex. For diagnosis,
the shared validators can also be run explicitly as shown below; disclose any
run where automatic hooks were inactive.

Run all commands from the external runtime workspace with the repository Python
environment. For example, after Map completes:

```bash
python3 "$SA_REPO/tools/validate/check_phase_complete.py" --slug dsql --phase 04-map
```

To diagnose final validation or independently verify a run, check all phase
outputs and run the shared validators. This complements automatic hooks and the
per-phase checks/reviews:

```bash
set -e
for phase in 00-intake 01-assess 02-research 03-validate 04-map 05-recommended-guidance 06-summarize; do
  python3 "$SA_REPO/tools/validate/check_phase_complete.py" --slug dsql --phase "$phase"
done
python3 "$SA_REPO/tools/validate/validate_pipeline_integrity.py"
python3 "$SA_REPO/tools/validate/validate_cross.py" \
  .service-approval/dsql/05-recommended-guidance
python3 "$SA_REPO/tools/validate/hook_stop.py"
```

Replace `dsql` with the canonical slug for another service. Capture each check's
result in the run diagnostics. A Stop-hook exit of zero on an empty directory,
or a `snoozed` result after repeated failures, does not prove success. The phase
checks, direct integrity check, and direct cross-artifact check must pass.

Optional artifact engines and Tier 2 AWS checks have their own prerequisites.
Disclose unavailable tools and skipped checks rather than reporting them as passed.

## Outputs and resume

The summary is `.service-approval/dsql/06-summarize/SUMMARY-REPORT.md` inside the
external workspace. Recommended controls are under
`.service-approval/dsql/05-recommended-guidance/`; logs, phase state, and the pinned
source snapshot remain alongside them.

To resume, reopen the same workspace and ask Codex to follow the orchestrator's
resume procedure. It revalidates the original intake and snapshot before
continuing from the last complete phase. Do not alter the snapshot or intake seal
to make a different workspace pass. An explicit new run retrieves the latest
published model.

Keep customer inputs, model snapshots, model-derived runtime state, and output
ZIPs outside Git, including PR attachments. A passing workflow does not mean every
framework objective is covered; review the unresolved items and generated guidance.
See the [test record](TESTING-CODEX.md) for the DSQL/custom CCC run and the
installer/adapter regression coverage. These checks do not deploy resources or
validate policies against a live AWS account.
