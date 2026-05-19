# Pipeline Integrity Hook

Runs at `sessionEnd` — after every GitHub Copilot coding-agent session — to run the P1–P7 pipeline-integrity checks.

## What it does

Invokes `tools/validate/hook_stop.py` which runs:
- `validate_pipeline_integrity.py` — P1–P7 checks (MCP call count, unique verification notes, IAM policy logic, IaC parameterization, framework coverage rationale, verdict consistency, phase-output completeness)
- `validate_cross.py` — cross-artifact integrity
- `validate_deployable.py` — Tier 1 static validation

Exit code 2 on any failure. Copilot surfaces the failure and can self-correct in the next turn.

## Installation

Copilot auto-discovers `.github/hooks/*/hooks.json` when the repo is opened in VS Code with Copilot Chat in Agent mode. No install command needed.

## Manual testing

```bash
# With pipeline state present:
bash .github/hooks/pipeline-integrity/validate.sh
echo "exit: $?"

# With no state dir (should exit 0):
rm -rf .service-approval
bash .github/hooks/pipeline-integrity/validate.sh
echo "exit: $?"
```

## Disabling

To temporarily disable (e.g., during debugging):

```bash
mv .github/hooks/pipeline-integrity/hooks.json .github/hooks/pipeline-integrity/hooks.json.disabled
```

Re-enable by renaming back.

## Shared script

`validate.sh` wraps the same Python scripts Kiro's `ide/hooks/stop.kiro.hook` and Claude Code's `hooks.json` Stop matcher invoke. One source of truth; the hook wrapper adapts it to each client's invocation convention.
