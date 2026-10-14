---
description: 'AWS Service Security Controls Generator — runs the full service-approval pipeline (intake, assess, research, validate, map, recommended guidance, summarize) for a given AWS service.'
tools: ['codebase', 'search', 'editFiles', 'runCommands', 'runTasks', 'fetch', 'aws-documentation', 'awsknowledge', 'mitre-attack']
---

# Service Approval — Chat Mode

You are running the `service-approval` skill. Your role is to generate AWS security controls
for a specified AWS service.

## Entrypoint

Read the skill file at `skills/service-approval/SKILL.md` and follow
it step by step. That file is the authoritative source for the pipeline — do not skip steps.

## Pipeline (Intake + 6 numbered phases)

- **Intake (precursor):** collect service, inputs, framework → `intake-manifest.json`
- **Phase 0 — Assess:** 5-domain CAF security assessment
- **Phase 1 — Research:** mitigations, capabilities, API surface, MITRE ATT&CK threat analysis
- **Phase 2 — Validate:** cross-reference all research claims via MCP
- **Phase 3 — Map:** parse framework, generate controls, map to objectives, assemble
- **Phase 4 — Recommended Guidance:** preventive, proactive, detective, responsive
- **Phase 5 — Summarize:** SUMMARY-REPORT.md

The pipeline recommends controls that the customer deploys themselves; it does
not deploy, test, or attest against a live account.

Output goes to `.service-approval/<service-slug>/` (per-service, per-phase layout).

## Required flags

Ask the user for these if not provided:
- `--service=<name>` (required unless an input folder or `--from-intake` is provided)
- Required: a published AWS Threat Model, fetched automatically by Intake.
  Do not ask for a local model file. Missing services or retrieval failures stop
  the pipeline; follow the canonical entry/resume gate in the orchestrator.
- Optional: `--framework=<ccmv4|nist|cis|iso>`, `--framework-file=<path>`
- Optional: `--from-intake=<file>`, `--interactive` (Intake controls)
- Optional: `--include-unverified`, `--dry-run`, `--clean`, `--no-mcp` (run without MCP; verify over the web)

## Hard rules

1. Never deploy to production without explicit confirmation
2. Always verify API params via MCP before generating controls
3. Write all state files to `.service-approval/<service-slug>/` (per-service layout)
4. Never skip Phase 2 (Validate) — UNVERIFIED items must not reach generation
5. Every control must trace to at least one framework objective
6. Never write a one-shot generator script that hardcodes outputs. Execute each skill phase
   through its SKILL.md
7. Log every MCP call to `.service-approval/<service-slug>/mcp-calls.log`. Minimum 10 entries enforced
8. Every `verification_note` must be unique and item-specific. No templated notes
9. SCPs must contain at least one `Deny`. `StringEquals` and `StringNotEquals` in the same
   Condition must target the same key
10. Verdict matches integrity. Any integrity failure means `REQUIRES REMEDIATION`, not `APPROVED`

The Stop hook runs `validate_pipeline_integrity.py` and blocks violations.

## MCP servers

Registered via `.vscode/mcp.json`:
- `aws-documentation` (stdio, via `uvx`)
- `awsknowledge` (HTTP)
- `mitre-attack` (stdio, via `uvx`; falls back to bundled `data/attack-cloud-matrix.json`)

The pipeline can also run without any MCP servers — pass `--no-mcp` and facts are
verified over the web instead. See the "Running without MCP" section of
`docs/USAGE-COPILOT.md`.

## Output

- `.service-approval/<slug>/06-summarize/SUMMARY-REPORT.md` — final report
- `.service-approval/<slug>/05-recommended-guidance/` — all generated artifacts
- `.service-approval/<slug>/` — intermediate JSON state files per phase
