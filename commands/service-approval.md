---
description: Run the AWS service-approval pipeline — generates security controls + compliant IaC for a specified AWS service
argument-hint: "[./input-folder] [--service=<name>] [--env=<profile>] [--framework=<ccmv4|nist|cis|iso>] [--skip-test] [--dry-run] [--clean] [--from-intake=<file>] [--interactive]"
---

# Service Approval — Orchestrator

Invokes the full 8-phase pipeline defined at `skills/service-approval/SKILL.md`.

## Parse arguments

Expect arguments in `$ARGUMENTS`. Extract:

- AWS service name — required unless an input folder is provided with a `sar-slugs.json`-resolvable service, or `--from-intake=<file>` points at an intake that names one
  - From `--service=<name>` flag, or
  - Inferred from `./input/` folder contents
- Input folder — optional path to customer docs (.md, .json, .xlsx, .pdf, .docx); defaults to `./input/`
- AWS profile — optional `--env=<profile>` (required only for Phase 5 Test with `full-deploy`)
- Framework — optional `--framework=<ccmv4|nist|cis|iso>`; auto-detected from input if absent
- Intake controls — `--from-intake=<file>`, `--interactive`
- Flags: `--skip-test`, `--dry-run`, `--clean`

If no service name can be determined and `--from-intake` is not provided, defer to the Intake phase — it will prompt interactively.

## Intake auto-discovery

Intake always runs. Its prompt behavior depends on what it finds:

1. `--from-intake=<path>` → read that file, no prompts (unless required fields are missing)
2. `./service-approval-intake.yaml` in the CWD → render a summary and prompt `[U]se as-is / [E]dit`
3. Neither → run the full interactive form and offer to save the answers to `./service-approval-intake.yaml` for next time

`--interactive` forces option 3 even when a YAML exists. Plugin-repo files (`skills/intake/intake-template.yaml`, `skills/intake/defaults.yaml`) are never auto-loaded as user intake.

## Execute

1. Read `skills/service-approval/SKILL.md` in full. Do NOT write a one-shot generator script. Follow every step.
2. Run every sub-skill through its own SKILL.md:
   - Intake (precursor): `skills/intake/` — writes `state/intake-manifest.json`
   - Phase 0: `skills/assess/`
   - Phase 1: `skills/research-mitigations/`, `research-capabilities/`, `research-api-surface/`, `research-attack-surface/` (parallel), then `skills/research/` (merge)
   - Phase 2: `skills/validate/`
   - Phase 3: `skills/map-parse-framework/`, `map-generate-controls/` (parallel), then `map-framework-mapping/`, `map-assemble/`
   - Phase 4: `skills/generate-preventive/`, `generate-detective/`, `generate-iac/` (parallel)
   - Phase 5: `skills/test/` (only if `--env` provided and not `--skip-test`)
   - Phase 6: `skills/summarize/`
3. Use MCP servers (`awsknowledge`, `aws-documentation`, `awsiac`) for every capability, API parameter, and condition key. Log each call to `.service-approval/state/mcp-calls.log` (minimum 10 entries).
4. Pipeline integrity is enforced automatically by the `Stop` hook at `hooks/hooks.json`, which invokes `tools/validate/hook_stop.py`. Exit code 2 blocks the stop and forces verdict `REQUIRES REMEDIATION`.

## Output

- `.service-approval/APPROVAL-REPORT.md` — final verdict + CCMv4 coverage matrix
- `.service-approval/controls/` — all 78–111 generated artifacts
- `.service-approval/state/` — pipeline state files (research.json, validated.json, etc.)

## Report back

After the pipeline completes, summarize:
- Final verdict (APPROVED / APPROVED with exceptions / REQUIRES REMEDIATION)
- Path to `.service-approval/APPROVAL-REPORT.md`
- Artifact count per category (preventive, proactive, detective, responsive, IaC)
- Any phases that failed or were skipped, and why
