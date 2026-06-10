---
description: Run the AWS service-approval pipeline — generates security control mappings and compliance assessments for a specified AWS service
argument-hint: "[./input-folder] [--service=<name>] [--framework=<ccmv4|nist|cis|iso>] [--clean] [--from-intake=<file>] [--interactive]"
---

# Service Approval — Orchestrator

Invokes the full 6-phase pipeline defined at `skills/service-approval/SKILL.md`.

## Parse arguments

Expect arguments in `$ARGUMENTS`. Extract:

- AWS service name — required unless an input folder is provided with a `sar-slugs.json`-resolvable service, or `--from-intake=<file>` points at an intake that names one
  - From `--service=<name>` flag, or
  - Inferred from `./input/` folder contents
- Input folder — optional path to customer docs (.md, .json, .xlsx, .pdf, .docx); defaults to `./input/`
  - If `./input/` is missing, the Intake skill creates it and offers to seed it with the bundled
    CCMv4 framework xlsx and/or auto-download the latest CCMv4 from CSA. See
    `skills/intake/SKILL.md` "Step 0" for the full bootstrap flow.
- Framework — optional `--framework=<ccmv4|nist|cis|iso>`; auto-detected from input if absent
- Intake controls — `--from-intake=<file>`, `--interactive`
- Flags: `--clean`

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
   - Intake (precursor): `skills/intake/` — writes `_staging/<ts>/00-intake/intake-manifest.json`, promoted to `<slug>/00-intake/intake-manifest.json` after slug derivation in Phase 0
   - Phase 0: `skills/assess/`
   - Phase 1: `skills/research-mitigations/`, `research-capabilities/`, `research-api-surface/`, `research-attack-surface/` (parallel), then `skills/research/` (merge)
   - Phase 2: `skills/validate/`
   - Phase 3: `skills/map-parse-framework/`, `map-generate-controls/` (parallel), then `map-framework-mapping/`, `map-assemble/`
   - Phase 4: `skills/summarize/`
3. Use MCP servers (`awsknowledge`, `aws-documentation`, `awsiac`) for every capability, API parameter, and condition key. Each call appends to the consolidated `.service-approval/<service-slug>/pipeline.log` (the primary debugging artifact, with `[mcp:<server>:call]` source tags) and is mirrored to `.service-approval/<service-slug>/mcp-calls.log` for backward compatibility (minimum 10 entries enforced by the Stop hook's P1 check).
4. Pipeline integrity is enforced automatically by the `Stop` hook at `hooks/hooks.json`, which invokes `tools/validate/hook_stop.py`. Exit code 2 blocks the stop and forces verdict `REQUIRES REMEDIATION`.

## Output

- `.service-approval/<service-slug>/05-summarize/APPROVAL-REPORT.md` — final verdict + CCMv4 coverage matrix
- `.service-approval/<service-slug>/` — pipeline state files (per-phase subdirectories)

## Report back

After the pipeline completes, summarize:
- Final verdict (APPROVED / APPROVED with exceptions / REQUIRES REMEDIATION)
- Path to `.service-approval/<service-slug>/05-summarize/APPROVAL-REPORT.md`
- Any phases that failed or were skipped, and why
