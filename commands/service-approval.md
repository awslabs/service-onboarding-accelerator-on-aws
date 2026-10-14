---
description: Run the AWS service-approval pipeline — generates security controls for a specified AWS service
argument-hint: "[./input-folder] [--service=<name>] [--framework=<ccmv4|nist|cis|iso>] [--framework-file=<path>] [--include-unverified] [--dry-run] [--clean] [--from-intake=<file>] [--interactive]"
---

# Service Approval — Orchestrator

Invokes the pipeline defined at `skills/service-approval/SKILL.md`:
Intake → Assess → Research → Validate → Map → Recommended Guidance → Summarize.

## Parse arguments

Expect arguments in `$ARGUMENTS`. Extract:

- AWS service name — required unless an input folder is provided with a `sar-slugs.json`-resolvable service, or `--from-intake=<file>` points at an intake that names one
  - From `--service=<name>` flag, or
  - Inferred from `./input/` folder contents
- AWS Threat Model — REQUIRED published model, retrieved automatically by
  `tools/validate/fetch_threat_model.py --service <name>`. Follow the canonical
  Intake gate; missing services or retrieval failures stop the pipeline.
  Local model files are no longer accepted as an override.
- Input folder — optional framework and supporting documents.
- Framework — optional `--framework=<ccmv4|nist|cis|iso>`; auto-detected from input if absent
- Framework file — optional `--framework-file=<path>`
- Intake controls — `--from-intake=<file>`, `--interactive`
- Flags: `--include-unverified`, `--dry-run`, `--clean`

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
   - Phase 4 (Recommended Guidance): `skills/generate-preventive/`, `generate-detective/` (parallel)
   - Phase 5: `skills/summarize/`
3. Use MCP servers (`awsknowledge`, `aws-documentation`) for every capability, API parameter, and condition key. Each call appends to the consolidated `.service-approval/<service-slug>/pipeline.log` (the primary debugging artifact, with `[mcp:<server>:call]` source tags) and is mirrored to `.service-approval/<service-slug>/mcp-calls.log` for backward compatibility (minimum 10 entries enforced by the Stop hook's P1 check).
4. Pipeline integrity is enforced automatically by the `Stop` hook at `hooks/hooks.json`, which invokes `tools/validate/hook_stop.py`. Exit code 2 blocks the stop and forces verdict `REQUIRES REMEDIATION`.

## Output

- `.service-approval/<service-slug>/06-summarize/SUMMARY-REPORT.md` — Summary Report + CCMv4 coverage matrix
- `.service-approval/<service-slug>/05-recommended-guidance/` — all generated artifacts
- `.service-approval/<service-slug>/` — pipeline state files (per-phase subdirectories)

## Report back

After the pipeline completes, summarize:
- Path to `.service-approval/<service-slug>/06-summarize/SUMMARY-REPORT.md`
- Artifact count per category (preventive, proactive, detective, responsive)
- Any phases that failed or were skipped, and why
