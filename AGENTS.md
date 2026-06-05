# Service Approval — Agents Guide

This repo generates AWS security controls for any AWS service via a 9-phase pipeline
(Intake, Assess, Research, Validate, Map, Generate, Test, Summarize, Evidence). It runs
on any [Agent Skills](https://agentskills.io)-compatible client: Claude Code, GitHub
Copilot, and Kiro.

## Install

```bash
git clone <repo> && cd service-onboarding-accelerator-on-aws && ./install.sh
```

Windows: `./install.ps1` (requires Developer Mode for symlink installs).

The installer detects which clients you have and wires them up. Clone + run = working.

## Update

```bash
git pull
```

Symlinked installs reflect changes on next session. No re-install needed.

## How agents use this repo

The pipeline lives in [`skills/`](skills/). Every skill has a `SKILL.md` with YAML frontmatter
that identifies it and tells agents when to activate it.

**Entry point:** `skills/service-approval/SKILL.md` — the orchestrator. All other skills
are invoked from this one.

Agents should:
1. Read the user's request for an AWS service name and optional input folder.
2. Activate the `service-approval` skill.
3. Follow the pipeline steps in the skill body.
4. Write all state to `.service-approval/<service-slug>/` (per-service, per-phase layout).

## Pipeline summary

```
Precursor Intake    → _staging/<ts>/00-intake/intake-manifest.json (service, inputs, testing intent)
Phase 0 Assess      → <slug>/01-assess/{sar-facts,checkpoint-results,iac-support}.json
Phase 1 Research    → <slug>/02-research/research.json (4 parallel sub-skills merged)
Phase 2 Validate    → <slug>/03-validate/validated.json
Phase 3 Map         → <slug>/04-map/{mapping-results.json, framework-mapping.md}
Phase 4 Generate    → <slug>/05-generate/{proactive,preventive,detective,responsive,iac}/
Phase 5 Test        → <slug>/06-test/{test-results.json, deployed-resources.json} (mode set upfront in Intake: full-deploy | dry-run | skip | manual-cli)
Phase 6 Summarize   → <slug>/07-summarize/APPROVAL-REPORT.md
Phase 7 Evidence    → <slug>/08-evidence/{attestation-report.md, cli-outputs/} (requires AWS credentials)
```

Intake runs first (unnumbered) and writes to a staging directory because the
canonical service slug is only known after Phase 0 derives it from SAR. Phase 0
atomically promotes the staging directory to `<slug>/`.

See [`README.md`](README.md) for per-phase artifact counts and the full flag reference.

## Hard rules (enforced at Stop hook time)

1. Never write a one-shot generator script that hardcodes state or controls. Run every
   phase through its `SKILL.md`.
2. Every capability claim, API parameter, and condition key must be verified via MCP
   (`awsknowledge`, `aws-documentation`, `awsiac`). Hardcoded values from training data
   are banned.
3. Log every MCP call to `.service-approval/<service-slug>/mcp-calls.log`. Minimum 10 entries.
4. Every item in `validated.json` must have a unique `verification_note`. Templated
   notes fail the integrity check.
5. IaC templates must be parameterized. No hardcoded account IDs (`123456789012`) or
   placeholder ARNs.
6. SCPs must contain at least one `Deny` statement. `StringEquals` and `StringNotEquals`
   in the same Condition must target the same key.
7. Verdict matches integrity. If any pipeline integrity check fails, the verdict is
   `REQUIRES REMEDIATION`, not `APPROVED`.

The Stop hook runs `tools/validate/validate_pipeline_integrity.py` and blocks violations.
See [`rules/service-approval-safety.md`](rules/service-approval-safety.md) for the full list.

## Directory map

| Path | What's in it |
|------|--------------|
| `skills/` | 18 `SKILL.md` skill definitions (canonical, agentskills.io format) |
| `.agents/skills/` | Symlink to `skills/` (cross-tool compatibility alias) |
| `schemas/` | 11 JSON Schemas for pipeline state files |
| `tools/validate/` | Python validators + hooks (runs at PostToolUse + Stop) |
| `tools/kb-search-mcp/` | Bedrock KB search MCP server |
| `data/` | SAR slug map, launch-type constraints, KMS consumer specs |
| `rules/` | Safety rules applied across all phases |
| `.claude-plugin/` | Claude Code plugin manifest |
| `.github/` | Copilot agents, prompts, chatmodes, skills, hooks |
| `powers/service-approval/` | Kiro Power (CLI 2.0 format) |

## Client-specific notes

| Client | Entry point | Auto-discovers? |
|--------|-------------|-----------------|
| Claude Code | `.claude-plugin/plugin.json` | Yes |
| GitHub Copilot | `.github/agents/service-approval.agent.md` | Yes |
| Kiro CLI | `powers/service-approval/POWER.md` | After `./install.sh` |

## Contributing

1. Edit `skills/*/SKILL.md` for skill changes. All clients read the same files.
2. Edit `manifest.yaml` to change which skills ship in each client's bundle.
3. Run `python3 tools/sync-ide-configs.py` to regenerate per-client manifests.
4. Run `python3 -m pytest tools/validate/` before committing.

Details: [`CONTRIBUTING.md`](CONTRIBUTING.md) (if present), otherwise this file.
