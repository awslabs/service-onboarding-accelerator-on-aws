---
name: structure
description: Repository layout, file naming, and where things live
alwaysApply: true
---

# Service Approval — Structure

## Repository layout

```
/
├── skills/                           (canonical)
│   └── <one SKILL.md per skills/<slug>/>
├── tools/                            (canonical)
│   ├── validate/                     Python validators + hooks
│   └── kb-search-mcp/                Bedrock KB MCP server
├── schemas/                          (canonical)
│   └── <one *.schema.json per state file>
├── data/                             (canonical)
├── rules/                            (canonical)
├── .claude-plugin/                   (symlink) — Claude Code discovery
├── .agents/skills/                   (symlink) — agentskills.io alias
├── powers/service-approval/          This Power
├── .github/                          Copilot agents, prompts, hooks (PR4)
├── install.sh / install.ps1          Cross-IDE installer
└── docs/INSTALL.md                   Install guide
```

## Power layout

```
powers/service-approval/
├── POWER.md                              Manifest + frontmatter + body
├── README.md                             Overview, install, prerequisites
├── mcp.json                              MCP server registrations
├── steering/                             Always-on + fileMatch-loaded guidance
│   ├── product.md                        what and who (always-on)
│   ├── tech.md                           stack, MCP servers, validators (always-on)
│   ├── structure.md                      (this file) — layout and naming (always-on)
│   ├── pipeline.md                       phase-by-phase execution guide
│   ├── phase-research.md                 loads for research-* state files
│   ├── phase-validate.md                 loads for validated.json
│   ├── phase-map.md                      loads for map-* state files
│   ├── phase-generate.md                 loads for 05-recommended-guidance/ artifacts
│   ├── headless.md                       CI / headless invocation
│   └── service-approval-enforcement.md   skill-based execution guardrail
├── agents-src/                           source-of-truth YAML — one sa-<slug>.yaml per agent
│   └── sa-*.yaml                         (one per sub-skill)
├── cli/agents/                           generated CLI format (JSON)
│   └── sa-*.json                         (run tools/generate-kiro-agents.py to regenerate)
└── ide/                                  generated IDE artifacts
    ├── agents/sa-*.md                    (markdown agents the IDE loads)
    └── hooks/                            (Kiro IDE hooks)
        ├── stop.kiro.hook                pipeline-integrity Stop hook
        ├── post-tool-use.kiro.hook       state-file PostToolUse hook
        └── block-direct-state-writes.kiro.hook   skill-based-execution PreToolUse hook
```

## File naming conventions

| Kind | Pattern | Example |
|------|---------|---------|
| Skill | `skills/<slug>/SKILL.md` | `skills/research-mitigations/SKILL.md` |
| Agent (CLI) | `cli/agents/sa-<slug>.json` | `cli/agents/sa-research-mitigations.json` |
| Agent (IDE) | `ide/agents/sa-<slug>.md` | `ide/agents/sa-research-mitigations.md` |
| Steering | `steering/<topic>.md` | `steering/phase-research.md` |
| Schema | `schemas/<name>.schema.json` | `schemas/research.schema.json` |
| Hook | `ide/hooks/<event>.kiro.hook` | `ide/hooks/stop.kiro.hook` |
| Validator | `tools/validate/validate_<scope>.py` | `tools/validate/validate_state.py` |
| Test | `tools/validate/test_<validator>.py` | `tools/validate/test_validate_state.py` |
| Control artifact | `.service-approval/<slug>/05-recommended-guidance/<category>/<CTRL-ID>.<ext>` | `.service-approval/<slug>/05-recommended-guidance/preventive/CTRL-ORG-PRV-001.json` |
| State file | `.service-approval/<slug>/<phase>/<name>.json` | `.service-approval/<slug>/02-research/research.json` |

Control ID format: `CTRL-(ORG|ACC|RES)-(PRO|PRV|DET|COR)-\d{3}`. Enforced by the schema at `schemas/map-controls-generated.schema.json`.

## Why symlinks

All pipeline content lives at the repo root. Why:
- Every agentic client can discover from the repo root without moving files
- Existing import paths in validators (`from _schemas import schema_errors`) keep working
- `git pull` updates all client installs automatically (symlinked)

Windows users need Developer Mode ON for symlinks to resolve without admin — documented in `docs/INSTALL.md`.
