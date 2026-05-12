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
│   └── <18 SKILL.md files>
├── tools/                            (canonical)
│   ├── validate/                     Python validators + hooks
│   └── kb-search-mcp/                Bedrock KB MCP server
├── schemas/                          (canonical)
│   └── <11 JSON Schema files>
├── data/                             (canonical)
├── rules/                            (canonical)
├── .claude-plugin/                   (symlink) — Claude Code discovery
├── .agents/skills/                   (symlink) — agentskills.io alias
├── AGENTS.md                         Codex CLI + Cursor entry point
├── powers/service-approval/          This Power
├── gemini-extension/                 Gemini CLI extension (PR3)
├── .github/                          Copilot agents, prompts, hooks (PR4)
├── install.sh / install.ps1          Cross-IDE installer
└── docs/INSTALL.md                   Install guide
```

## Power layout

```
powers/service-approval/
├── POWER.md                          Manifest + frontmatter + body
├── steering/
│   ├── product.md                    (this) — what and who
│   ├── tech.md                       stack, MCP servers, validators
│   ├── structure.md                  (this file) — layout and naming
│   ├── pipeline.md                   phase-by-phase execution guide
│   ├── phase-research.md             loads for research-* agents
│   ├── phase-validate.md             loads for validate agent
│   ├── phase-map.md                  loads for map-* agents
│   ├── phase-generate.md             loads for generate-* agents
│   └── headless.md                   CI / headless invocation
├── agents/
│   ├── sa-assess.json
│   ├── sa-research-mitigations.json
│   ├── sa-research-capabilities.json
│   ├── sa-research-api-surface.json
│   ├── sa-research-attack-surface.json
│   ├── sa-validate.json
│   ├── sa-map-parse-framework.json
│   ├── sa-map-generate-controls.json
│   ├── sa-map-framework-mapping.json
│   ├── sa-map-assemble.json
│   ├── sa-generate-preventive.json
│   ├── sa-generate-detective.json
│   └── sa-generate-iac.json
├── mcp.json                          MCP server registrations
└── hooks/
    ├── post-tool-use.json            PostToolUse matcher=fs_write
    ├── stop.json                     Stop matcher=*
    └── README.md
```

## File naming conventions

| Kind | Pattern | Example |
|------|---------|---------|
| Skill | `skills/<slug>/SKILL.md` | `skills/research-mitigations/SKILL.md` |
| Agent | `agents/sa-<slug>.json` | `agents/sa-research-mitigations.json` |
| Steering | `steering/<topic>.md` | `steering/phase-research.md` |
| Schema | `schemas/<name>.schema.json` | `schemas/research.schema.json` |
| Hook | `hooks/<event>.json` | `hooks/stop.json` |
| Validator | `tools/validate/validate_<scope>.py` | `tools/validate/validate_state.py` |
| Test | `tools/validate/test_<validator>.py` | `tools/validate/test_validate_state.py` |
| Control artifact | `.service-approval/controls/<category>/<CTRL-ID>.<ext>` | `.service-approval/controls/preventive/CTRL-ORG-PRV-001.json` |
| State file | `.service-approval/state/<name>.json` | `.service-approval/state/research.json` |

Control ID format: `CTRL-(ORG|ACC|RES)-(PRO|PRV|DET|COR)-\d{3}`. Enforced by the schema at `schemas/map-controls-generated.schema.json`.

## Why symlinks

All pipeline content lives at the repo root. Why:
- Every agentic client can discover from the repo root without moving files
- Existing import paths in validators (`from _schemas import schema_errors`) keep working
- `git pull` updates all client installs automatically (symlinked)

Windows users need Developer Mode ON for symlinks to resolve without admin — documented in `docs/INSTALL.md`.
