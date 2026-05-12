---
name: phase-research
description: Rules that apply to Phase 1 (Research) sub-skills
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/state/research*.json"
---

# Phase 1 — Research sub-skill rules

Applies to: `sa-research-mitigations`, `sa-research-capabilities`, `sa-research-api-surface`, `sa-research-attack-surface`, and the merge step.

## Hard rules

1. **Every capability claim must be MCP-verified.** For each mitigation, capability, API parameter, and condition key, make at least one call to `@awsknowledge`, `@aws-documentation`, or `@awsiac`. Log it to `state/mcp-calls.log`. Integrity rule P1 enforces a minimum of 10 total calls.

2. **No training-data values.** If your answer starts with "I know that S3 supports..." or "Lambda has a feature called...", stop. Re-query MCP. Training data is banned as a source of truth.

3. **Per-item verification notes.** Each item written to `research-*.json` must have a `verification_note` citing the specific MCP call (server name + tool name + key argument) and what was returned. Templated or duplicated notes fail integrity rule P2.

## Output contracts

Each research sub-skill writes its output to a file matching its schema in `/schemas/`:

| Sub-skill | Output | Schema |
|-----------|--------|--------|
| `research-mitigations` | `state/research-mitigations.json` | `schemas/research-mitigations.schema.json` |
| `research-capabilities` | `state/research-capabilities.json` | `schemas/research-capabilities.schema.json` |
| `research-api-surface` | `state/research-api-surface.json` | `schemas/research-api-surface.schema.json` |
| `research-attack-surface` | `state/research-attack-surface.json` | (optional, no schema) |

The PostToolUse hook (`hook_post_tool_use.py`) validates the output against the schema on every `fs_write`.

## Parallel execution

Use Kiro CLI 2.0 `/spawn` to run the 4 research sub-skills concurrently:

```
/spawn sa-research-mitigations     ./input/mitigation-report.md
/spawn sa-research-capabilities    <service-name>
/spawn sa-research-api-surface     <service-name>
/spawn sa-research-attack-surface  (optional)
```

Each subagent has its own context window. Kiro's main agent waits for all four
before proceeding to the merge step (Phase 1e in `skills/research/SKILL.md`).

## What triggers this steering

`inclusion: fileMatch` with pattern `**/.service-approval/state/research*.json`
means this file loads into context only when a research sub-skill is writing
one of these files. Saves tokens for unrelated phases.
