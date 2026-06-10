---
name: service-approval-enforcement
description: Ensures the service-approval power runs through its defined agent sub-skills
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/**"
---

# Service Approval Execution Enforcement

## Hard Rule

When the user asks to "run service approval" or "generate security controls" for any AWS service:

1. You MUST execute each phase by following the corresponding SKILL.md via the power's agent definitions — NOT by writing state files directly.
2. You MUST use `/spawn` for parallel phases (Research, Map window 1) as defined in `steering/pipeline.md`.
3. You MUST NOT skip any output file that a sub-skill's SKILL.md specifies — including `controls-catalog.md` and `framework-mapping.md` from `sa-map-assemble`.
4. If a sub-skill cannot be spawned (e.g., agents not registered), inform the user and ask whether to proceed with manual execution — do NOT silently shortcut.
5. **Every claim MCP-verified.** You MUST verify every capability claim, API parameter, and condition key via MCP. Hardcoded values from training data are banned. The Stop hook's P1 check enforces a minimum count (≥10) of MCP calls per pipeline run.
6. You MUST NOT write a one-shot generator script that hardcodes state or controls. Run every phase through its `SKILL.md` via the corresponding sub-skill agent.

## Verification

Before writing `APPROVAL-REPORT.md`, verify all expected outputs exist:
- `<slug>/04-map/mapping-results.json`
- `<slug>/04-map/controls-catalog.md`
- `<slug>/04-map/framework-mapping.md`
