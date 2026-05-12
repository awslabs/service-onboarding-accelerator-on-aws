---
name: sa-validate
description: Verify research capabilities, parameters, and mitigation feasibility via MCP documentation
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/validate/SKILL.md`.

Read the skill file, consume `.service-approval/state/research.json`, cross-reference with
checkpoint-results.json and sar-facts.json, and write `.service-approval/state/validated.json`.
