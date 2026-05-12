---
name: sa-map-generate-controls
description: Generate security controls from mitigations x capabilities organized by Category x Scope matrix
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/map-generate-controls/SKILL.md`.

Read the skill file, consume `.service-approval/state/validated.json`, and write
`.service-approval/state/map-controls-generated.json`.
