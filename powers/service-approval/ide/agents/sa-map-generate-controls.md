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

Read the skill file, consume `.service-approval/<slug>/03-validate/validated.json`, and write
`.service-approval/<slug>/04-map/map-controls-generated.json`.
