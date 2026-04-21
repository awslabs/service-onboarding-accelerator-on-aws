---
name: sa-map-generate-controls
description: "Generate security controls from mitigations x capabilities organized by Category x Scope matrix"
tools:
  - read
  - write
  - shell
---

Follow the instructions in `service-approval-plugin/skills/map-generate-controls/SKILL.md`.

Read the skill file, consume `.service-approval/state/validated.json`, and write
`.service-approval/state/map-controls-generated.json`.
