---
name: sa-map-assemble
description: Deterministic assembly of map sub-skill outputs into mapping-results.json and markdown reports
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/map-assemble/SKILL.md`.

Read the skill file, consume all map-*.json state files, and write:
- `.service-approval/state/mapping-results.json`
- `.service-approval/state/controls-catalog.md`
- `.service-approval/state/framework-mapping.md`
