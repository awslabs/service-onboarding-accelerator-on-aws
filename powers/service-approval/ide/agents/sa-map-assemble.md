---
name: sa-map-assemble
description: Deterministic assembly of map sub-skill outputs into mapping-results.json and markdown reports
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/map-assemble/SKILL.md`.

Read the skill file, consume all map-*.json state files, and write:
- `.service-approval/<slug>/04-map/mapping-results.json`
- `.service-approval/<slug>/04-map/controls-catalog.md`
- `.service-approval/<slug>/04-map/framework-mapping.md`
