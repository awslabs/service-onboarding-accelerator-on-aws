---
name: sa-map-framework-mapping
description: Map controls to framework objectives with per-objective analysis, confidence scoring, and quality gates
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/map-framework-mapping/SKILL.md`.

Read the skill file, consume `map-framework-parsed.json` and `map-controls-generated.json`,
and write `.service-approval/<slug>/04-map/map-framework-mapped.json`.

Quality cap: no control may map to more than 5 objectives.
