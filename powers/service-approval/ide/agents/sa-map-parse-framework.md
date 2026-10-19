---
name: sa-map-parse-framework
description: Parse customer control framework file (xlsx/json/md) into normalized objectives
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/map-parse-framework/SKILL.md`.

Read the skill file, parse the framework file from `input/`, and write
`.service-approval/<slug>/04-map/map-framework-parsed.json`.
