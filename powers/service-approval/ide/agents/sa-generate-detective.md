---
name: sa-generate-detective
description: Generate detective and responsive controls (Config rules, CloudWatch, EventBridge, Lambda remediators, SSM)
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/generate-detective/SKILL.md`.

Read the skill file, consume `.service-approval/state/mapping-results.json` and `.service-approval/state/validated.json`, and write outputs to `.service-approval/controls/detective/` and `.service-approval/controls/responsive/`.
