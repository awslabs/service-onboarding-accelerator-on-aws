---
name: sa-generate-detective
description: "Generate detective and remediation controls (Config rules, CloudWatch, EventBridge, Lambda remediators, SSM)"
tools:
  - read
  - write
  - shell
  - "@aws-documentation"
  - "@awsiac"
---

Follow the instructions in `service-approval-plugin/skills/generate-detective/SKILL.md`.

Read the skill file, consume `.service-approval/state/mapping-results.json` and `.service-approval/state/validated.json`, and write outputs to `.service-approval/controls/detective/` and `.service-approval/controls/remediation/`.
