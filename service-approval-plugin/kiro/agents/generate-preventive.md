---
name: sa-generate-preventive
description: "Generate preventive and proactive security controls (SCPs, IAM, CFN Guard, OPA, Checkov)"
tools:
  - read
  - write
  - shell
  - "@aws-documentation"
  - "@awsiac"
---

Follow the instructions in `service-approval-plugin/skills/generate-preventive/SKILL.md`.

Read the skill file, consume `.service-approval/state/mapping-results.json` and `.service-approval/state/validated.json`, and write outputs to `.service-approval/controls/preventive/` and `.service-approval/controls/proactive/`.
