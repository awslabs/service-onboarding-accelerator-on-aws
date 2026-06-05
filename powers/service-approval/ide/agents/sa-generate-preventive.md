---
name: sa-generate-preventive
description: Generate preventive and proactive security controls (SCPs, IAM, CFN Guard, OPA, Checkov)
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/generate-preventive/SKILL.md`.

Read the skill file, consume `.service-approval/<slug>/04-map/mapping-results.json` and `.service-approval/<slug>/03-validate/validated.json`, and write outputs to `.service-approval/<slug>/05-generate/preventive/` and `.service-approval/<slug>/05-generate/proactive/`.
