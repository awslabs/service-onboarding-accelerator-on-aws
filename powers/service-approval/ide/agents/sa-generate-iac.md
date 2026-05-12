---
name: sa-generate-iac
description: Generate compliant IaC templates in Terraform, CloudFormation, CDK TypeScript, and CDKTF
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
- '@terraform'
---

Follow the instructions in `skills/generate-iac/SKILL.md`.

Read the skill file, consume `.service-approval/state/mapping-results.json` and `.service-approval/state/validated.json`, and write outputs to `.service-approval/controls/iac/` in 4 formats: Terraform (modular), CloudFormation YAML, CDK TypeScript, and CDKTF.
