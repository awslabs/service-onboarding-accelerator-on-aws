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

Read the skill file, consume `.service-approval/<slug>/04-map/mapping-results.json` and `.service-approval/<slug>/03-validate/validated.json`, and write outputs to `.service-approval/<slug>/05-recommended-guidance/iac/` in 4 formats: Terraform (modular), CloudFormation YAML, CDK TypeScript, and CDKTF.
