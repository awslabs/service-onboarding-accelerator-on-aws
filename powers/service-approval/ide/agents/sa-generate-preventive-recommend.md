---
name: sa-generate-preventive-recommend
description: Decide the enforcement mechanism per preventive objective (SCP/RCP/IAM or not-preventable) and anchor each to a reference example; gates the preventive authors
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/generate-preventive-recommend/SKILL.md`.

Read mapping-results.json, validated.json, and data/reference-repos/index.yaml. Run the preventability analyzer and the reference-index lookup, then write the per-control decision plan to `.service-approval/<slug>/05-generate/preventive-plan.json`. This runs FIRST and gates the SCP/RCP/IAM authors.
