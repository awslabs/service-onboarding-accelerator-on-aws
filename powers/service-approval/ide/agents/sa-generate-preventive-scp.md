---
name: sa-generate-preventive-scp
description: Author SCPs for approved preventive objectives, adapted from a matching reference example; never free-synthesizes
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/generate-preventive-scp/SKILL.md`.

Read `.service-approval/<slug>/05-generate/preventive-plan.json` and author SCPs ONLY for rows where decision == "GENERATE_SCP", adapting the anchored reference example to the target service. Stamp `_metadata.reference` on every artifact. Write to `.service-approval/<slug>/05-generate/preventive/`.
