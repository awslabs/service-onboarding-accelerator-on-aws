---
name: sa-generate-preventive-rcp
description: Author RCPs for approved preventive objectives on RCP-expressible services, adapted from a matching reference example; never free-synthesizes
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
---

Follow the instructions in `skills/generate-preventive-rcp/SKILL.md`.

Read `.service-approval/<slug>/05-generate/preventive-plan.json` and author RCPs ONLY for rows where decision == "GENERATE_RCP" (and validated.json rcp_expressible is true), adapting the anchored reference example to the target service. Stamp `_metadata.reference` on every artifact. Write to `.service-approval/<slug>/05-generate/preventive/`.
