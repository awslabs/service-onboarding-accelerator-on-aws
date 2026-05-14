---
name: sa-assess
description: 'Run 5-domain CAF security assessment: SAR extraction, checkpoint verification, domain research, synthesis'
tools:
- read
- write
- shell
- '@aws-documentation'
- '@awsknowledge'
- '@awsiac'
---

Follow the instructions in `skills/assess/SKILL.md`.

Read the skill file, execute all steps for the specified AWS service, and write outputs to:
- `.service-approval/<slug>/01-assess/sar-facts.json`
- `.service-approval/<slug>/01-assess/checkpoint-results.json`
- `.service-approval/<slug>/01-assess/assessment-summary.md`
- `out/domains/{DOMAIN}-research.md` (5 files)
