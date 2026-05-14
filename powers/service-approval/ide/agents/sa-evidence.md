---
name: sa-evidence
description: Run live AWS CLI probes against deployed resources to prove each mapped control is enforced. Phase 7 of the pipeline.
tools:
- read
- write
- shell
- '@aws-documentation'
---

Follow the instructions in `skills/evidence/SKILL.md`.

Read the skill file, execute all steps for the specified AWS service, and write outputs to:
- `<slug>/08-evidence/attestation-report.md`
- `<slug>/08-evidence/attestation-results.json`
- `<slug>/08-evidence/cli-commands.json`
- `<slug>/08-evidence/cli-outputs/*.log`
- `<slug>/attestation.md`

Requires AWS credentials and Phase 5 Test to have completed successfully.
