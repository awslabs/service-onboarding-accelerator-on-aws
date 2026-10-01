---
mode: agent
description: 'Generate AWS security controls for a specified AWS service'
---

Run the service-approval skill at `skills/service-approval/SKILL.md`.

## Inputs
Ask the user for:
1. **Service name** (e.g., `s3`, `lambda`, `bedrock-agentcore-control`)
2. **AWS Threat Model JSON export** (required for the requested service; an input folder containing it or `--threat-model-file=<path>`)
3. **Framework** (optional — `ccmv4`, `nist`, `cis`, `iso`; defaults to CCMv4)

If the user provided any of these in their invocation message, don't re-ask.

## Execution
Follow the skill file step by step. Write all output to `.service-approval/` in the workspace root.
Run the mandatory AWS Threat Model preflight before any assessment or research.
Missing, malformed, or wrong-service exports halt the pipeline; flags and saved
state do not bypass this requirement.

## Output
Report back to the user with:
- Path to `.service-approval/<slug>/06-summarize/SUMMARY-REPORT.md`
- Count of artifacts generated per category
- Any phases that were skipped or failed
