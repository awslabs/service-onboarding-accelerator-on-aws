---
mode: agent
description: 'Generate AWS security controls for a specified AWS service'
---

Run the service-approval skill at `skills/service-approval/SKILL.md`.

## Inputs
Ask the user for:
1. **Service name** (e.g., `s3`, `lambda`, `bedrock-agentcore-control`)
2. **Input folder path** (optional — folder containing customer docs: .md, .json, .xlsx, .pdf, .docx)
3. **Framework** (optional — `ccmv4`, `nist`, `cis`, `iso`; defaults to CCMv4)

If the user provided any of these in their invocation message, don't re-ask.

## Execution
Follow the skill file step by step. Write all output to `.service-approval/` in the workspace root.

## Output
Report back to the user with:
- Path to `.service-approval/<slug>/06-summarize/SUMMARY-REPORT.md`
- Count of artifacts generated per category
- Any phases that were skipped or failed
