---
mode: agent
description: 'Generate AWS security control mappings and compliance assessments for a specified AWS service'
---

Run the service-approval skill at `skills/service-approval/SKILL.md`.

## Inputs
Ask the user for:
1. **Service name** (e.g., `s3`, `lambda`, `bedrock-agentcore-control`)
2. **Input folder path** (optional — folder containing customer docs: .md, .json, .xlsx, .pdf, .docx)

If the user provided any of these in their invocation message, don't re-ask.

## Execution
Follow the skill file step by step. Write all output to `.service-approval/` in the workspace root.

## Output
Report back to the user with:
- Path to `.service-approval/<slug>/05-summarize/APPROVAL-REPORT.md`
- Any phases that were skipped or failed
