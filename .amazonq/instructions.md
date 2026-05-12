# Service Approval — Amazon Q Developer Instructions

## Activation
Say: "Run service approval for [service-name]" or "Generate AWS security controls for [service-name]"

## How to execute
Read the skill file at `skills/service-approval/SKILL.md` in full and follow every step.
Run agents sequentially. Write all outputs to `.service-approval/` in the working directory.

## Parameters
- Service name: the AWS service to analyze (e.g., `bedrock-agentcore-control`, `s3`, `kms`)
- Input folder: optional path to folder with mitigation reports, threat models, xlsx files
- AWS profile: optional, required only for the Tester agent
- Skip test: pass `--skip-test` to skip deployment validation

## Output location
- Report: `.service-approval/APPROVAL-REPORT.md`
- Controls: `.service-approval/controls/`
- State: `.service-approval/state/`
