# Service Approval — GitHub Copilot Instructions

## How to invoke
Type: `@service-approval [./input-folder] [--service=<name>] [--env=<profile>] [--skip-test] [--dry-run]`

Examples:
- `@service-approval ./Hackathon --service=bedrock-agentcore-control --skip-test`
- `@service-approval --service=s3 --env=my-dev-profile`

Flags are passed as natural language if preferred:
- "run service approval for bedrock agentcore skipping the test phase"
- "generate controls for s3 using the dev aws profile"

## What it does
Reads the skill at `skills/service-approval/SKILL.md` and follows it step by step.
Runs agents sequentially: researcher → validator → generator → tester → summarizer.
All state is written to `.service-approval/` in the current working directory.

## Output
Final report: `.service-approval/APPROVAL-REPORT.md`
All controls: `.service-approval/controls/`
