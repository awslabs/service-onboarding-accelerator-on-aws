# Service Approval Plugin

Generate AWS security controls and compliant resource templates for any AWS service.

## What it does

Orchestrates 5 agents to produce:
- **Proactive controls**: cfn-guard rules, CloudFormation hooks, Checkov config, OPA policies
- **Preventive controls**: SCPs, RCPs, declarative policies, AI opt-out, backup, tag policies, permission boundaries, Config org rules, conformance packs
- **Detective controls**: Config rules, EventBridge rules, CloudWatch alarms, Access Analyzer, CloudTrail org trail
- **Auto-remediation**: Lambda functions, SSM runbooks, Step Functions workflows
- **Compliant IaC**: CDK (TypeScript), Terraform, CloudFormation, CDK for Terraform

Maps everything to CCMv4 control objectives. Optionally integrates **MITRE ATT&CK v16.1** threat mapping for technique-to-control traceability.

## Quick Start

### Claude Code
Install the plugin, then:
```
/service-approval ./my-service-docs --service=bedrock-agentcore-control
```
Claude Code runs in **parallel mode** (14 agents across 3 parallelization windows).

### Kiro (as a Power)
1. Install as a Kiro Power: **Powers panel → Add power from Local Path** → select `service-approval-plugin/kiro/`
2. MCP servers (aws-documentation, awsknowledge, awsiac, terraform) are auto-configured via `mcp.json`
3. Mention "security controls" or any keyword from the Power — Kiro activates it automatically
4. Runs in **sequential mode** (7 phases, 19 sub-skills)
5. Configure validation hooks (File Save + Agent Stop) per the steering guide for auto-validation

### GitHub Copilot (VS Code)
**Requires Copilot Pro or higher** for agent mode with terminal and file-write tools. Copilot Free discovers the custom agent but cannot execute the full pipeline.

1. Open the repo in VS Code with the GitHub Copilot extension signed in.
2. MCP servers load from `.vscode/mcp.json` (aws-documentation, awsknowledge, awsiac, terraform). Approve them when prompted. Docker Desktop must be running for the terraform MCP.
3. Open Copilot Chat. VS Code auto-discovers custom agents from `.github/agents/` and prompt files from `.github/prompts/` at the repo root.
4. Open the Agent dropdown at the bottom of the chat and pick **service-approval**. Or stay in Agent mode and type `/service-approval` to invoke the prompt file. Include inputs in the initial message:
   ```
   run for service=bedrock-agentcore-control with --skip-test --dry-run
   ```

### GitHub Copilot CLI
```
@service-approval --service=bedrock-agentcore-control --skip-test
```

### Amazon Q Developer
"Run service approval for bedrock-agentcore-control"

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Folder with input files (.md, .json, .xlsx, .pdf, .docx) | None |
| `--service=<name>` | AWS service ID | Required if no folder |
| `--env=<profile>` | AWS CLI profile for Tester | None (skips Tester) |
| `--skip-test` | Skip deployment validation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--timeout=<minutes>` | Config evaluation timeout | 30 |
| `--keep` | Keep deployed test resources | false |
| `--include-unverified` | Include unverified items in generation | false |
| `--clean` | Delete existing state before run | false |

## Output
- Report: `.service-approval/APPROVAL-REPORT.md`
- Controls: `.service-approval/controls/`
- State files: `.service-approval/state/`

## v1 Service
Amazon Bedrock AgentCore Control (AgentRuntime, Gateway, Memory) — 37 mitigations, 14 gap threats identified.
