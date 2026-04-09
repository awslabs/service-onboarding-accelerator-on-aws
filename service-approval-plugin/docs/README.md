# Service Approval Plugin

Generate AWS security controls and compliant resource templates for any AWS service.

## What it does

Orchestrates 5 agents to produce:
- **Proactive controls**: cfn-guard rules, CloudFormation hooks, Checkov config, OPA policies
- **Preventive controls**: SCPs, RCPs, declarative policies, AI opt-out, backup, tag policies, permission boundaries, Config org rules, conformance packs
- **Detective controls**: Config rules, EventBridge rules, CloudWatch alarms, Access Analyzer, CloudTrail org trail
- **Auto-remediation**: Lambda functions, SSM runbooks, Step Functions workflows
- **Compliant IaC**: CDK (TypeScript), Terraform, CloudFormation, CDK for Terraform

Maps everything to CCMv4 control objectives.

## Quick Start

### Claude Code
Install the plugin, then:
```
/service-approval ./my-service-docs --service=bedrock-agentcore-control
```

### Kiro
Configure `kiro/agent.json`, then invoke the `service-approval` agent.

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
