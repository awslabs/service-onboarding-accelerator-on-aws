# Service Approval Plugin

Generates AWS security controls and compliant IaC templates for any AWS service. Orchestrates 5 agents (Researcher → Validator → Generator → Tester → Summarizer) and maps everything to CCMv4 control objectives.

## What it produces

- **Proactive controls** — cfn-guard rules, CloudFormation hooks, Checkov config, OPA policies
- **Preventive controls** — SCPs, RCPs, declarative policies, permission boundaries, Config conformance packs
- **Detective controls** — Config rules, EventBridge rules, CloudWatch alarms, Security Hub, Access Analyzer
- **Auto-remediation** — Lambda functions, SSM runbooks, Step Functions workflows
- **Compliant IaC** — CDK (TypeScript), Terraform, CloudFormation, CDK for Terraform

Output lands in `.service-approval/` in your working directory:
```
.service-approval/
  APPROVAL-REPORT.md   ← final verdict + CCMv4 matrix
  controls/            ← all generated control artifacts
  state/               ← agent handoff files
```

---

## Installation & usage by client

### Claude Code

Install the plugin from the `service-approval-plugin/` directory:

```bash
claude plugin install ./service-approval-plugin
```

Then invoke from any project:

```
/service-approval [./input-folder] --service=<name> [flags]
```

Examples:
```
/service-approval ./my-docs --service=bedrock-agentcore-control
/service-approval --service=s3 --env=my-dev-profile
/service-approval ./my-docs --service=kms --dry-run
```

---

### Kiro IDE

Copy the `kiro/` folder into your Kiro config:

```bash
cp -r service-approval-plugin/kiro ~/.kiro/agents/service-approval
cp service-approval-plugin/kiro/steering/service-approval.md ~/.kiro/steering/
```

Then in any Kiro agent chat:
```
/service-approval --service=bedrock-agentcore-control
```

---

### GitHub Copilot

Copy the instructions file to your repo's Copilot config:

```bash
cp service-approval-plugin/github/copilot-instructions.md .github/copilot-instructions.md
cp service-approval-plugin/github/copilot/skill-manifest.json .github/copilot/skill-manifest.json
```

Then invoke in Copilot Chat:
```
@service-approval ./my-docs --service=bedrock-agentcore-control --skip-test
```

Or in natural language:
```
run service approval for bedrock agentcore skipping the test phase
```

---

### Amazon Q Developer

Copy the instructions file to your repo:

```bash
cp service-approval-plugin/amazonq/instructions.md .amazonq/instructions.md
```

Then say in Q Chat:
```
Run service approval for bedrock-agentcore-control
Generate AWS security controls for s3
```

---

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--service=<name>` | AWS service ID (e.g. `bedrock-agentcore-control`, `s3`, `kms`) | Required if no folder |
| `--env=<profile>` | AWS CLI profile for the Tester agent | None (skips Tester) |
| `--skip-test` | Skip deployment validation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--timeout=<minutes>` | Security Hub polling timeout | 30 |
| `--keep` | Keep deployed test resources after run | false |
| `--include-unverified` | Include unverified findings in generation | false |
| `--clean` | Delete existing `.service-approval/` state before run | false |

---

## Repository layout

```
service-approval-plugin/
  plugin.json                   ← plugin manifest (Claude Code)
  .mcp.json                     ← MCP server config
  skills/
    service-approval/SKILL.md   ← orchestrator (all clients read this)
    research/SKILL.md
    validate/SKILL.md
    generate/SKILL.md
    test/SKILL.md
    summarize/SKILL.md
  rules/
    service-approval-safety.md  ← safety steering (no prod deploys, etc.)
  kiro/                         ← Kiro agent config + steering
  github/                       ← GitHub Copilot manifest + instructions
  amazonq/                      ← Amazon Q Developer instructions
  claude/                       ← Claude Code plugin manifest
  docs/README.md                ← quick-start reference
```

---

## Authors

GFS PACE — fsi-pace@amazon.com
