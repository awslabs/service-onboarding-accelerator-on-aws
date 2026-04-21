---
name: "service-approval"
displayName: "AWS Service Security Controls Generator"
description: "Generate proactive, preventive, detective, and remediation security controls with MITRE ATT&CK v16.1 threat mapping for any AWS service. Maps controls to CCMv4 framework objectives and produces compliant IaC (Terraform, CloudFormation, CDK, CDKTF)."
keywords: ["security", "controls", "aws", "compliance", "scp", "iam", "config", "cloudtrail", "terraform", "cdk", "cloudformation", "mitre", "attack", "ccm", "nist", "proactive", "detective", "remediation", "guard", "checkov", "opa", "service approval", "security controls", "ccmv4", "framework mapping"]
---

# AWS Service Security Controls Generator

## Onboarding

When first activated, perform these setup steps:

1. **Verify Python 3.9+**: Run `python3 --version`. Required for validation scripts.

2. **Verify MCP Servers**: Confirm the following MCP servers are available. If any are missing, report which ones need configuration:
   - `aws-documentation` (HTTP: https://mcp.awsdocs.amazon.com)
   - `awsknowledge` (HTTP: https://knowledge-mcp.global.api.aws)
   - `awsiac` (HTTP: https://iac-mcp.global.api.aws)

3. **Create working directory**: Create `.service-approval/` and `.service-approval/state/` in the project root if they don't exist.

4. **Verify ATT&CK data files**: Check that `service-approval-plugin/data/attack-cloud-matrix.json` exists. If not, the optional MITRE ATT&CK enrichment phase (Phase 1d) will be skipped automatically.

5. **Install subagent definitions**: Copy the subagent files to the workspace for parallel execution:
   ```
   cp service-approval-plugin/kiro/agents/*.md .kiro/agents/
   ```
   This installs 13 subagents covering the full pipeline:
   - **Assess**: `sa-assess` (spawns domain research)
   - **Research** (parallel): `sa-research-mitigations`, `sa-research-capabilities`, `sa-research-api-surface`, `sa-research-attack-surface`
   - **Validate**: `sa-validate`
   - **Map** (2 parallel + 2 sequential): `sa-map-parse-framework`, `sa-map-generate-controls`, `sa-map-framework-mapping`, `sa-map-assemble`
   - **Generate** (parallel): `sa-generate-preventive`, `sa-generate-detective`, `sa-generate-iac`

6. **Create validation hooks**: Add these hooks to the workspace for automated quality checks:

   Add a hook to `.kiro/hooks/validate-state-files.kiro.hook`:
   - **Title**: Validate service-approval state files
   - **Trigger**: File Save
   - **File Pattern**: `.service-approval/state/*.json`, `.service-approval/controls/**/*`
   - **Action**: Run Command
   - **Command**: `python3 service-approval-plugin/tools/validate/hook_post_tool_use.py`

   Add a hook to `.kiro/hooks/final-cross-validation.kiro.hook`:
   - **Title**: Cross-validate service-approval artifacts
   - **Trigger**: Agent Stop
   - **Action**: Run Command
   - **Command**: `python3 service-approval-plugin/tools/validate/hook_stop.py`

## Steering

### Generating security controls for an AWS service → steering/service-approval.md
Full 7-phase pipeline (Assess → Research → Validate → Map → Generate → Test → Summarize) with 19 sub-skills, sequential execution, MITRE ATT&CK optional enrichment, and error recovery instructions.

### Understanding the artifact flow → steering/service-approval.md (State File Dependencies section)
Dependency graph showing which artifacts feed into which phases.

### Validating generated controls → steering/service-approval.md (Validation section)
Hook configuration and manual validation commands using shared validation scripts.
