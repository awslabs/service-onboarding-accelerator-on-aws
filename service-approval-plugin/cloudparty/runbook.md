# Service Onboarding Cloud Party: Facilitation Runbook

## Overview

One-day hands-on workshop teaching security and platform teams to automate AWS service approval using AI-powered multi-agent tooling. Output: Service Approval Plugin that works with your choice of IDE — Kiro, Claude Code, GitHub Copilot, or Amazon Q Developer — to generate controls, compliance mappings, and Terraform modules for any future service.

**Audience:**

- **Primary:** Security team (threat modeling, controls design), Platform team (Terraform review, Artifactory deployment)
- **Secondary:** Risk and compliance teams (compliance mapping validation)

**Delivery options:**

- **Customer lab environment:** Deploy together during Cloud Party
- **AWS-provided ephemeral environment:** Workshop-style (like AWS Skill Builder) with temporary accounts

**Duration:** 8 hours (one day)

---

## What the Plugin Produces

Five-agent orchestration (Researcher → Validator → Generator → Tester → Summarizer):

### Research outputs (Researcher agent)

- **`controls-catalog.md`** — All controls organized in a 4×3 matrix: Proactive/Preventive/Detective/Corrective × Organisation/Account/Resource
- **`threat-model.md`** — Full threat register using MITRE ATT&CK tactics (10 tactics, TA0001–TA0040), each threat mapped to controls and mitigations with residual risk rating
- **`ccmv4-mapping.md`** — All 197 CCMv4 control IDs across 17 domains, each mapped or marked N/A

### Generated artifacts (Generator agent)

- **Security controls:** SCP (deny policies), RCP, tag policies, permission boundaries, CFN Guard rules, Config rules, EventBridge rules, Lambda remediator
- **IaC templates:** Modular Terraform (one module per resource asset), CDK TypeScript, CloudFormation, CDK for Terraform

### Output structure

```
.service-approval/
  APPROVAL-REPORT.md              ← final verdict + CCMv4 matrix (Summarizer)
  approval-evidence/              ← facilitator agent decision records
  state/
    research.json                 ← machine-readable state (Researcher)
    controls-catalog.md           ← controls matrix (Researcher)
    threat-model.md               ← MITRE threat register (Researcher)
    ccmv4-mapping.md              ← CCMv4 crosswalk (Researcher)
    validated.json                ← verified findings (Validator)
    test-results.json             ← test pass/fail (Tester)
    mcp-calls.log                 ← all MCP calls made
  controls/
    preventive/                   ← SCP, RCP, permission-boundary, tag-policy
    proactive/                    ← cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA policies
    detective/                    ← config-rules, eventbridge-rules, cloudwatch-alarms
    remediation/                  ← lambda-remediator, ssm-runbook, stepfunctions
    iac/                          ← compliant IaC templates
      main.tf                     ← root Terraform module
      modules/<asset>/            ← per-resource Terraform modules
      compliant-resource.cdk.ts   ← CDK TypeScript
      compliant-resource.cfn.yaml ← CloudFormation
      compliant-resource.cdktf.ts ← CDK for Terraform
```

---

## Pre-Cloud Party (2 weeks before)

### Customer provides

- AWS service to onboard (e.g., `bedrock-agentcore-control`)
- Compliance framework (CSA CCMv4, SOC2, PCI-DSS, or custom)
- Lab/dev environment access (if using customer infrastructure)

### AWS prepares

- Service Approval Plugin deployed (supports Kiro, Claude Code, GitHub Copilot, and Amazon Q Developer — customer chooses their preferred IDE)
- MCP tools configured (AWS Knowledge, AWS Docs, Terraform Registry)
- Canopy threat models available on GitHub (public access)
- Ephemeral environment provisioned (if customer lacks lab)
- Pre-run prototype to validate tooling
- Cloud Party facilitator agent for approval evidence recording

### Send pre-read (30 min)

- PRFAQ overview
- Multi-agent architecture diagram
- Sample outputs (`APPROVAL-REPORT.md`, `threat-model.md`, `ccmv4-mapping.md`, `controls-catalog.md`, IaC modules)
- Plugin installation instructions for customer's preferred IDE

---

## Cloud Party Agenda (8 hours)

### Session 1: Kickoff & Plugin Setup (60 min)

**Objectives:**

- Align on problem (60–90 day approval bottleneck)
- Install Service Approval Plugin
- Introduce facilitator agent

**Activities:**

1. **Problem statement** (10 min): Current manual process pain points
2. **Solution overview** (15 min): Five-agent workflow, outputs, success metrics
3. **Plugin installation** (20 min) — install for customer's chosen IDE:
   - **Kiro:** Copy plugin to `~/.kiro/agents/service-approval`
   - **Claude Code:** Run `claude plugin install ./service-approval-plugin`
   - **GitHub Copilot:** Copy instructions to `.github/copilot-instructions.md`
   - **Amazon Q Developer:** Copy instructions to `.amazonq/instructions.md`
4. **Facilitator agent demo** (10 min): Show approval evidence recording interface
5. **Q&A** (5 min): Clarify roles, expectations, tooling

> **Checkpoint:** Everyone has plugin installed in their chosen IDE and understands workflow

---

### Session 2: Threat Mapping — Security Team Review (90 min)

**Objectives:**

- Run Researcher and Validator agents live
- Security team reviews and approves MITRE threat model and controls catalog
- Record security team approval before proceeding to compliance mapping

**Activities:**

#### Live demo (30 min)

- Invoke plugin: `/service-approval ./my-docs --service=bedrock-agentcore-control`
- **Researcher agent:** Load Canopy threat model from GitHub, enrich via MCP (AWS Knowledge, AWS Docs). Produces three artifacts:
  - `state/controls-catalog.md` — all controls organized by category × scope matrix
  - `state/threat-model.md` — MITRE ATT&CK tactic-based threat register with controls mapped
  - `state/ccmv4-mapping.md` — all 197 CCMv4 IDs mapped or marked N/A
- **Validator agent:** Verifies all findings via MCP — confirms condition keys, API parameters, MITRE assignments, CCMv4 IDs. Produces `state/validated.json`.

#### Security team review — threat coverage (45 min)

Two approval gates in this review:

**Gate 1: MITRE threats and mitigating controls (25 min)**

- Interactive review: Project `state/threat-model.md` on screen
- Questions via facilitator agent:
  - "Do these MITRE threats accurately represent the risk surface for this service?"
  - "Are the mitigating controls sufficient for each threat?"
  - "Are controls categorized correctly (proactive/preventive/detective/corrective)?"
  - "Are organisation/account/resource scope levels appropriate for each control?"
  - "Which controls require manual review or additional context?"
- Validate coverage: Target >75% automated mapping
- Record decision: Facilitator agent captures *"Security team approves MITRE threat mapping and mitigating controls"* with timestamp

**Gate 2: Controls mapped to compliance objectives (20 min)**

- Review `state/ccmv4-mapping.md` — same controls mapped to all 197 CCMv4 objectives
- Security team validates that control-to-objective mappings are accurate from a security perspective
- Questions via facilitator agent:
  - "Do the control-to-objective mappings make sense from a security standpoint?"
  - "Are any control objectives missing coverage?"
  - "Which mappings need security team input before risk review?"
- Record decision: Facilitator agent captures *"Security team approves controls-to-objectives mapping for risk review"* with timestamp

#### Buffer (15 min)

- Handle follow-up questions, iterate on flagged items
- If security team finishes early, use time for informal discussion on institution-specific threat landscape

> **Checkpoint:** Security team has approved both threat model and CCMv4 mapping before risk team review

**Deliverable:** Security-approved `threat-model.md` + `ccmv4-mapping.md` with recorded decisions

---

### Break (15 min)

---

### Session 2b: Compliance Mapping — Risk Team Review (30 min)

**Objectives:**

- Risk/compliance team reviews and approves the CCMv4 mapping that security already validated
- Record risk team approval to complete the mapping phase

**Activities:**

#### Risk/compliance validation (30 min)

- Interactive review: Project `state/ccmv4-mapping.md` on screen (already security-approved)
- Questions via facilitator agent:
  - "Does the CCMv4 mapping align with your compliance framework and interpretation?"
  - "Are control objectives covered comprehensively per your audit requirements?"
  - "Which mappings need adjustment for your specific regulatory context?"
  - "Are there additional control objectives your framework requires that aren't covered?"
- Document adjustments: Note institution-specific customizations, regulatory nuances
- Record decision: Facilitator agent captures *"Risk team approves compliance mapping"* with timestamp

> **Checkpoint:** Both security and risk teams have approved all mappings — proceed to control generation

**Deliverable:** Fully approved `threat-model.md` + `ccmv4-mapping.md` with dual sign-off recorded

---

### Session 3: Generate Controls & IaC (90 min)

**Objectives:**

- Run Generator agent live
- Review generated security controls and Terraform modules
- Record platform team approval

**Activities:**

#### Generator agent demo (30 min)

- Reads `state/validated.json` and generates the full controls matrix:
  - **Org-level:** SCP deny policies, tag policies, Config org rules, Security Hub org config
  - **Account-level:** CFN Guard rules, Checkov config, permission boundary, EventBridge rules, Config rules, Lambda remediator
  - **Resource-level:** Resource policies, KMS key policies, RCP (where supported)
  - **IaC:** Modular Terraform (one module per resource asset), CDK TypeScript, CloudFormation, CDK for Terraform — all with embedded security controls and inline control ID comments

#### Platform team review (40 min)

- Interactive review: Walk through `controls/iac/` (Terraform modules) and `controls/preventive/` (SCP, RCP)
- Questions via facilitator agent:
  - "Do these Terraform patterns match your architectural standards?"
  - "Are security baselines sufficient?"
  - "Which variables need customization?"
  - "How do these integrate with existing Artifactory patterns?"
- Validate controls: Confirm SCPs, Config rules, and remediators are correctly scoped
- Document adjustments: Note naming conventions, tagging standards, network configurations

#### Approval decision (20 min)

- Questions via facilitator agent:
  - "Platform team: Do you approve these controls and IaC modules for testing?"
- Record decision: Facilitator agent captures *"Platform team approves controls and IaC for testing"* with timestamp
- Iterate if needed: Refine with `--clean` flag, re-run Generator agent

> **Checkpoint:** Platform team approves controls and IaC for testing

**Deliverable:** Approved security controls + IaC modules with recorded decision

---

### Lunch (60 min)

---

### Session 4: Automated Testing & Validation (60 min)

**Objectives:**

- Run Tester agent live
- Interpret validation report
- Iterate until tests pass

**Activities:**

#### Tester agent demo (20 min)

- Run with `--env=<profile>` flag to deploy test resources
- Execute `terraform validate`, `checkov`, `tfsec`, ASH
- Generate `state/test-results.json`
- Show pass/fail status per control

#### Platform team review (30 min)

- Interactive review: Walk through test results
- Questions via facilitator agent:
  - "Do failures indicate real issues or false positives?"
  - "Which controls need refinement?"
- Iterate: Refine modules, re-run with `--clean` flag until tests pass
- Record decision: Facilitator agent captures *"Platform team approves validated controls and IaC"* with timestamp

#### CI/CD integration (10 min)

- Wire tests to CI/CD pipeline (auto-execute on module changes)
- Demonstrate continuous compliance validation

> **Checkpoint:** All tests pass, modules ready for Artifactory

**Deliverable:** `test-results.json` + test scripts with recorded decision

---

### Session 5: Hands-On Practice (60 min)

**Objectives:**

- Team runs plugin independently on a second service
- Validate self-sufficiency
- Document lessons learned

**Activities:**

#### Select second service (5 min)

- Team chooses next service to onboard (e.g., S3, KMS)
- Load Canopy threat model from GitHub

#### Run plugin independently (40 min)

- **Security team:** Invoke `/service-approval --service=s3`, review `threat-model.md` and `controls-catalog.md`
- **Risk team:** Review `ccmv4-mapping.md`
- **Platform team:** Review generated IaC in `controls/iac/` and SCPs in `controls/preventive/`
- **All teams:** Run Tester agent, validate outputs
- **Facilitator agent:** Record decisions at each stage
- **Facilitator:** Provide guidance, answer questions, troubleshoot

#### Debrief (15 min)

- Questions via facilitator agent:
  - "What worked well?"
  - "What was confusing?"
  - "What institution-specific adjustments are needed?"
- Document lessons learned: Add to this runbook
- Feedback loop: Capture improvement suggestions in facilitator agent

> **Checkpoint:** Team successfully generates outputs for second service

**Deliverable:** Second service outputs + institution-specific customizations documented + feedback captured

---

### Session 6: Deployment & Next Steps (45 min)

**Objectives:**

- Deploy to Artifactory (or plan deployment)
- Finalize runbook with institution-specific notes
- Plan independent onboarding

**Activities:**

#### Deployment walkthrough (15 min)

- **Platform team:** Push Terraform modules from `controls/iac/` to Artifactory
- **Security team:** Add `threat-model.md` and `controls-catalog.md` to approved repository
- **Risk team:** Add `ccmv4-mapping.md` to approved repository
- **All teams:** Configure CI/CD pipeline with validation

#### Runbook finalization (15 min)

- Review this runbook
- Add institution-specific notes (naming conventions, approval workflows, Artifactory integration)
- Assign owner for runbook maintenance

#### Next steps planning (15 min)

- Questions via facilitator agent:
  - "Which services to onboard next?"
  - "Who owns independent onboarding?"
  - "When to schedule follow-up?"
- Schedule follow-up: 2-week check-in call, optional refresher after 1 month
- Feedback loop: Review captured feedback, prioritize improvements

> **Checkpoint:** Team has clear plan for independent onboarding

**Deliverable:** Finalized runbook with institution-specific customizations + feedback summary
