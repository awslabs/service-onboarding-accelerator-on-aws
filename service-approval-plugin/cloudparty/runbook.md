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

### Research outputs

- **Threat-to-controls mapping:** Controls (proactive, preventative, detective, corrective) across platform/account/resource levels mapped to specific threats (MITRE)
- **Compliance mapping:** Controls (proactive, preventative, detective, corrective) across platform/account/resource levels mapped to each control objective (CCMv4)

### Generated artifacts

- **Terraform modules:** Production-ready resource definitions (without SCPs/control artifacts)
- **Validation reports:** ASH test results, compliance coverage matrix

### Output structure

```
.service-approval/
  APPROVAL-REPORT.md        ← final verdict + CCMv4 matrix
  approval-evidence/        ← facilitator agent decision records
  controls/
    threat-mapping.md       ← controls mapped to MITRE threats
    compliance-mapping.md   ← controls mapped to CCMv4 objectives
  terraform/                ← TF modules (resources only)
  state/                    ← agent handoff files
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
- Sample outputs (`APPROVAL-REPORT.md`, `threat-mapping.md`, `compliance-mapping.md`, TF modules)
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
- Security team reviews and approves MITRE threat mapping and mitigating controls
- Record security team approval before proceeding to compliance mapping

**Activities:**

#### Live demo (30 min)

- Invoke plugin: `/service-approval ./my-docs --service=bedrock-agentcore-control`
- **Researcher agent:** Load Canopy threat model from GitHub, enrich via MCP (AWS Knowledge, AWS Docs)
- **Validator agent:** Generate `threat-mapping.md` — controls (proactive, preventative, detective, corrective) across platform/account/resource levels → MITRE threats

#### Security team review — threat coverage (45 min)

Two approval gates in this review:

**Gate 1: MITRE threats and mitigating controls (25 min)**

- Interactive review: Project `threat-mapping.md` on screen
- Questions via facilitator agent:
  - "Do these MITRE threats accurately represent the risk surface for this service?"
  - "Are the mitigating controls sufficient for each threat?"
  - "Are controls categorized correctly (proactive/preventative/detective/corrective)?"
  - "Are platform/account/resource levels appropriate for each control?"
  - "Which controls require manual review or additional context?"
- Validate coverage: Target >75% automated mapping
- Record decision: Facilitator agent captures *"Security team approves MITRE threat mapping and mitigating controls"* with timestamp

**Gate 2: Controls mapped to compliance objectives (20 min)**

- Validator agent generates `compliance-mapping.md` — same controls mapped to CCMv4 (or customer's chosen framework)
- Security team validates that control-to-objective mappings are accurate from a security perspective
- Questions via facilitator agent:
  - "Do the control-to-objective mappings make sense from a security standpoint?"
  - "Are any control objectives missing coverage?"
  - "Which mappings need security team input before risk review?"
- Record decision: Facilitator agent captures *"Security team approves controls-to-objectives mapping for risk review"* with timestamp

#### Buffer (15 min)

- Handle follow-up questions, iterate on flagged items
- If security team finishes early, use time for informal discussion on institution-specific threat landscape

> **Checkpoint:** Security team has approved both threat mapping and compliance mapping before risk team review

**Deliverable:** Security-approved `threat-mapping.md` + `compliance-mapping.md` with recorded decisions

---

### Break (15 min)

---

### Session 2b: Compliance Mapping — Risk Team Review (30 min)

**Objectives:**

- Risk/compliance team reviews and approves the compliance mapping that security already validated
- Record risk team approval to complete the mapping phase

**Activities:**

#### Risk/compliance validation (30 min)

- Interactive review: Project `compliance-mapping.md` on screen (already security-approved)
- Questions via facilitator agent:
  - "Does the CCMv4 mapping align with your compliance framework and interpretation?"
  - "Are control objectives covered comprehensively per your audit requirements?"
  - "Which mappings need adjustment for your specific regulatory context?"
  - "Are there additional control objectives your framework requires that aren't covered?"
- Document adjustments: Note institution-specific customizations, regulatory nuances
- Record decision: Facilitator agent captures *"Risk team approves compliance mapping"* with timestamp

> **Checkpoint:** Both security and risk teams have approved all mappings — proceed to Terraform generation

**Deliverable:** Fully approved `threat-mapping.md` + `compliance-mapping.md` with dual sign-off recorded

---

### Session 3: Generate Terraform Modules (90 min)

**Objectives:**

- Run Generator agent live
- Review generated Terraform modules (resources only, no SCPs/control artifacts)
- Record platform team approval

**Activities:**

#### Generator agent demo (30 min)

- Read approved `threat-mapping.md` and `compliance-mapping.md`
- Query Terraform Registry via MCP
- Generate Terraform modules (resources only):
  - Encryption at rest with KMS
  - Private networking with VPC
  - Least-privilege IAM roles
  - CloudWatch logging
  - Security groups
  - Compliance tags

#### Platform team review (40 min)

- Interactive review: Walk through `.service-approval/terraform/`
- Questions via facilitator agent:
  - "Do these patterns match your architectural standards?"
  - "Are security baselines sufficient?"
  - "Which variables need customization?"
  - "How do these integrate with existing Artifactory patterns?"
- Validate controls: Confirm security controls embedded in resources
- Document adjustments: Note naming conventions, tagging standards, network configurations

#### Approval decision (20 min)

- Questions via facilitator agent:
  - "Platform team: Do you approve these Terraform modules for testing?"
- Record decision: Facilitator agent captures *"Platform team approves TF modules for testing"* with timestamp
- Iterate if needed: Refine modules based on feedback, re-run Generator agent

> **Checkpoint:** Platform team approves Terraform modules for testing

**Deliverable:** Approved Terraform modules (resources only) with recorded decision

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
- Generate validation report
- Show pass/fail status per control

#### Platform team review (30 min)

- Interactive review: Walk through validation report
- Questions via facilitator agent:
  - "Do failures indicate real issues or false positives?"
  - "Which controls need refinement?"
- Iterate: Refine modules, re-run with `--clean` flag until tests pass
- Record decision: Facilitator agent captures *"Platform team approves validated TF modules"* with timestamp

#### CI/CD integration (10 min)

- Wire tests to CI/CD pipeline (auto-execute on module changes)
- Demonstrate continuous compliance validation

> **Checkpoint:** All tests pass, modules ready for Artifactory

**Deliverable:** Validation report + test scripts with recorded decision

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

- **Security team:** Invoke `/service-approval --service=s3`, review `threat-mapping.md`
- **Risk team:** Review `compliance-mapping.md`
- **Platform team:** Review generated Terraform modules
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

- **Platform team:** Push Terraform modules to Artifactory
- **Security team:** Add `threat-mapping.md` to approved repository
- **Risk team:** Add `compliance-mapping.md` to approved repository
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
