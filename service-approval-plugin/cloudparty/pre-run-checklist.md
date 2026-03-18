# Cloud Party — Pre-Run Checklist

Run this checklist the night before (or morning of) the Cloud Party.
Every item must pass before the session starts.

---

## 1. Plugin Installation (Customer's Chosen IDE)

Confirm the plugin is installed and working in the IDE the customer will use during the Cloud Party. Only one IDE is needed — verify the one they've chosen:

- [ ] **Kiro:** Plugin copied to `~/.kiro/agents/service-approval` — invoke test command, confirm agent loads
- [ ] **Claude Code:** `claude plugin install ./service-approval-plugin` — confirm plugin appears in `/plugins`
- [ ] **GitHub Copilot:** `.github/copilot-instructions.md` in place — confirm Copilot reads instructions
- [ ] **Amazon Q Developer:** `.amazonq/instructions.md` in place — confirm Q picks up instructions

**Verify:** Run a trivial command in the chosen IDE (e.g., list skills) to confirm the plugin responds.

---

## 2. MCP Tool Validation

- [ ] **AWS Knowledge MCP:** `awsknowledge` responds — test: query `bedrock-agentcore` API surface
- [ ] **AWS Docs MCP:** `aws-documentation` responds — test: fetch a known doc URL
- [ ] **Terraform Registry MCP:** responds — test: query `aws_bedrock_agent` resource

**Verify:** Each MCP call returns data (not timeout or auth error). Check `.service-approval/state/mcp-calls.log` for entries.

---

## 3. Canopy Threat Model

- [ ] Canopy threat model for target service accessible on GitHub (public repo)
- [ ] Threat model loads correctly — parse JSON, confirm `entities` key with mitigations array
- [ ] Mitigation IDs follow expected pattern (`M-<Resource>.<N>`)

**Verify:** Count mitigations. For `bedrock-agentcore-control`, expect ~37 mitigations.

---

## 4. Full Pipeline End-to-End Run

Run the complete five-agent pipeline against the target service:

```bash
/service-approval ./input-docs --service=bedrock-agentcore-control
```

- [ ] **Researcher** completes — all four outputs written:
  - `.service-approval/state/research.json`
  - `.service-approval/state/controls-catalog.md`
  - `.service-approval/state/threat-model.md`
  - `.service-approval/state/ccmv4-mapping.md`
- [ ] **Validator** completes — `.service-approval/state/validated.json` written
- [ ] **Generator** completes — `.service-approval/controls/` populated:
  - `preventive/` — SCP, RCP, tag-policy, permission-boundary
  - `proactive/` — cfn-guard-rules, checkov-config, OPA policies
  - `detective/` — config-rules, eventbridge-rules, cloudwatch-alarms
  - `remediation/` — lambda-remediator, ssm-runbook
  - `iac/` — main.tf, modules/<asset>/, compliant-resource.cdk.ts, .cfn.yaml, .cdktf.ts
- [ ] **Tester** completes (if `--env` available) — `.service-approval/state/test-results.json` written
- [ ] **Summarizer** completes — `.service-approval/APPROVAL-REPORT.md` written

**Verify:** Open `APPROVAL-REPORT.md` and confirm it has verdict, CCMv4 matrix, control inventory, and test evidence sections.

---

## 5. Facilitator Agent

```bash
cd service-onboarding/service-approval-plugin/cloudparty/cloudparty-facilitator-agent
python facilitate.py --list
python facilitate.py --stage session-2-gate-1
```

- [ ] `facilitate.py` runs with Python 3.x (no external dependencies)
- [ ] Interactive prompts display correctly (questions, decision choices, comments)
- [ ] Evidence files write to `.service-approval/approval-evidence/`
- [ ] `--summary` generates `summary.md` from recorded evidence
- [ ] `--list` shows recorded evidence files

**Verify:** Run through one stage, confirm markdown output is clean.

---

## 6. Ephemeral Environment (if applicable)

- [ ] AWS account provisioned and accessible
- [ ] IAM roles/credentials configured for Terraform deployment
- [ ] VPC/networking in place for test deployments
- [ ] `terraform init` succeeds in the environment

**Skip if:** Using customer's own lab environment (they handle access).

---

## 7. Fallback: Pre-Cached State Files

If MCP tools are slow or unavailable during the live session:

- [ ] Copy the pre-run state files to fallback locations:
  ```bash
  cp .service-approval/state/research.json .service-approval/state/research.json.fallback
  cp .service-approval/state/validated.json .service-approval/state/validated.json.fallback
  ```
- [ ] Verify fallback files load correctly when swapped in

**When to use:** If Researcher or Validator agents hang during live demo, swap in fallback files and continue from Generator stage.

---

## 8. Presentation & Materials

- [ ] Screen sharing works (projector or video call)
- [ ] Sample outputs ready to project (`threat-model.md`, `ccmv4-mapping.md`, `controls-catalog.md`, IaC modules)
- [ ] Runbook printed or accessible on a second screen
- [ ] Pre-read materials sent to attendees (PRFAQ, architecture diagram, sample outputs)

---

## Final Go/No-Go

| Check | Status |
|-------|--------|
| Plugin installed in chosen IDE | ⬜ |
| All 3 MCP tools respond | ⬜ |
| Canopy threat model loads | ⬜ |
| Full pipeline ran successfully | ⬜ |
| Facilitator agent works | ⬜ |
| Fallback files cached | ⬜ |
| Presentation materials ready | ⬜ |

**All boxes checked → GO.** Any unchecked → resolve before Cloud Party starts.
