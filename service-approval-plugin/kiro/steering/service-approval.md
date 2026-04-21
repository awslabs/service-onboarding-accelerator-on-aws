# Service Approval — Kiro Execution Guide

## Scope
You are running the service-approval skill (v3.0). Your role is to generate AWS security controls
and compliant resource templates for a specified AWS service, with optional MITRE ATT&CK threat mapping.

## Execution Mode
**Parallel via Subagents** — Kiro supports subagents that run in parallel. The main agent waits for all subagents to complete before proceeding to the next phase. Each subagent has its own context window. Steering and MCP servers are available in subagents; Specs and Hooks are not.

All sub-skills are in `service-approval-plugin/skills/`. Each sub-skill has its own `SKILL.md`.

### Parallelization Windows
Use `Run subagents to...` or let Kiro auto-launch subagents for these independent phases:

**Window 1 — Research (Phase 1a-1d):** 4 subagents in parallel
- Subagent 1: `skills/research-mitigations/SKILL.md`
- Subagent 2: `skills/research-capabilities/SKILL.md`
- Subagent 3: `skills/research-api-surface/SKILL.md`
- Subagent 4 (optional): `skills/research-attack-surface/SKILL.md`
- After all complete → merge into `state/research.json` (Phase 1e)

**Window 2 — Map (Phase 3a-3b):** 2 subagents in parallel
- Subagent 1: `skills/map-parse-framework/SKILL.md`
- Subagent 2: `skills/map-generate-controls/SKILL.md`
- After both complete → Phase 3c and 3d run sequentially

**Window 3 — Generate (Phase 4a-4c):** 3 subagents in parallel
- Subagent 1: `skills/generate-preventive/SKILL.md`
- Subagent 2: `skills/generate-detective/SKILL.md`
- Subagent 3: `skills/generate-iac/SKILL.md`

Phases 0 (Assess), 2 (Validate), 5 (Test), and 6 (Summarize) run sequentially — they have cross-phase dependencies.

## Hard Rules
1. Never deploy to production unless explicitly confirmed by the user
2. Always verify API parameters via MCP before generating controls
3. Write all state files to `.service-approval/state/` relative to the working directory
4. Never skip the Validator — UNVERIFIED items must not reach the Control Generator
5. All ATT&CK reference data files are in `service-approval-plugin/data/`
6. Every generated control must trace to at least one framework objective

---

## Pipeline: 7 Phases (19 sub-skills)

### Phase 0: Assess
**Sub-skill:** `skills/assess/SKILL.md`
**Input:** `input/sar-slugs.json`, CCMv4 framework
**Output:**
- `state/sar-facts.json` — SAR extraction (actions, condition keys, resource types)
- `state/checkpoint-results.json` — Definitive checks (SCP, RCP, FIPS, RAM, Config, etc.)
- `state/assessment-summary.md` — 5-domain CAF security posture

### Phase 1: Research (4 sub-skills + merge, sequential)

**1a — Mitigations:**
`skills/research-mitigations/SKILL.md` → `state/research-mitigations.json`
- Parses input documents, extracts mitigations, assets, assessment gaps

**1b — Capabilities:**
`skills/research-capabilities/SKILL.md` → `state/research-capabilities.json`
- IAM, encryption, network, logging, org-policy capabilities via MCP

**1c — API Surface:**
`skills/research-api-surface/SKILL.md` → `state/research-api-surface.json`
- Complete API operations and parameters via MCP

**1d — Attack Surface (OPTIONAL — MITRE ATT&CK):**
`skills/research-attack-surface/SKILL.md` → `state/research-attack-surface.json`
- Maps API patterns to MITRE ATT&CK v16.1 Cloud techniques
- Uses reference data: `data/attack-cloud-matrix.json`, `data/stride-to-attack-bridge.json`, `data/attack-nist-ccm-crosswalk.json`
- Builds STRIDE-to-ATT&CK bridge and tactic coverage summary
- **Skip with `--skip-attack-surface` if time-constrained**

**1e — Merge:**
`skills/research/SKILL.md` (merge step) → `state/research.json` (schema v3.0)
- Merges 1a + 1b + 1c + optional 1d (attack_surface field)

### Phase 2: Validate
**Sub-skill:** `skills/validate/SKILL.md`
**Input:** `state/research.json`
**Output:** `state/validated.json` (schema v3.0)
- MCP-based verification of all research claims
- Enriches attack_surface if present (adds verification notes)

**Validation checks include:**
- Step 2a: Verify capabilities against MCP documentation reads
- Step 2b: Verify API parameters against MCP documentation reads
- Step 2c: Verify ATT&CK attack surface (if present) — technique applicability, API evidence, NIST/CCMv4 mapping

### Phase 3: Map (4 sub-skills, sequential)

**3a — Parse Framework:**
`skills/map-parse-framework/SKILL.md` → `state/map-framework-parsed.json`

**3b — Generate Controls:**
`skills/map-generate-controls/SKILL.md` → `state/map-controls-generated.json`
- 4 control categories: Proactive (PRO), Preventive (PRV), Detective (DET), Corrective (COR)
- 3 scope levels: Organisation (ORG), Account (ACC), Resource (RES)
- Controls enriched with `attack_techniques[]` if attack_surface present

**3c — Framework Mapping:**
`skills/map-framework-mapping/SKILL.md` → `state/map-framework-mapped.json`

**3d — Assemble:**
`skills/map-assemble/SKILL.md` → `state/mapping-results.json`, `controls-catalog.md`, `framework-mapping.md`
- **Phase 2b: ATT&CK Coverage Summary** (only if attack_surface present):
  - Builds technique→control reverse index
  - Calculates tactic-level coverage percentages
  - Identifies uncovered HIGH-applicability techniques
  - Adds `attack_coverage` section to mapping-results.json
  - Adds "ATT&CK Technique Coverage" table to controls-catalog.md

### Phase 4: Generate (3 sub-skills, sequential)

**4a — Preventive + Proactive:**
`skills/generate-preventive/SKILL.md`
- Output: `controls/preventive/` (SCP, IAM, KMS, VPC endpoint, tag, resource, RCP policies)
- Output: `controls/proactive/` (CFN Guard rules, Checkov configs, OPA policies, custom Checkov rules)

**4b — Detective + Remediation:**
`skills/generate-detective/SKILL.md`
- Output: `controls/detective/` (Config rules, CloudTrail, CloudWatch alarms, EventBridge, Access Analyzer)
- Output: `controls/remediation/` (Lambda remediators, SSM runbooks, Step Functions workflows)

**4c — IaC Templates:**
`skills/generate-iac/SKILL.md`
- Output: `controls/iac/` — 4 required formats:
  - Terraform (modular: main.tf, variables.tf, outputs.tf + per-resource modules)
  - CloudFormation YAML
  - CDK TypeScript (package.json, tsconfig.json, src/stack.ts)
  - CDK for Terraform — CDKTF (package.json, tsconfig.json, main.ts)
- Uses `aws-documentation` and `awsiac` MCP servers for CDK/CDKTF construct lookups

### Phase 5: Test (optional)
**Sub-skill:** `skills/test/SKILL.md`
**Condition:** Only if `--env` provided AND not `--skip-test` AND not `--dry-run`
**Output:** `state/test-results.json`

### Phase 6: Summarize
**Sub-skill:** `skills/summarize/SKILL.md`
**Output:** `.service-approval/APPROVAL-REPORT.md`
- Includes all control categories with counts
- Includes framework mapping coverage
- **Includes ATT&CK Threat Coverage section** (if attack_surface was run):
  - Tactic heat map with coverage percentages
  - Threat Gaps table with uncovered HIGH techniques and recommendations

---

## State File Dependencies

```
Phase 0: sar-facts.json, checkpoint-results.json, assessment-summary.md
    ↓
Phase 1: research-mitigations.json + research-capabilities.json +
         research-api-surface.json + [research-attack-surface.json]
    ↓ (merge)
         research.json (v3.0, with optional attack_surface)
    ↓
Phase 2: validated.json (v3.0, with optional attack_surface)
    ↓
Phase 3: map-framework-parsed.json → map-controls-generated.json →
         map-framework-mapped.json → mapping-results.json (with optional attack_coverage)
    ↓
Phase 4: controls/preventive/, controls/proactive/, controls/detective/,
         controls/remediation/, controls/iac/
    ↓
Phase 6: APPROVAL-REPORT.md
```

---

## Error Recovery
- If a sub-skill fails, check `.service-approval/state/mcp-calls.log` for MCP errors
- Re-run the failed phase only — do not restart from Phase 0
- State files are checkpoints; each phase reads the prior phase's output
- If MCP is unavailable, the skill will report the error and halt

## Validation via Kiro Hooks

Hooks are auto-created during Power onboarding (see POWER.md). They use the same validation scripts as Claude Code's hooks — the scripts are tool-agnostic.

### Hook 1: `validate-state-files.kiro.hook` (File Save)
- **Trigger:** File Save on `.service-approval/state/*.json` and `.service-approval/controls/**/*`
- **Action:** Run Command → `python3 service-approval-plugin/tools/validate/hook_post_tool_use.py`
- Validates JSON structure, schema versions, and cross-references after each file write

### Hook 2: `final-cross-validation.kiro.hook` (Agent Stop)
- **Trigger:** Agent Stop
- **Action:** Run Command → `python3 service-approval-plugin/tools/validate/hook_stop.py`
- Runs cross-file validation (controls ↔ assets, controls ↔ framework, ATT&CK techniques ↔ API operations)

### Hook 3: Deployability Check (Manual)
- **Trigger:** Manual (run on demand via Kiro Hook UI or Command Palette)
- **Action:** Run Command → `python3 service-approval-plugin/tools/validate/validate_deployable.py`
- Checks AWS prerequisites for deployment

### Manual validation (if hooks not configured)
If hooks were not created during onboarding, run manually:
```bash
python3 service-approval-plugin/tools/validate/validate_cross.py
python3 service-approval-plugin/tools/validate/validate_deployable.py
```
