---
name: generate-v3
description: Generate all security control artifacts and compliant IaC templates from mapping-results.json and validated.json. Split into 3 focused sub-skills for better accuracy; this skill orchestrates them.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Control Generator v3

Read `.service-approval/state/mapping-results.json` (produced by Mapper) for controls and
framework mappings. Read `.service-approval/state/validated.json` (produced by Validator v3)
for API surface and capabilities. Generate artifacts organized by the Controls Matrix
(Category x Scope). Write to `.service-approval/controls/`.

## Sub-Skill Architecture

This skill is split into 3 focused sub-skills that write to separate directories:

| Sub-Skill | Focus | Output Directory |
|-----------|-------|-----------------|
| `generate-preventive` | SCPs, resource policies, KMS key policies, permission boundaries, tag policies, OPA, CFN Guard | `controls/preventive/`, `controls/proactive/` |
| `generate-detective` | Config rules, Lambda handlers, EventBridge, CloudWatch, SSM runbooks, Step Functions | `controls/detective/`, `controls/remediation/` |
| `generate-iac` | Terraform modules, CDK TypeScript, CloudFormation YAML, CDK for Terraform | `controls/iac/` |

**When invoked directly** (via `/generate`), this skill runs all 3 sub-skills sequentially.
**When invoked by the orchestrator**, the orchestrator dispatches sub-skills in parallel.

## Agent model rule

When spawning subagents (via the Agent tool) for parallel artifact generation, do NOT specify
a `model` parameter. Omitting `model` causes subagents to inherit the caller's model.

---

## Prerequisites

```bash
test -f .service-approval/state/mapping-results.json && echo "mapping-results: OK" || echo "ERROR: run mapper first"
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR: run validator first"
mkdir -p .service-approval/controls/{proactive,preventive,detective,remediation,iac}
mkdir -p .service-approval/controls/proactive/opa-policies
mkdir -p .service-approval/controls/remediation/lambda-remediator
mkdir -p .service-approval/controls/detective/config-rule-lambdas
```

Create Terraform module directories:
```bash
for asset in $(python3 -c "import json; d=json.load(open('.service-approval/state/validated.json')); [print(a['name'].lower().replace(' ','-')) for a in d['assets']]"); do
  mkdir -p ".service-approval/controls/iac/modules/${asset}"
done
mkdir -p .service-approval/controls/iac/modules/_shared
```

---

## Direct Invocation Mode (Sequential)

When this skill is invoked directly (not by orchestrator):

### Step 1: Run generate-preventive
Follow ALL instructions in `skills/generate-preventive/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/preventive/` and `controls/proactive/` to be populated.

### Step 2: Run generate-detective
Follow ALL instructions in `skills/generate-detective/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/detective/` and `controls/remediation/` to be populated.

### Step 3: Run generate-iac
Follow ALL instructions in `skills/generate-iac/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `controls/iac/` to be populated with all 4 formats.

### Step 4: Final Validation
Run the comprehensive validation below.

---

## Final Validation

Final validation runs automatically via PostToolUse hooks (validate_controls.py per-file checks) and Stop hook (validate_cross.py cross-artifact checks X1-X11).

---

## Print Summary

```
Control generation complete (v3):
  Sub-skills:
    - generate-preventive:  preventive/ + proactive/
    - generate-detective:   detective/ + remediation/
    - generate-iac:         iac/ (4 formats + {N} TF modules)
  Controls matrix:
    Org×Proactive:    tag-policy, OPA, cfn-guard [, scp-provisioning]
    Org×Preventive:   scp-policy [, ai-optout]
    Org×Detective:    config-org-rules, conformance-pack, cloudtrail-org-config
    Org×Corrective:   ssm-runbook-org
    Acc×Proactive:    cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA
    Acc×Preventive:   permission-boundary
    Acc×Detective:    config-rules, eventbridge-rules, cloudwatch-alarms [, access-analyzer]
    Acc×Corrective:   lambda-remediator, ssm-runbook, stepfunctions-workflow
    Res×Preventive:   resource-policy [, kms-key-policy] [, rcp-policy]
    Res×Corrective:   stepfunctions-workflow (resource-level)
  IaC:          CDK, CFN, CDKTF + Terraform ({N} modules)
  Output: .service-approval/controls/
```
