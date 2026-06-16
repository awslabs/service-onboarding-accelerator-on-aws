---
name: generate-v3
description: Generate all security control artifacts and compliant IaC templates from mapping-results.json and validated.json. Split into 3 focused sub-skills for better accuracy; this skill orchestrates them.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Control Generator v3

Read `.service-approval/<slug>/04-map/mapping-results.json` (produced by Mapper) for controls and
framework mappings. Read `.service-approval/<slug>/03-validate/validated.json` (produced by Validator v3)
for API surface and capabilities. Generate artifacts organized by the Controls Matrix
(Category x Scope). Write to `.service-approval/<slug>/05-generate/`.

## Sub-Skill Architecture

This skill is split into 3 focused control families that write to separate
directories. The **preventive family is itself a sequenced sub-pipeline** (a
recommender gate → reference-anchored authors → a root-cause critic), so that
the *decision* of how to enforce an objective happens before any policy is
authored, and every authored policy is proven anchored and enforcing:

| Family | Sub-skills | Output Directory |
|--------|-----------|-----------------|
| Preventive (gated) | `generate-preventive-recommend` → (`generate-preventive-scp` / `generate-preventive-rcp` / `generate-preventive-iam`) → `generate-preventive-rootcause` | `<slug>/05-generate/preventive/`, `<slug>/05-generate/proactive/` |
| Detective | `generate-detective` | `<slug>/05-generate/detective/`, `<slug>/05-generate/responsive/` |
| IaC | `generate-iac` | `<slug>/05-generate/iac/` |

`skills/generate-preventive/SKILL.md` is retained as the **shared authoring-rules
reference** the preventive authors follow (SCP/RCP/IAM rules, Rule C2, the
proactive sections). It is no longer dispatched as a single monolithic generator.

**When invoked directly** (via `/generate`), this skill runs the families
sequentially (and the preventive sub-pipeline in its fixed order).
**When invoked by the orchestrator**, the orchestrator dispatches the three
families in parallel; the preventive family runs its sub-skills in order.

## Agent model rule

When spawning subagents (via the Agent tool) for parallel artifact generation, do NOT specify
a `model` parameter. Omitting `model` causes subagents to inherit the caller's model.

---

## Prerequisites

**Hard gate — halts the run if upstream phases are incomplete.**

```bash
python3 -m tools.validate.check_phase_complete --slug <slug> --phase 03-validate || exit 2
python3 -m tools.validate.check_phase_complete --slug <slug> --phase 04-map || exit 2

mkdir -p .service-approval/<slug>/05-generate/{proactive,preventive,detective,responsive,iac}
mkdir -p .service-approval/<slug>/05-generate/proactive/opa-policies
mkdir -p .service-approval/<slug>/05-generate/responsive/lambda-remediator
mkdir -p .service-approval/<slug>/05-generate/detective/config-rule-lambdas
```

The check_phase_complete CLI verifies every required artifact (mapping-results.json,
controls-catalog.md, framework-mapping.md, validated.json, etc.) exists and is
non-stub. Without this gate, generate would silently skip controls when its
inputs are missing, producing an empty 05-generate/ tree.

Create Terraform module directories:
```bash
for asset in $(python3 -c "import json; d=json.load(open('.service-approval/<slug>/03-validate/validated.json')); [print(a['name'].lower().replace(' ','-')) for a in d['assets']]"); do
  mkdir -p ".service-approval/<slug>/05-generate/iac/modules/${asset}"
done
mkdir -p .service-approval/<slug>/05-generate/iac/modules/_shared
```

---

## Direct Invocation Mode (Sequential)

When this skill is invoked directly (not by orchestrator):

### Step 1: Run the preventive sub-pipeline (in order)
Run the preventive sub-skills sequentially — each step gates the next:
1. `skills/generate-preventive-recommend/SKILL.md` — decide mechanism + anchor
   per objective; writes `<slug>/05-generate/preventive-plan.json` (the gate).
2. For each `GENERATE_*` row in the plan, the matching author:
   `skills/generate-preventive-scp/SKILL.md`, `…-rcp/SKILL.md`, `…-iam/SKILL.md`.
   These also write the proactive artifacts per
   `skills/generate-preventive/SKILL.md` (tag policy, OPA, CFN Guard, Checkov).
3. `skills/generate-preventive-rootcause/SKILL.md` — prove every preventive
   artifact is anchored and enforcing; route non-preventable objectives to detective.
Pass: `--service`, `--include-unverified` if set.
Wait for `<slug>/05-generate/preventive/` and `<slug>/05-generate/proactive/` to be populated.

### Step 2: Run generate-detective
Follow ALL instructions in `skills/generate-detective/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Runs AFTER Step 1's root-cause critic so it can consume
`<slug>/05-generate/detective-routing.json` (objectives the critic found
not-preventable and routed to detective) in its top-up pass.
Wait for `<slug>/05-generate/detective/` and `<slug>/05-generate/responsive/` to be populated.

### Step 3: Run generate-iac
Follow ALL instructions in `skills/generate-iac/SKILL.md`.
Pass: `--service`, `--include-unverified` if set.
Wait for `<slug>/05-generate/iac/` to be populated with all 4 formats.

### Step 4: Final Validation
Run the comprehensive validation below.

---

## Final Validation

Final validation runs automatically via PostToolUse hooks (validate_controls.py per-file checks) and Stop hook (validate_cross.py cross-artifact checks X1-X11).

---

## Phase 4 Inventory

After sub-skills finish, print a one-screen inventory of what was generated. This
gives the user (and Summarize) a quick view of category counts and which IaC formats
are actually present. Runs unconditionally — no HITL gate.

```bash
python3 - <<'PY'
import json
from pathlib import Path

root = Path(f".service-approval/{slug}/05-generate")
categories = ["preventive", "proactive", "detective", "responsive", "iac"]
counts = {c: sum(1 for _ in (root / c).rglob("*") if _.is_file()) if (root / c).exists() else 0
          for c in categories}

iac_formats = {}
iac_root = root / "iac"
if iac_root.exists():
    iac_formats["terraform"]      = (iac_root / "modules").exists()
    iac_formats["cloudformation"] = any(iac_root.glob("*.cfn.yaml")) or any(iac_root.glob("*.yaml"))
    iac_formats["cdk-typescript"] = any(iac_root.rglob("*.ts"))
    iac_formats["cdktf"]          = (iac_root / "cdktf").exists() or any(iac_root.rglob("cdktf.json"))

service = None
sj = Path(f".service-approval/{slug}/03-validate/validated.json")
if sj.exists():
    service = json.loads(sj.read_text()).get("service")

formats_present = ", ".join(k for k, v in iac_formats.items() if v) or "(none)"
print(f"Phase 4 complete — {service or '(unknown service)'}:")
for c in categories:
    print(f"  {c.capitalize():13} {counts[c]} files")
print(f"  IaC formats:  {formats_present}")
PY
```

---

## Print Summary

```
Control generation complete (v3):
  Sub-skills:
    - generate-preventive:  preventive/ + proactive/
    - generate-detective:   detective/ + responsive/
    - generate-iac:         iac/ (4 formats + {N} TF modules)
  Controls matrix:
    Org×Proactive:    tag-policy, OPA, cfn-guard [, scp-provisioning]
    Org×Preventive:   scp-policy [, ai-optout]
    Org×Detective:    config-org-rules, conformance-pack, cloudtrail-org-config
    Org×Responsive:   ssm-runbook-org
    Acc×Proactive:    cfn-guard-rules, cfn-hooks-policy, checkov-config, OPA
    Acc×Preventive:   permission-boundary
    Acc×Detective:    config-rules, eventbridge-rules, cloudwatch-alarms [, access-analyzer]
    Acc×Responsive:   lambda-remediator, ssm-runbook, stepfunctions-workflow
    Res×Preventive:   resource-policy [, kms-key-policy] [, rcp-policy]
    Res×Responsive:   stepfunctions-workflow (resource-level)
  IaC:          CDK, CFN, CDKTF + Terraform ({N} modules)
  Output: .service-approval/<slug>/05-generate/
```
