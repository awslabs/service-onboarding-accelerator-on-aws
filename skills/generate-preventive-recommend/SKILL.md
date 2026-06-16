---
name: generate-preventive-recommend
description: Decide the enforcement mechanism for each preventive control objective — SCP, RCP, IAM, or "not preventable → detective/proactive" — and anchor each decision to a reference example. Runs first in the preventive sub-pipeline and gates the authoring sub-skills. Reads mapping-results.json, validated.json, and the reference index.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Preventive: Mechanism Recommender (gate)

This is the **decision** sub-skill of preventive generation. It runs **first** and
produces the plan every authoring sub-skill obeys. For each preventive (PRV)
control it answers two questions and records the answer:

1. **Is the objective preventable at request time?** (root-cause / preventability)
2. **Can we anchor it to a known-good reference example?** (repo anchor)

A preventive policy is authored **only when both are yes**. When either is no,
we do **not** invent a preventive control — we point the customer at the
reference, or route the objective to a detective/proactive control instead.

**Input:**
- `.service-approval/<slug>/04-map/mapping-results.json` — controls (filter `category == "PRV"`)
- `.service-approval/<slug>/03-validate/validated.json` — API surface + condition keys
- `data/reference-repos/index.yaml` — the reference anchor library (via `tools/reference_index.py`)

**Output:** `.service-approval/<slug>/05-generate/preventive-plan.json` — the per-control
decision plan consumed by `generate-preventive-scp`, `-rcp`, and `-iam`.

> This output lives in the `05-generate/` root, NOT in `preventive/`, so it is a
> plan, not a policy artifact (the reference-anchor gate scans `preventive/*.json`).

---

## Prerequisites

```bash
test -f .service-approval/<slug>/04-map/mapping-results.json && echo "mapping: OK" || echo "ERROR"
test -f .service-approval/<slug>/03-validate/validated.json && echo "validated: OK" || echo "ERROR"
test -f data/reference-repos/index.yaml && echo "ref-index: OK" || echo "ERROR — build it: python3 tools/post-process/build_reference_index.py --repos-dir <clones>"
mkdir -p .service-approval/<slug>/05-generate
```

---

## Step 1 — Preventability (root-cause) verdict per control

Run the preventability analyzer over the mapped controls. It finds, for each PRV
control, the condition key(s) that gate the control's target action(s):

```bash
python3 tools/validate/validate_preventability.py --slug <slug> --json > /tmp/preventability.json
```

Each entry carries `verdict` (`FEASIBLE` | `NOT_PREVENTABLE`),
`enforcing_condition_keys[]`, and `route_to`. Treat the SAR condition-key list as
a **lower bound**: if the analyzer says `NOT_PREVENTABLE` but you can cite an
authoritative AWS doc (service authorization reference) for a gating condition
key the SAR snapshot lacks, you may override to `FEASIBLE` — record the doc URL
in the plan's `preventability_override` field and log the MCP lookup.

## Step 2 — Reference anchor per control

For each `FEASIBLE` control, find a matching reference example using the shared
loader. Match on **mechanism** first, then prefer examples whose governed actions
or condition keys overlap the control's:

```bash
python3 - <<'PY'
import json, sys
sys.path.insert(0, "tools")
import reference_index as ri

control_mechanism = "SCP"   # from the control's mapping mechanism → see table below
candidates = ri.examples_for_mechanism(control_mechanism)
# Rank by overlap with the control's governed actions / condition keys.
PY
```

**Mechanism → reference family:**

| Control `mechanism` (mapping-results) | Anchor mechanism in index | Authoring sub-skill |
|---|---|---|
| `SCP` | `SCP` | `generate-preventive-scp` |
| `RCP` | `RCP` | `generate-preventive-rcp` |
| `IAM Policy`, `IAM Trust Policy`, `IAM Permission Boundary`, `Resource Policy`, `Resource-Based Policy`, `KMS Key Policy`, `VPCE Policy` | `IAM`, `permission-boundary`, `data-perimeter`, `VPCE` | `generate-preventive-iam` |

If **no** example matches the mechanism (or no example overlaps the control's
actions/keys), the control gets `decision: "REFER_TO_REFERENCE"` — we do not
author. Surface the closest reference family so the customer knows where to look.

## Step 3 — Emit the plan

Write `.service-approval/<slug>/05-generate/preventive-plan.json`:

```json
{
  "_metadata": {
    "service": "<service-name>",
    "generated": "service-approval v3.0.0",
    "reference_index_version": 1
  },
  "decisions": [
    {
      "control_id": "CTRL-ORG-PRV-001",
      "mechanism": "SCP",
      "preventable": true,
      "enforcing_condition_keys": ["lambda:CodeSigningConfigArn"],
      "decision": "GENERATE_SCP",
      "anchor": {
        "example_id": "service-control-policy-examples-deny-...",
        "repo": "service-control-policy-examples",
        "url": "https://github.com/aws-samples/.../blob/<sha>/<path>"
      },
      "route_to": null,
      "rationale": "condition key gates CreateFunction; SCP example covers the deny-on-create pattern"
    },
    {
      "control_id": "CTRL-ORG-PRV-007",
      "mechanism": "SCP",
      "preventable": false,
      "decision": "ROUTE_DETECTIVE",
      "anchor": null,
      "route_to": "detective",
      "rationale": "no condition key gates DeleteFunction; a request-time deny would silently never fire"
    }
  ]
}
```

`decision` is one of:
- `GENERATE_SCP` / `GENERATE_RCP` / `GENERATE_IAM` — authoring sub-skill proceeds; `anchor` MUST be non-null.
- `REFER_TO_REFERENCE` — preventable but no anchor; do not author. Point to the closest reference.
- `ROUTE_DETECTIVE` — not preventable; the detective generator should cover this objective.

## Step 4 — Hand-off summary

```
Preventive recommender complete — <service>:
  GENERATE_SCP:        N controls (anchored)
  GENERATE_RCP:        N controls (anchored)
  GENERATE_IAM:        N controls (anchored)
  REFER_TO_REFERENCE:  N controls (no anchor — see reference)
  ROUTE_DETECTIVE:     N controls (not preventable)
  Plan: .service-approval/<slug>/05-generate/preventive-plan.json
```

The authoring sub-skills read ONLY rows whose `decision` is `GENERATE_*` and
whose `anchor` is non-null. A `GENERATE_*` row with a null anchor is a bug in
this skill — fix the anchor lookup, do not let authoring proceed un-anchored
(the reference-anchor gate would hard-fail it anyway).
