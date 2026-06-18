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
- (optional) Canopy threat-model — when one was provided for this service, its
  `mitigations[]` carry the control intent and citation; see "Sourcing order" below.

**Output:** `.service-approval/<slug>/05-generate/preventive-plan.json` — the per-control
decision plan consumed by `generate-preventive-scp`, `-rcp`, and `-iam`.
**Schema:** `schemas/preventive-plan.schema.json` — enforces the decision enum, the
`CTRL-<SCOPE>-<CAT>-NNN` id pattern, and the rules that every `GENERATE_*` decision
carries a non-null `anchor.example_id` and every `ROUTE_DETECTIVE` carries a `route_to`.
Validated at write time by `validate_controls.py`.

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

## Sourcing order (Canopy first)

When deciding the enforcement mechanism and anchor for each preventive control,
walk the source list in this order — stop at the first source that yields a
usable answer, fall through only when nothing applies:

1. **Canopy mitigation (highest priority)** — if a Canopy threat-model was
   provided for this service, its `mitigations[]` entries supply the control
   intent (`statement` field), the exact operation+parameter to gate
   (`configurationRequestParameters[]`), and the citation (the mitigation's
   `alias`). Treat a Canopy mitigation as the authoritative source of intent
   for any control that maps to it; record `citation: {type: "canopy", id:
   "<alias>"}` on the plan row. **IMPORTANT:** Canopy contains NO preventive
   policy TEXT — its implementations are only AWS Config rules (detective)
   and CloudFormation Hooks (proactive). A Canopy-anchored preventive control
   STILL must resolve a reference-repo example for the SCP/RCP/IAM policy
   BODY (source 2 below); if no reference example matches, downgrade the
   decision to detective/proactive (`ROUTE_DETECTIVE` with `route_to:
   "detective"` or `"proactive"`). Canopy supplies intent and citation, not
   policy body.
2. **Reference-repo index** (`data/reference-repos/index.yaml`) — the
   deterministic ranker (`tools/reference_index.py`) scores published AWS
   sample policies by mechanism + action + condition-key overlap. This
   produces the policy BODY anchor (`citation: {type: "reference", id:
   "<example_id>", url: "<source_url>"}`).
3. **AWS Control Catalog API** — for objectives the AWS Control Catalog
   covers, cite the catalog control ARN directly (`citation: {type:
   "catalog", id: "<arn>"}`). Use only when neither Canopy intent nor a
   reference-repo example matches and the catalog has an explicit control.
4. **Service-specific AWS documentation** — last resort, only when the
   prior three sources have nothing. Cite the exact doc URL (`citation:
   {type: "service-doc", url: "<url>"}`) and log the MCP lookup. Do NOT
   free-browse general AWS docs to fabricate intent that none of the
   prior sources support.

The plan row records both the **intent source** (Canopy / catalog /
service-doc — what motivates the control) and the **anchor** (the reference
example whose body we adapt). For a Canopy-driven control authored against
a reference-repo body, the row carries the Canopy citation AND the
reference anchor; the authoring sub-skill consumes both.

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

### Keep enforcing keys aligned to the control's INTENT (required)

The analyzer returns *every* service condition key whose `applies_to_actions`
intersects the control's target action(s). That set can include keys unrelated
to what the control is actually about — e.g. a control whose intent is "cap the
execution role passed on `CreateFunction`" (`parameters_controlled: ["$.Role"]`)
will see the analyzer also surface `lambda:SubnetIds`, `lambda:SecurityGroupIds`,
`lambda:CodeSigningConfigArn` simply because they too apply to `CreateFunction`.
Authoring a policy around those drops the control's real intent — a
mapping↔generate drift where the generated policy gates a different thing than
the control objective describes.

So when the control declares its intent, **filter the enforcing keys to the ones
that match it** before recording them on the plan row:

1. If the control has non-empty `condition_keys[]` (the keys the mapping chose),
   intersect the analyzer's `enforcing_condition_keys[]` with those; use the
   intersection. If the mapping's declared key is not in the SAR snapshot but is
   doc-citable (e.g. `iam:PassedToService` for a PassRole control), keep it and
   record the citation.
2. Else, if the control has `parameters_controlled[]`, keep only the enforcing
   keys whose meaning matches that parameter (e.g. `$.Role` → an IAM
   role-passing key such as `iam:PassedToService` / a role-ARN-scoping key, NOT
   networking/code-signing keys).
3. If after filtering NO key remains that genuinely enforces the control's
   intent, the control is NOT preventable *as mapped* — set `ROUTE_DETECTIVE`
   (do not author a policy around an unrelated key just because it applies to
   the same action).

Record the chosen, intent-aligned keys in the plan row's
`enforcing_condition_keys[]`; the authoring sub-skill uses exactly those.

## Step 2 — Reference anchor per control

For each `FEASIBLE` control, find a matching reference example with the
deterministic ranker in the shared loader. It restricts to the control's
mechanism family and scores each example by overlap with the control's governed
actions and condition keys (condition-key overlap weighted 2x — a closer
structural match). Do NOT eyeball this; call the helper:

```bash
python3 - <<'PY'
import json, sys
sys.path.insert(0, "tools")
import reference_index as ri

# control_mechanism / actions / condition_keys come from the control + the
# preventability verdict's enforcing_condition_keys[].
best = ri.best_anchor(control_mechanism, control_actions, enforcing_condition_keys)
# best is None when the mechanism family has no example OR nothing overlaps
# (best score 0.0). None → REFER_TO_REFERENCE; do NOT claim an anchor.
ranked = ri.rank_anchors(control_mechanism, control_actions, enforcing_condition_keys)
# ranked[:3] gives the top candidates with scores for the rationale.
PY
```

`best_anchor` returning `None` is the risk-averse signal: a mechanism family with
no overlapping example means we cannot anchor → the control's `decision` is
`REFER_TO_REFERENCE`, NOT a `GENERATE_*`. `mechanism_family()` maps the control's
mapping mechanism to the index mechanism(s) to search (the table below).

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
      "source_control_id": "CTRL-ORG-PRV-001",
      "mechanism": "SCP",
      "preventable": true,
      "enforcing_condition_keys": ["lambda:CodeSigningConfigArn"],
      "decision": "GENERATE_SCP",
      "anchor": {
        "example_id": "service-control-policy-examples-deny-...",
        "repo": "service-control-policy-examples",
        "url": "https://github.com/aws-samples/.../blob/<sha>/<path>"
      },
      "citation": {
        "type": "canopy",
        "id": "<canopy-mitigation-alias>"
      },
      "route_to": null,
      "rationale": "condition key gates CreateFunction; SCP example covers the deny-on-create pattern"
    },
    {
      "control_id": "CTRL-ORG-PRV-007",
      "source_control_id": "CTRL-ORG-PRV-007",
      "mechanism": "SCP",
      "preventable": false,
      "decision": "ROUTE_DETECTIVE",
      "anchor": null,
      "citation": {
        "type": "service-doc",
        "url": "https://docs.aws.amazon.com/.../<page>.html"
      },
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

Every emitted decision MUST carry:

- `source_control_id` — the originating control id from
  `mapping-results.json` that this decision implements. Validators
  cross-check `source_control_id` against `mapping-results.json.controls[].id`;
  an orphan decision (no matching upstream control) hard-fails.
- `anchor` (for `GENERATE_*` decisions) — the resolved reference example
  (already enforced; see Step 2).
- `citation` — typed pointer to the intent source. `type` is one of
  `canopy` (cite the mitigation `alias` in `id`), `reference` (cite the
  reference-repo example in `id` and `url`), `catalog` (cite the AWS
  Control Catalog control ARN in `id`), or `service-doc` (cite the AWS
  doc URL in `url`). The `citation` field is REQUIRED on every
  decision row, regardless of decision type.

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
