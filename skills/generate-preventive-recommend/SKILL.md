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
- (optional) `.service-approval/<slug>/02-research/canopy-index.json` — when a
  Canopy threat-model was provided, its normalized `mitigations[]` +
  `implementations[]` carry the control intent, the preventive policy shape
  (governed actions + condition keys), and the public REFERENCE doc URL; this is
  the first-priority citation source. See "Sourcing order" below.

**Output:** `.service-approval/<slug>/05-recommended-guidance/preventive-plan.json` — the per-control
decision plan consumed by `generate-preventive-scp`, `-rcp`, and `-iam`.
**Schema:** `schemas/preventive-plan.schema.json` — enforces the decision enum, the
`CTRL-<SCOPE>-<CAT>-NNN` id pattern, and the rules that every `GENERATE_*` decision
carries a non-null `anchor.example_id` and every `ROUTE_DETECTIVE` carries a `route_to`.
Validated at write time by `validate_controls.py`.

> This output lives in the `05-recommended-guidance/` root, NOT in `preventive/`, so it is a
> plan, not a policy artifact (the reference-anchor gate scans `preventive/*.json`).

---

## Prerequisites

```bash
test -f .service-approval/<slug>/04-map/mapping-results.json && echo "mapping: OK" || echo "ERROR"
test -f .service-approval/<slug>/03-validate/validated.json && echo "validated: OK" || echo "ERROR"
test -f data/reference-repos/index.yaml && echo "ref-index: OK" || echo "ERROR — build it: python3 tools/post-process/build_reference_index.py --repos-dir <clones>"
mkdir -p .service-approval/<slug>/05-recommended-guidance
```

---

## Sourcing order (Canopy first)

When deciding the enforcement mechanism and anchor for each preventive control,
walk the source list in this order — stop at the first source that yields a
usable answer, fall through only when nothing applies:

1. **Canopy implementation (highest priority).** When a Canopy threat-model was
   provided for this service, `.service-approval/<slug>/02-research/canopy-index.json`
   holds its normalized `mitigations[]` and `implementations[]`. If it has an
   implementation whose `behavior == "PREVENTIVE"` and whose `mechanism` +
   governed `actions[]` / `condition_keys[]` match the control, use it as the
   anchor. Canopy carries the preventive policy SHAPE: the implementation's
   `authorization_policy` gives the exact `actions`, `resources`, and
   `condition_keys` to author, and its REFERENCE context links to a public AWS
   documentation URL. Record:
   - `anchor: {source: "canopy", example_id: "<implementation.alias>"}` — the
     Canopy implementation resolves the anchor requirement.
   - `citation: {type: "canopy", id: "<implementation.alias>", url: "<REFERENCE
     href if present>", verified_via: "mcp"}` — cite the implementation `alias`
     and link straight to the public doc it is grounded in.

   This **replaces** the old "a Canopy-anchored preventive control must still
   resolve a reference-repo body" rule — Canopy now supplies both the intent AND
   the policy shape plus a cited public doc URL, so **a Canopy implementation is a
   complete anchor** for a `GENERATE_*` decision. When the implementation carries
   no REFERENCE `href` of its own, fall back to the linked mitigation's cited
   link (`canopy-index.json` `mitigations[].reference_links`).
2. **Reference-repo index** (`data/reference-repos/index.yaml`) — fallback when
   no Canopy implementation matches. The deterministic ranker
   (`tools/reference_index.py`) scores published AWS sample policies by
   mechanism + action + condition-key overlap. This produces the policy BODY
   anchor (`citation: {type: "reference", id: "<example_id>", url:
   "<source_url>"}`).
3. **AWS Control Catalog API** — for objectives the AWS Control Catalog
   covers, cite the catalog control ARN directly (`citation: {type:
   "catalog", id: "<arn>"}`). Use only when neither a Canopy implementation nor a
   reference-repo example matches and the catalog has an explicit control.
4. **Service-specific AWS documentation** — last resort, only when the
   prior three sources have nothing. Cite the exact doc URL (`citation:
   {type: "service-doc", url: "<url>"}`) and log the MCP lookup. Do NOT
   free-browse general AWS docs to fabricate intent that none of the
   prior sources support.

The plan row records both the **intent source** (Canopy / catalog /
service-doc — what motivates the control) and the **anchor** (the example whose
body we adapt). When the anchor is Canopy-derived, set `anchor.source: "canopy"`
and the `example_id` to the Canopy implementation `alias`; when it is a
reference-repo body, set the repo `example_id` (and, if a Canopy mitigation also
motivated the control, carry the Canopy `citation` alongside the reference
anchor — the authoring sub-skill consumes both).

**Every Canopy REFERENCE `href` surfaced as a citation `url` MUST be MCP-verified
reachable at generation time** (fetch it via the `aws-documentation` /
`awsknowledge` MCP and log the call to `pipeline.log`), and the citation MUST
carry `verified_via: "mcp"` — the same discipline the `service-doc` / `aws_doc`
anchors follow. The citation validator hard-fails a Canopy citation whose alias
does not resolve in `canopy-index.json` or whose `url` is not a well-formed,
MCP-verified AWS doc URL.

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

## Step 2 — Anchor per control (Canopy first, then reference-repo)

For each `FEASIBLE` control, first check `canopy-index.json` (Sourcing order
step 1): if a `behavior == "PREVENTIVE"` implementation matches the control's
mechanism and governed actions/condition keys, that implementation IS the anchor
(`anchor.source: "canopy"`, `example_id: "<alias>"`) — skip the reference-repo
ranker for that control. Only when no Canopy implementation matches do you run
the reference-repo ranker below.

For a control with no Canopy match, find a matching reference example with the
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
| `IAM Policy`, `IAM Permission Boundary`, `Resource Policy`, `Resource-Based Policy`, `KMS Key Policy`, `VPCE Policy` | `IAM`, `permission-boundary`, `data-perimeter`, `VPCE` | `generate-preventive-iam` |
| `IAM Trust Policy` | *(none — refer-only)* | *(not authored — see below)* |

If **no** example matches the mechanism (or no example overlaps the control's
actions/keys), the control gets `decision: "REFER_TO_REFERENCE"` — we do not
author. Surface the closest reference family so the customer knows where to look.

### Trust policies are refer-only (required)

A role's trust policy (the `AssumeRolePolicyDocument`) is **never authored** by
this pipeline. There is no vetted trust-policy example library to anchor to, and
the cross-service confused-deputy prevention a trust policy implements (the
`aws:SourceArn` / `aws:SourceAccount` condition pattern on the `sts:AssumeRole`
principal) is documented per-service. `mechanism_family("IAM Trust Policy")`
returns an empty family, so `best_anchor` never resolves an anchor for it.

- A control whose `mechanism` is **`IAM Trust Policy`** always gets
  `decision: "REFER_TO_REFERENCE"` with a `citation` of `type: "service-doc"`
  pointing at the service's documented cross-service confused-deputy prevention
  page. Do **not** stamp it with a repo `anchor` — claiming an identity-policy
  example as a trust-policy anchor is an incoherent shape.
- The reference-anchor validator code-guards this: a trust-policy artifact that
  carries a repo anchor, or that ships an enforcing `Statement[]` body, fails the
  generation review gate. The IAM authoring sub-skill emits a REFER pointer
  (no body, `not_anchored: true`, the service-doc reason), not a policy.

### Permission boundaries are refer-by-default (required)

A permission boundary only takes effect if the org actually attaches one to its
delegated-admin / role principals; authoring a boundary for an org that does not
attach boundaries is shelfware. So a control whose mechanism is an **IAM
Permission Boundary** defaults to `REFER_TO_REFERENCE` (pointing at the
`example-permissions-boundary` scaffold) — do NOT author it unless the run
explicitly opts in:

```
org_context.permission_boundaries_attached == true   (in intake-manifest.json)
```

- **Opt-in absent or false (the common case):** set the boundary control's
  `decision` to `REFER_TO_REFERENCE`, anchor to the reference boundary example,
  and note that the customer attaches it themselves. This removes the boundary
  authoring surface entirely in the default case.
- **Opt-in `true`:** the boundary may be `GENERATE_IAM` (subject to the usual
  anchor + enforcing-key gates); the authored boundary must be minimal (no
  enumerated management actions — integrity check P10) and carry the control's
  enforcing condition keys in its Deny.

The cross-artifact validator (X4 in `validate_cross.py`) enforces this: a
`GENERATE_IAM` boundary decision without the recorded opt-in fails the gate.
Prefer an SCP/RCP path over a boundary where the control objective allows it.

## Step 3 — Emit the plan

Write `.service-approval/<slug>/05-recommended-guidance/preventive-plan.json`:

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
      "rationale": "condition key gates CreateFunction; SCP example covers the deny-on-create pattern",
      "application_guidance": {
        "placement": "Attach to the workload OU SCP at the Organizations root or target OU",
        "placeholders": ["<ORG_ID>", "<WORKLOAD_OU_ID>", "the function ARN pattern in Resource"],
        "test": "aws iam simulate-custom-policy / deploy to a sandbox account and confirm a non-compliant create is denied",
        "rollback": "Detach the SCP from the OU; no resource state changes are made by the policy"
      },
      "applicability": {
        "applies_to": "Lambda functions matching the [INFRASTRUCTURE_AUTOMATION_PREFIX] ARN pattern in the Resource element — the functions your infrastructure-automation pipeline creates and manages",
        "usage_notes": "Scope the Resource ARN pattern to only the automation-managed functions. Do NOT apply it across all functions: application teams that legitimately self-manage lambda:AddPermission / RemovePermission / UpdateFunctionCode on their own functions would be blocked. The excepted privileged automation role stays able to modify the targeted functions."
      }
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
- `plan_actions[]` (for `GENERATE_*` decisions) — the **reviewed action set**:
  the exact IAM actions you intend the authored policy's Deny(s) to gate for this
  control. This is the closed set the root-cause critic checks the authored
  statements against (Step 2c of the critic): an action present in a statement
  but absent here is unreviewed scope-creep. Keep it to the actions the control's
  intent actually targets — do NOT widen it to every action the enforcing key
  happens to apply to. If the mapping control's `actions[]` already names exactly
  the reviewed set, you may omit `plan_actions[]` (the critic falls back to it);
  record it explicitly whenever the reviewed set is narrower than, or differs
  from, the mapping's `actions[]` (e.g. a PassRole control whose mapping
  `actions[]` lists only the Lambda create/update operations must record
  `plan_actions: ["iam:PassRole"]`).
- `application_guidance` (for `GENERATE_*` AND `REFER_TO_REFERENCE` decisions) —
  a concrete **"what to do with this policy"** block so the customer is not left
  with a bare citation URL. It carries:
  - `placement` — where the policy goes (e.g. "attach to the workload OU SCP",
    "set as the function's resource-based policy", "attach as a permission
    boundary to the execution role").
  - `placeholders[]` — the **specific tokens the customer must edit**: account
    ids, `<ORG_ID>`, OU ids, role ARNs, function ARNs, KMS key ARNs. Draw these
    from the control's real parameter/condition names (the mapping control's
    `parameters_controlled[]` / `enforcing_condition_keys[]` and `validated.json`
    operation parameters) — do NOT invent generic names.
  - `test` — how to verify it before relying on it (e.g.
    `aws iam simulate-principal-policy`, or deploy to a sandbox account and
    confirm a non-compliant action is denied).
  - `rollback` — how to undo it (detach the SCP/boundary, remove the resource
    policy statement; note whether any resource state is changed).

  For an **authored** control, the guidance points at the generated artifact file
  and the exact placeholders inside it. For a **referred** control, the guidance
  summarizes how to copy the referenced example and what to change for this
  service/account — not just the URL. `ROUTE_DETECTIVE` rows need no guidance
  (they produce no preventive policy to apply). `build_preventive_coverage.py`
  carries this block into `preventive-coverage.json`, and `summarize` renders it
  in the Summary Report preventive section.
- `applicability` (**when the decision surfaces a citation URL to the customer** —
  `anchor.url` for `GENERATE_*` reference-anchored controls, or `citation.url` for
  a `reference` / `service-doc` citation) — a two-field object that tells the
  customer **what the cited policy targets and how to use it, including where NOT
  to apply it**. It renders in the Summary Report **immediately after the cited
  policy URL** and is stamped into the authored artifact's `_metadata.applicability`.
  - `applies_to` — the **specific resource subset/type the policy targets and the
    pattern that selects it**. Draw it from the control's real parameters /
    condition keys and the reference example's placeholders (e.g. the ARN pattern
    in the `Resource` element that scopes the deny), not generic prose. It is
    service-agnostic: for one service it names which functions; for another, that
    service's resource subset.
  - `usage_notes` — how the customer is meant to use the policy, and it MUST state
    the **caution about where NOT to apply it** — the case where over-applying the
    policy would block a team that legitimately performs the gated actions on its
    own resources. This is the sentence that keeps a customer from over-scoping.

  Author `applicability` from the same real parameters you use for
  `application_guidance.placeholders[]` and the reference example's placeholders —
  never templated generic text. A Canopy citation now usually carries a REFERENCE
  `url`, so **`applicability` is required whenever the Canopy citation surfaces a
  URL** (same rule as a `reference` / `service-doc` citation). **Omit it only for
  a Canopy citation that truly has no link** (an `id` and no `url`, and no
  `anchor.url`) — there is no external link to clarify — and for `ROUTE_DETECTIVE`
  rows (they surface no preventive policy). When a decision surfaces a URL,
  `applicability` is required with non-empty `applies_to` + `usage_notes` — the
  schema and the reference-anchor validator both enforce it.

## Step 4 — Hand-off summary

```
Preventive recommender complete — <service>:
  GENERATE_SCP:        N controls (anchored)
  GENERATE_RCP:        N controls (anchored)
  GENERATE_IAM:        N controls (anchored)
  REFER_TO_REFERENCE:  N controls (no anchor — see reference)
  ROUTE_DETECTIVE:     N controls (not preventable)
  Plan: .service-approval/<slug>/05-recommended-guidance/preventive-plan.json
```

The authoring sub-skills read ONLY rows whose `decision` is `GENERATE_*` and
whose `anchor` is non-null. A `GENERATE_*` row with a null anchor is a bug in
this skill — fix the anchor lookup, do not let authoring proceed un-anchored
(the reference-anchor gate would hard-fail it anyway).
