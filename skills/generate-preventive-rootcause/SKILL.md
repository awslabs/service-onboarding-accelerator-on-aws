---
name: generate-preventive-rootcause
description: Final critic for preventive generation — proves every authored preventive artifact is both reference-anchored and actually enforces the root cause of its control (a real condition key gates the target action). Runs last in the preventive sub-pipeline. Routes non-enforcing objectives to detective. Reads preventive-plan.json, the preventive artifacts, validated.json, and the reference index.
disable-model-invocation: false
argument-hint: '[--service=<name>]'
---

# Service Approval — Preventive: Root-Cause Critic (runs last)

After the authoring sub-skills write preventive artifacts, this critic proves two
properties for the whole `preventive/` directory before the phase is allowed to
complete:

1. **Anchored** — every emitted policy traces to a real reference example.
2. **Enforcing** — every emitted policy gates the root cause of its control: a
   real condition key limits the target action. A syntactically-valid SCP that
   denies an action no condition key can gate is a no-op; it must not ship as a
   preventive control — its objective routes to detective instead.

**Input:**
- `.service-approval/<slug>/05-recommended-guidance/preventive/` — the authored artifacts
- `.service-approval/<slug>/05-recommended-guidance/preventive-plan.json` — the recommender plan
- `.service-approval/<slug>/03-validate/validated.json`, `04-map/mapping-results.json`

**Output:** `.service-approval/<slug>/05-recommended-guidance/preventive/rootcause-report.json`
(a report, exempt from the anchor gate as a documentation file — its basename is
in `validate_reference_anchor._DOC_ONLY_BASENAMES`) and, when a not-preventable
objective slipped through, a routing note for the detective generator.

---

## Step 1 — Reference-anchor proof (hard)

```bash
python3 tools/validate/validate_reference_anchor.py --slug <slug>
```

Exit 0 → every preventive artifact is anchored (or an exempt gap/doc stub).
Exit 2 → an un-anchored policy exists. STOP: either anchor it to a reference, or
delete it and route the objective to detective/proactive. Do not complete the
phase with an un-anchored preventive artifact — the Stop hook (P8) would fail the
run anyway.

## Step 2 — Preventability (root-cause) proof

```bash
python3 tools/validate/validate_preventability.py --slug <slug> --json > /tmp/rootcause.json
```

For every control that produced a preventive artifact, confirm its verdict is
`FEASIBLE` and the artifact's `Condition` blocks actually use one of the
`enforcing_condition_keys[]`. A control whose verdict is `NOT_PREVENTABLE` must
NOT have a preventive policy artifact — if one exists, that is the exact failure
mode this critic catches:

### Step 2a — Per-statement enforcement check (deterministic, required)

The preventability verdict is a mapping-time judgement. Prove the SAME property
on the policy text that was actually authored — statement by statement — with the
enforcement analyzer:

```bash
python3 tools/validate/validate_enforcement.py --slug <slug> --json > /tmp/enforcement.json
```

For every Deny statement in every authored artifact it resolves
`{sid, action, resource_arn, enforcing_key, evaluable, reason}` and proves three
things a name-overlap check misses:

1. **Key-context evaluability.** The enforcing key must be evaluable in *this
   policy type*. A request-time-only key — one bound solely to a policy-management
   action (e.g. `lambda:Principal` → AddPermission/RemovePermission) — placed
   inside a **resource-based policy** never fires: the attached document is not in
   the evaluation path for that request. (The same key in an SCP/identity policy
   IS evaluable.) `evaluable:false`.
2. **Resolved Resource ARN.** The ARN must use the delimiter the service's SAR
   format mandates for that resource type (`function:` not `function/`); a
   mismatched delimiter matches nothing and the deny is a no-op. `evaluable:false`.
3. **Action applicability.** The enforcing key must apply to at least one gated
   action; gating `DeleteFunction` on a key that only applies to `CreateFunction`
   denies a different operation than the key controls. `evaluable:false`.

Any statement with `evaluable:false` is a non-enforcing artifact: **remove it and
route the objective to detective (Step 2b).** Copy the analyzer's per-statement
records into the report's `enforcement[]` (Step 4) so the resolved ARN and key
context are visible at generation time, not only at the Stop gate. (Global keys
such as `aws:PrincipalOrgID` are principal-context — a Deny that gates only on
them, e.g. a VPCE org-perimeter deny, is legitimate and is not flagged here.)

**Also prove the artifact enforces the control's INTENT, not just *some* gate.**
A policy can use a real condition key that gates the target action yet still miss
what the control is about (e.g. a boundary whose control intent is "cap the
execution role passed on create" but that gates `lambda:SubnetIds` instead, or an
unconditional allowlist with no enforcing key at all). For each artifact, check:

- The artifact's `Condition` keys overlap the control's declared
  `condition_keys[]` / the parameter named in `parameters_controlled[]`
  (`$.Role` → an IAM role-passing/role-ARN key; `$.KmsKeyArn` → a KMS key;
  networking params → subnet/SG keys). A mismatch is an **intent-drift FAIL** —
  the artifact gates the wrong thing.
- A preventive artifact that carries NO `Condition` at all (e.g. a permission
  boundary that is just an Allow allowlist) does not enforce its control — FAIL.

On an intent-drift or no-condition FAIL: remove the artifact, route the
objective to detective (Step 2b), and record it in the report under a new
`intent_mismatch[]` list with the control id, the expected intent
(parameter/key), and what the artifact actually gated.

- Remove the non-enforcing artifact.
- Record the objective in `rootcause-report.json` with `route_to: "detective"`.
- **Write the machine-readable hand-off** so the detective generator actually
  covers it (see Step 2b).

The SAR condition-key list is a **lower bound**: if an artifact relies on a
condition key absent from the SAR snapshot, require a doc citation (logged to
`mcp-calls.log`) — otherwise treat it as not-enforcing.

### Step 2c — Reject unreviewed authored deny actions (deterministic, required)

Every action a Deny authorizes over must have been reviewed. Run:

```bash
python3 tools/validate/validate_action_scope.py --slug <slug>
```

It compares each authored Deny statement's actions against the control's
**reviewed action set** — the plan decision's `plan_actions[]` (the actions the
recommender deliberately intends to gate), falling back to the originating
mapping control's `actions[]`. An action that appears in a statement but not in
that set is **unreviewed scope-creep**: it may be SAR-bound to the enforcing key
(so it is not unsound), but it expands the deny beyond what the mapping
described. For each flagged action, either confirm the intent and record it in
the plan row's `plan_actions[]`, or remove it from the statement. Do not ship a
Deny that authorizes over an unreviewed action.

## Step 2b — Write the detective-routing hand-off

For every objective routed to detective, write a machine-readable contract the
detective generator consumes. Without this, routing is a dead-end report and the
objective gets no coverage.

Write `.service-approval/<slug>/05-recommended-guidance/detective-routing.json`
(schema: `schemas/detective-routing.schema.json`):

```json
{
  "_metadata": {"service": "<service>", "generated": "service-approval v3.0.0"},
  "routed": [
    {
      "control_id": "CTRL-ORG-PRV-007",
      "objective_ids": ["IAM-13"],
      "reason": "no condition key gates DeleteFunction; not preventable at request time",
      "covered_by": null
    }
  ]
}
```

`covered_by` is `null` here — the detective generator fills it in with the
detective artifact filename(s) it produces. Leave it null; do not guess. If no
objectives were routed, do NOT write the file (its absence means "nothing routed").

## Step 3 — Cross-check the plan

Every `GENERATE_*` row in `preventive-plan.json` should have a corresponding
artifact; every `ROUTE_DETECTIVE` / `REFER_TO_REFERENCE` row should have **no**
preventive artifact. Flag mismatches in the report.

These deferred decisions are not coverage gaps: the cross-artifact check
(`validate_cross.py` CHECK-X2) reads `preventive-plan.json` and treats a control
with a recorded `REFER_TO_REFERENCE` / `ROUTE_DETECTIVE` decision as covered, so
a deliberately un-authored control is not reported as an orphan. A control with
a `GENERATE_*` decision but no artifact IS still flagged — that is a real
generation gap, not a deferral, so do not leave a `GENERATE_*` row unauthored.

## Step 4 — Report

```json
{
  "_metadata": {"service": "<service>", "generated": "service-approval v3.0.0"},
  "anchored": true,
  "enforcing": true,
  "artifacts_checked": 4,
  "enforcement": [
    {"sid": "DenyPublicFunctionUrlCtrlOrgPrv003", "action": ["lambda:CreateFunctionUrlConfig"],
     "resource_arn": ["arn:aws:lambda:*:*:function:*"],
     "enforcing_key": ["lambda:FunctionUrlAuthType"], "evaluable": true, "reason": ""}
  ],
  "routed_to_detective": [
    {"control_id": "CTRL-ORG-PRV-007", "reason": "no gating condition key for DeleteFunction"}
  ],
  "intent_mismatch": [
    {"control_id": "CTRL-ACC-PRV-001", "expected": "$.Role / iam:PassedToService",
     "artifact_gated": "lambda:SubnetIds", "action": "removed; routed to detective"}
  ],
  "unmatched_plan_rows": []
}
```

The `enforcement[]` array is the per-statement output of `validate_enforcement.py`
(one record per Deny statement, across all authored artifacts). Any record with
`evaluable:false` MUST correspond to a removed artifact and a detective routing —
`enforcing` cannot be `true` while an `evaluable:false` record remains.

## Print summary

```
Preventive root-cause critic complete — <service>:
  Anchored:   PASS/FAIL (N artifacts)
  Enforcing:  PASS/FAIL (N artifacts; M routed to detective)
  Plan match: PASS/FAIL
```

If anchored or enforcing is FAIL, the preventive phase is NOT complete — fix the
flagged artifacts (re-anchor, add the gating condition key, or remove and route
to detective) and re-run this critic.
