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
- `.service-approval/<slug>/05-generate/preventive/` — the authored artifacts
- `.service-approval/<slug>/05-generate/preventive-plan.json` — the recommender plan
- `.service-approval/<slug>/03-validate/validated.json`, `04-map/mapping-results.json`

**Output:** `.service-approval/<slug>/05-generate/preventive/rootcause-report.json`
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

- Remove the non-enforcing artifact.
- Record the objective in `rootcause-report.json` with `route_to: "detective"`.
- **Write the machine-readable hand-off** so the detective generator actually
  covers it (see Step 2b).

The SAR condition-key list is a **lower bound**: if an artifact relies on a
condition key absent from the SAR snapshot, require a doc citation (logged to
`mcp-calls.log`) — otherwise treat it as not-enforcing.

## Step 2b — Write the detective-routing hand-off

For every objective routed to detective, write a machine-readable contract the
detective generator consumes. Without this, routing is a dead-end report and the
objective gets no coverage.

Write `.service-approval/<slug>/05-generate/detective-routing.json`
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
  "routed_to_detective": [
    {"control_id": "CTRL-ORG-PRV-007", "reason": "no gating condition key for DeleteFunction"}
  ],
  "unmatched_plan_rows": []
}
```

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
