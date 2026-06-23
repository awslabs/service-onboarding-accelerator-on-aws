---
name: generate-preventive-rcp
description: Author Resource Control Policies (RCPs) for preventive control objectives, adapted from a matching reference example. Generates only for controls the recommender marked GENERATE_RCP with a resolved reference anchor and an RCP-expressible service; never free-synthesizes. Reads preventive-plan.json, mapping-results.json, validated.json, and the reference index.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Preventive: RCP Author (reference-anchored)

Author RCP artifacts for control objectives the recommender approved, adapting a
known-good reference RCP to the target service. Does not invent policy.

**Input:**
- `.service-approval/<slug>/05-generate/preventive-plan.json` — rows where `decision == "GENERATE_RCP"`
- `.service-approval/<slug>/04-map/mapping-results.json`, `03-validate/validated.json`
- `data/reference-repos/index.yaml` (mechanism `RCP`; the data-perimeter repo's RCP examples are facts-only)

**Output:** `.service-approval/<slug>/05-generate/preventive/rcp-policy*.json`

---

## Gate

```bash
python3 - <<'PY'
import json
plan = json.load(open(".service-approval/<slug>/05-generate/preventive-plan.json"))
v = json.load(open(".service-approval/<slug>/03-validate/validated.json"))
rows = [d for d in plan["decisions"] if d["decision"] == "GENERATE_RCP"]
assert v.get("rcp_expressible", False) or not rows, \
    "GENERATE_RCP rows but rcp_expressible is false — recommender bug."
assert all(r.get("anchor", {}).get("example_id") for r in rows), "un-anchored GENERATE_RCP row"
print(f"{len(rows)} RCP controls to author")
PY
```

No `GENERATE_RCP` rows → write nothing. If a control was mapped to RCP but the
service is not RCP-expressible, the recommender will have routed it elsewhere; if
you must record the gap, write `_metadata.rcp_gap` with an empty `Statement[]`
(gap stubs are exempt from the anchor gate) and full framework/mitigation
metadata.

## Authoring procedure

Same as `generate-preventive-scp` (load anchor body → adapt actions/keys →
apply shared authoring rules → stamp `_metadata.reference`), with the
RCP-specific requirements:

- Always `"Effect": "Deny"` and `"Principal": "*"`.
- Include `"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}` where the
  reference pattern uses it.
- Org scoping via `"StringNotEquals": {"aws:PrincipalOrgID": "<org-id>"}` —
  use a literal placeholder with an `_metadata._deployment_notes` substitution
  note, never a shell-style `${ORG_ID}` token inside policy content.

## Required metadata

Identical shape to `generate-preventive-scp` with `scope`/`layer` appropriate to
the control and `posture: "preventative-request"`. `_metadata.reference.example_id`
MUST equal the plan row's `anchor.example_id` and resolve in the index.

## Shared authoring rules

Follow `skills/generate-preventive/SKILL.md` "Resource × Preventive → RCP" and
"Rule C2". Validators CHECK-14a (condition keys) and CHECK-17 (action sourcing)
enforce the hard rules at hook time. Every target-service action must come from
`validated.json`; never synthesize.

## Print summary

```
Preventive RCP author complete — <service>:
  Authored: rcp-policy.json (controls: ...) anchored to <example_id>
  (or: no GENERATE_RCP controls in plan)
```
