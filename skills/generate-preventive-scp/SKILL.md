---
name: generate-preventive-scp
description: Author Service Control Policies (SCPs) for preventive control objectives, adapted from a matching reference example. Generates only for controls the recommender marked GENERATE_SCP with a resolved reference anchor; never free-synthesizes. Reads preventive-plan.json, mapping-results.json, validated.json, and the reference index.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Preventive: SCP Author (reference-anchored)

Author SCP artifacts for control objectives the recommender approved. This skill
**adapts a known-good reference SCP** to the target service's actions and
condition keys — it does not invent policy from scratch.

**Input:**
- `.service-approval/<slug>/05-generate/preventive-plan.json` — read rows where `decision == "GENERATE_SCP"`
- `.service-approval/<slug>/04-map/mapping-results.json` — the controls
- `.service-approval/<slug>/03-validate/validated.json` — actions + condition keys
- `data/reference-repos/index.yaml` + vendored bodies under `data/reference-repos/<repo>/examples/`

**Output:** `.service-approval/<slug>/05-generate/preventive/scp-policy.json`
(a SINGLE consolidated file — see "One consolidated file" below)

---

## Gate — only author what the recommender approved

```bash
python3 - <<'PY'
import json
plan = json.load(open(".service-approval/<slug>/05-generate/preventive-plan.json"))
scp_rows = [d for d in plan["decisions"] if d["decision"] == "GENERATE_SCP"]
assert all(r.get("anchor", {}).get("example_id") for r in scp_rows), \
    "GENERATE_SCP row with no anchor — recommender bug; do not author un-anchored."
print(f"{len(scp_rows)} SCP controls to author")
PY
```

If there are no `GENERATE_SCP` rows, write nothing and report "no SCP controls."
Do NOT emit a placeholder.

## One consolidated file (REQUIRED)

Author **exactly one** `scp-policy.json` containing the Statements for ALL
`GENERATE_SCP` controls — never one file per control. A reviewer asked "why is
this two files?"; per-control SCP files are noise. Collect every approved
control's Deny statement(s) into the single file's `Statement[]` array, list
every control id in `_metadata.controls[]`, and record each control's anchor in
`_metadata._anchors` (a `{control_id: example_id}` map). `_metadata.reference`
holds the primary anchor (the example most controls drew from); `_anchors` keeps
the rest traceable. Give each Statement a `Sid` suffixed with its control id
(e.g. `DenyLambdaWithoutPrivateSubnet`) so statements stay attributable.

If two controls would emit byte-identical statements, keep one and list both
control ids against it — do not duplicate.

**Only exception — the SCP size limit.** A single attached SCP has a hard
character limit (CHECK-12 fails a minified body over 5120 bytes). If, and only
if, consolidating every statement into one file would exceed that limit, split
into the fewest files that fit, named `scp-policy.json`, `scp-policy-2.json`,
… (numeric suffix, not per-control). Each split file carries its own
`_metadata` (controls/`_anchors` for the statements it holds). Do NOT split for
any other reason — one statement per file is wrong.

## Authoring procedure (per approved control)

1. **Load the anchor body.** Read the example from the index entry's
   `source_path` (vendored JSON). For facts-only entries (share-alike license,
   `source_path: null`), fetch the structure from the `source_url` via the doc
   MCP and log the call — do not reproduce share-alike text verbatim into the
   artifact; re-express the pattern using the target service's own actions/keys.
2. **Adapt to the target service.** Replace the example's actions with the
   control's target actions (sourced from `validated.json`, see Action rule
   below) and its condition keys with the recommender's
   `enforcing_condition_keys[]`.
3. **Apply the SCP authoring rules** (shared with the other preventive authors —
   see "Shared authoring rules" below).
4. **Stamp the reference anchor** into `_metadata.reference` (REQUIRED — the
   reference-anchor gate hard-fails an un-anchored preventive artifact).

## Required artifact metadata

```json
{
  "_metadata": {
    "scope": "org",
    "layer": "preventive",
    "posture": "preventative-request",
    "controls": ["CTRL-ORG-PRV-001", "CTRL-ORG-PRV-002"],
    "framework": "<copy VERBATIM from mapping-results.json.framework_header_canonical>",
    "mitigations": ["M-..."],
    "generated": "service-approval v3.0.0",
    "service": "<service-name>",
    "reference": {
      "example_id": "service-control-policy-examples-deny-...",
      "repo": "service-control-policy-examples",
      "url": "https://github.com/aws-samples/.../blob/<sha>/<path>"
    },
    "_anchors": {
      "CTRL-ORG-PRV-001": "service-control-policy-examples-deny-...",
      "CTRL-ORG-PRV-002": "data-perimeter-policy-examples-..."
    },
    "_simulation_tests": {
      "should_deny": [{"action": "<prefix>:CreateX", "context": {}}],
      "should_allow": [{"action": "<prefix>:CreateX", "context": {"<key>": "<compliant-value>"}}]
    }
  },
  "Version": "2012-10-17",
  "Statement": [ ... ]
}
```

The `reference.example_id` MUST equal the plan row's `anchor.example_id` and
MUST resolve in `data/reference-repos/index.yaml`. Mark the policy as an example
to be verified against the service authorization guide before deployment.

## Shared authoring rules

The SCP/RCP/IAM authoring rules — strict Deny semantics, mandatory condition
keys, BreakGlass exclusion, AND-logic awareness, ARN/region placeholder rules,
no non-standard Statement fields, minified-size limits, the service-principal
vs confused-deputy split, and the **IAM action-name sourcing rule** — are
documented once in `skills/generate-preventive/SKILL.md` under
"Organisation × Preventive" and "Rule C2". Follow those rules verbatim. They are
enforced by validators CHECK-12 (size), CHECK-14a (condition keys), and CHECK-17
(action sourcing) at hook time.

**Action rule (restated — hard):** IAM Action strings are NOT API operation
names. Every target-service `Action`/`NotAction` string MUST be a real action
in the AWS Service Authorization Reference for the target service, sourced
from the SAR IAM action list (resolving operation→action drift via
`data/botocore-iam-alias.json` — e.g. boto3 `StopQueryExecution` ↔ SAR
`athena:CancelQueryExecution`) or from
`capabilities.iam.permission_only_actions[]`. Never template an Action
string from an operation name. CHECK-17 fails the hook on a synthesized
action. Service-specific condition keys absent from the SAR snapshot may
still be valid — the SAR is a lower bound; cite the service authorization
doc when relying on a non-SAR key.

## Print summary

```
Preventive SCP author complete — <service>:
  Authored: scp-policy.json (1 file, N controls: ...) each anchored (see _anchors)
  (or: no GENERATE_SCP controls in plan)
```
