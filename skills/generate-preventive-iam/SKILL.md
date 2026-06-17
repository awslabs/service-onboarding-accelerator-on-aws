---
name: generate-preventive-iam
description: The single IAM authority for preventive controls — authors IAM identity policies, trust policies, permission boundaries, resource-based policies, VPCE policies, and KMS key policies, each adapted from a matching reference example. Generates only for controls the recommender marked GENERATE_IAM with a resolved reference anchor; never free-synthesizes. Reads preventive-plan.json, mapping-results.json, validated.json, and the reference index.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Preventive: IAM Author (single IAM authority)

All IAM reasoning for preventive controls routes through this one sub-skill, so
IAM logic is not scattered. It decides how to express each approved IAM-family
control and authors it from a reference example. Covers these mechanisms:

| Mechanism (mapping) | Output file | Anchor family |
|---|---|---|
| `IAM Policy` / `IAM Trust Policy` | `preventive/iam-policies.json` | `IAM`, `permission-boundary` |
| `IAM Permission Boundary` | `preventive/permission-boundary.json` | `permission-boundary`, `IAM` |
| `Resource Policy` / `Resource-Based Policy` | `preventive/resource-policy.json` | `IAM`, `data-perimeter` |
| `VPCE Policy` | `preventive/vpce-policy.json` | `VPCE`, `data-perimeter` |
| `KMS Key Policy` | `preventive/kms-key-policy.json` | `IAM` |

**Input:**
- `.service-approval/<slug>/05-generate/preventive-plan.json` — rows where `decision == "GENERATE_IAM"`
- `.service-approval/<slug>/04-map/mapping-results.json`, `03-validate/validated.json`
- `data/reference-repos/index.yaml` (anchored to `iam-policy-autopilot`,
  `example-permissions-boundary`, `iam-access-analyzer-custom-policy-check-samples`,
  `data-perimeter-policy-examples`)

**Output:** the per-mechanism files above under
`.service-approval/<slug>/05-generate/preventive/`.

---

## Gate

```bash
python3 - <<'PY'
import json
plan = json.load(open(".service-approval/<slug>/05-generate/preventive-plan.json"))
rows = [d for d in plan["decisions"] if d["decision"] == "GENERATE_IAM"]
assert all(r.get("anchor", {}).get("example_id") for r in rows), "un-anchored GENERATE_IAM row"
print(f"{len(rows)} IAM-family controls to author")
PY
```

For each row, dispatch to the matching output file by the control's `mechanism`.
A mechanism with no approved row → do not emit that file (no placeholder, no
invented control ID). Generate ONLY files whose mechanism appears in the plan.

## Authoring procedure (per approved control)

1. Load the anchor body (vendored JSON, or facts-only re-expressed from
   `source_url` for share-alike entries — log the MCP lookup).
2. Adapt to the target service: actions from `validated.json` (action rule
   below), condition keys from the recommender's `enforcing_condition_keys[]`.
3. Apply the IAM-family authoring rules from
   `skills/generate-preventive/SKILL.md` ("Account × Preventive",
   "Resource × Preventive", "Rule C2"):
   - Trust policies: confused-deputy `Condition` (`aws:SourceAccount`/`aws:SourceArn`).
   - IAM policies: scope to specific resource ARN patterns, not `*`.
   - Permission boundaries: NEVER emit an unconditional `Allow <prefix>:* on
     Resource "*"` baseline — that is an exfiltration path the integrity check
     (P3) hard-blocks, and it defeats the purpose of a boundary (which exists to
     *constrain*). Scope the Allow to specific actions on the resource ARN
     pattern (`arn:aws:<prefix>:*:*:<type>/*`); put only the genuinely
     wildcard-only actions (those whose SAR `resource_types` is empty — e.g.
     `List*`, account-level `Get*`) in a separate `Resource: "*"` Allow
     statement. Then add the scoped Deny(s) that enforce the control.
   - Resource-based policies: mandatory confused-deputy conditions.
   - VPCE policies: org scoping via `aws:PrincipalOrgID` (NOT confused-deputy keys).
   - KMS key policies: `kms:ViaService` keyed to the consuming service.
4. Stamp `_metadata.reference` (REQUIRED — the anchor gate hard-fails otherwise).

## Required metadata

Same shape as `generate-preventive-scp`, with `posture: "preventative-request"`
and `scope`/`layer` from the control. `_metadata.reference.example_id` MUST equal
the plan row's `anchor.example_id` and resolve in the index.

## Action rule (hard)

IAM Action strings are NOT API operation names. Every target-service
`Action`/`NotAction` string MUST be a real action in the AWS Service
Authorization Reference for the target service, sourced from the SAR IAM
action list (resolving operation→action drift via the
`data/botocore-iam-alias.json` map — boto3 and SAR sometimes disagree, e.g.
`StopQueryExecution` vs `athena:CancelQueryExecution`) or from
`capabilities.iam.permission_only_actions[]` (IAM-evaluated actions without an
API endpoint, e.g. `lambda:InvokeFunctionUrl`). Never template an Action
string from an operation name. CHECK-17 fails the hook on a synthesized
target-service action; CHECK-14a fails the hook on a non-SAR/non-doc-cited
condition key. Service-specific condition keys absent from the SAR snapshot
may still be valid — the SAR is a lower bound; cite the service authorization
doc in `mcp-calls.log` when relying on a non-SAR key.

## Print summary

```
Preventive IAM author complete — <service>:
  Authored: <files> (controls: ...) each anchored to a reference example
  (or: no GENERATE_IAM controls in plan)
```
