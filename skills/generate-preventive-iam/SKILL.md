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
| `IAM Policy` | `preventive/iam-policies.json` | `IAM` |
| `IAM Permission Boundary` | `preventive/permission-boundary.json` | `permission-boundary` |
| `Resource Policy` / `Resource-Based Policy` | `preventive/resource-policy.json` | `IAM`, `data-perimeter` |
| `VPCE Policy` | `preventive/vpce-policy.json` | `VPCE`, `data-perimeter` |
| `KMS Key Policy` | `preventive/kms-key-policy.json` | `IAM` |
| `IAM Trust Policy` | *(referred, not authored)* | *(none — refer-only)* |

**Trust policies are referred, not authored.** There is no vetted trust-policy
example library to anchor to, and the cross-service confused-deputy prevention a
trust policy implements (the `aws:SourceArn` / `aws:SourceAccount` condition on
the `sts:AssumeRole` principal) is documented per-service. The recommender marks
trust-policy controls `REFER_TO_REFERENCE` with a `service-doc` citation, so they
never reach this skill as a `GENERATE_IAM` row. If you ever encounter a
trust-policy control here, emit a REFER pointer — `{"_metadata": {"mechanism":
"IAM Trust Policy", "not_anchored": true, "not_anchored_reason": "...service-doc
confused-deputy pattern..."}}` with **no** `Statement[]` body and **no** repo
`reference` — never an authored policy. The reference-anchor validator hard-fails
a trust policy that carries a repo anchor or ships an enforcing body.

**Reference-repo purposes (anchor to the RIGHT repo for the mechanism).** The
recommender's `best_anchor` already restricts to the correct family, but when
you load the anchor body, confirm it came from the repo that *publishes that
mechanism* — do not adapt an identity-policy access-check sample into a
permission boundary:

| Mechanism | Correct source repo | NOT this |
|---|---|---|
| Permission boundary | `example-permissions-boundary` (structural boundary scaffold) | `iam-access-analyzer-custom-policy-check-samples` (those are identity-policy *checks*, not boundaries) |
| Resource-based / data-perimeter policy | `data-perimeter-policy-examples`, `iam-access-analyzer-custom-policy-check-samples` (resource-policy examples) | — |
| Identity policy | `iam-access-analyzer-custom-policy-check-samples`, `iam-policy-autopilot` | — |

**Input:**
- `.service-approval/<slug>/05-recommended-guidance/preventive-plan.json` — rows where `decision == "GENERATE_IAM"`
- `.service-approval/<slug>/04-map/mapping-results.json`, `03-validate/validated.json`
- `data/reference-repos/index.yaml` (anchored to `iam-policy-autopilot`,
  `example-permissions-boundary`, `iam-access-analyzer-custom-policy-check-samples`,
  `data-perimeter-policy-examples`)

**Output:** the per-mechanism files above under
`.service-approval/<slug>/05-recommended-guidance/preventive/`.

---

## Gate

```bash
python3 - <<'PY'
import json
plan = json.load(open(".service-approval/<slug>/05-recommended-guidance/preventive-plan.json"))
rows = [d for d in plan["decisions"] if d["decision"] == "GENERATE_IAM"]
assert all(r.get("anchor", {}).get("example_id") for r in rows), "un-anchored GENERATE_IAM row"
print(f"{len(rows)} IAM-family controls to author")
PY
```

For each row, dispatch to the matching output file by the control's `mechanism`.
A mechanism with no approved row → do not emit that file (no placeholder, no
invented control ID). Generate ONLY files whose mechanism appears in the plan.

## Authoring procedure (per approved control)

1. Load the anchor body. **When the plan row's `anchor.source == "threat_model"`**,
   load the matching AWS Threat Model implementation from
   `.service-approval/<slug>/02-research/threat-model-index.json` (match `implementations[]`
   by `anchor.example_id` == the implementation `alias`) and author from its
   `authorization_policy` (governed `actions` / `resources` / `condition_keys`);
   the AWS Threat Model anchor is complete on its own. **Otherwise** load the
   reference-repo anchor body (vendored JSON, or facts-only re-expressed from
   `source_url` for share-alike entries — log the MCP lookup).
2. Adapt to the target service: actions from `validated.json` (action rule
   below), condition keys from the recommender's `enforcing_condition_keys[]`.
3. Apply the IAM-family authoring rules from
   `skills/generate-preventive/SKILL.md` ("Account × Preventive",
   "Resource × Preventive", "Rule C2"):
   - IAM policies: scope to specific resource ARN patterns, not `*`.
   - Permission boundaries: NEVER emit an unconditional `Allow <prefix>:* on
     Resource "*"` baseline — that is an exfiltration path the integrity check
     (P3) hard-blocks, and it defeats the purpose of a boundary (which exists to
     *constrain*). A boundary is the **maximum** a principal may do; it is NOT
     the role's grant policy. Two failure modes to avoid:
     1. **Do not re-create the role's main policy.** Do not enumerate a broad
        list of management actions (`CreateFunction`, `UpdateFunctionCode`,
        `TagResource`, …) as the Allow — that is the role policy's job, not the
        boundary's. The boundary's Allow exists only to keep the boundary from
        being a deny-all; keep it to the smallest scope the control needs. The
        integrity check (P10) hard-blocks a boundary Allow that enumerates
        `Create*/Update*/Put*/Delete*/Tag*/…` management actions.
     2. **The boundary MUST carry the control's enforcing condition.** A
        boundary with no condition key does not implement the control — it is
        the same defect as a no-op SCP. The Deny statement(s) MUST use the
        plan row's `enforcing_condition_keys[]` to gate the target action(s)
        (e.g. deny `iam:PassRole` unless `iam:PassedToService` /
        `aws:ResourceTag` matches the approved execution-role pattern, when the
        control's intent is "cap PassRole to approved roles"). If the plan row
        has no `enforcing_condition_keys[]`, the recommender should not have
        marked it `GENERATE_IAM` — surface the mismatch rather than emitting an
        unconditional boundary.

     Concretely: scope the Allow to specific actions on the resource ARN
     pattern (`arn:aws:<prefix>:*:*:<type>/*`); put only the genuinely
     wildcard-only actions (those whose SAR `resource_types` is empty — e.g.
     `List*`, account-level `Get*`) in a separate `Resource: "*"` Allow
     statement. Then add the scoped, **condition-keyed** Deny(s) that enforce
     the control. The boundary must reflect the upstream control's intent — if
     the mapping says "cap PassRole to approved execution roles," the boundary
     denies the un-approved case, it does not hand out a Lambda-management
     allowlist.
   - Resource-based policies: mandatory confused-deputy conditions.
   - VPCE policies: org scoping via `aws:PrincipalOrgID` (NOT confused-deputy keys).
     A VPCE policy gates *endpoint use* — Action × Principal × ResourceArn at
     the endpoint — not request-body parameters of the caller's API call. If
     the upstream control's `parameters_controlled[]` references a nested
     create/update field (e.g., `$.VpcConfig.SubnetIds`,
     `$.ServerSideEncryption`, `$.KMSKeyArn`), a VPCE policy CANNOT enforce
     it; surface this as a recommender mismatch rather than authoring a
     no-op policy. Endpoint-use controls (restricting which principals or
     actions may flow through the endpoint) remain a valid VPCE-policy use
     case.
   - KMS key policies: `kms:ViaService` keyed to the consuming service.
4. Stamp the anchor. For a **AWS Threat Model** anchor, stamp `_metadata.citation =
   {type: "threat_model", id: "<alias>", url: "<MCP-verified REFERENCE href>",
   verified_via: "mcp"}` (stamp `_metadata.reference` only if a repo body was
   also used). For a **reference-repo** anchor, stamp `_metadata.reference`
   (REQUIRED — the anchor gate hard-fails an artifact with neither).
5. Stamp `_metadata.applicability` — copy the plan row's `applicability` object
   verbatim. Anchored IAM artifacts surface a citation `url`, so the plan row
   carries `applicability` and the reference-anchor validator hard-fails a
   URL-cited artifact that omits it. (A refer-only trust-policy pointer ships no
   policy and is exempt.)

## Required metadata

Same shape as `generate-preventive-scp`, with `posture: "preventative-request"`
and `scope`/`layer` from the control. For a reference-repo anchor,
`_metadata.reference.example_id` MUST equal the plan row's `anchor.example_id`
and resolve in the index; for an AWS Threat Model anchor the artifact carries
`_metadata.citation` of `type: "threat_model"` (alias resolves in `threat-model-index.json`)
instead. `_metadata.applicability` MUST be copied verbatim from the plan row's
`applicability` object (what the policy targets + how to use it, including where
NOT to apply it).

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
