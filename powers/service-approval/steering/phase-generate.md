---
name: phase-generate
description: Rules for Phase 4 (Recommended Guidance) sub-skills
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/*/05-recommended-guidance/**"
---

# Phase 4 — Generate

Applies to the three generate families: preventive (a gated sub-pipeline),
`sa-generate-detective`, and `sa-generate-iac`.

## Parallel execution

Use `/spawn` to run the three families concurrently. Each writes to a disjoint
subtree of `.service-approval/<slug>/05-recommended-guidance/`. The **preventive family runs
its sub-skills in order** — the recommender gate, then the reference-anchored
authors, then the root-cause critic — and must not be parallelized internally:

```
preventive (in order):
  /spawn sa-generate-preventive-recommend  → 05-recommended-guidance/preventive-plan.json (gate)
  /spawn sa-generate-preventive-scp         → 05-recommended-guidance/preventive/ (GENERATE_SCP rows)
  /spawn sa-generate-preventive-rcp         → 05-recommended-guidance/preventive/ (GENERATE_RCP rows)
  /spawn sa-generate-preventive-iam         → 05-recommended-guidance/preventive/ (GENERATE_IAM rows)
  /spawn sa-generate-preventive-rootcause   → prove anchored + enforcing
/spawn sa-generate-detective     → 05-recommended-guidance/detective/, 05-recommended-guidance/responsive/
/spawn sa-generate-iac           → 05-recommended-guidance/iac/{cdk,cloudformation,cdktf,terraform}/
```

`skills/generate-preventive/SKILL.md` is the shared authoring-rules reference the
preventive authors follow; it is not a standalone generator.

## Hard rules

1. **IaC must be parameterized.** No hardcoded account IDs (`123456789012`, `000000000000`) or placeholder ARNs. Integrity rule P4 blocks.

2. **SCPs must have at least one Deny.** Allow-only SCPs are a safety violation. Integrity rule P3 blocks.

3. **`StringEquals` and `StringNotEquals` in the same Condition must target the same key.** Conditions AND together — different keys means the statement can never fire. Integrity rule P3 blocks.

4. **Every artifact gets a control ID annotation.** Every resource property that implements a control must have an inline comment with the control ID (e.g., `# CTRL-ACC-PRV-001` in Terraform, `// CTRL-ACC-PRV-001` in CDK, `Comment: CTRL-ACC-PRV-001` in CFN).

5. **`_metadata` must be top-level only.** IAM policy Statements reject underscore-prefixed fields (`_description`, `_comment`, `_control_ids`). Put per-statement context in the `Sid` field. `_metadata` sits outside the `Statement` array.

6. **Every SCP needs `_simulation_tests` metadata.** Required for the test harness to simulate deny/allow behavior. See `skills/generate-preventive/SKILL.md` for the full shape.

7. **Every generate sub-skill must read `mapping-results.json`, not `map-controls-generated.json`.** `mapping-results` is the assembled, framework-mapped truth.

8. **Every preventive policy artifact must carry a reference anchor.** Each file under `05-recommended-guidance/preventive/` must have `_metadata.reference.example_id` resolving to a real entry in `data/reference-repos/index.yaml`. Un-anchored policy → integrity rule P8 blocks. Gap/skip stubs and documentation files are exempt. If no reference covers an objective, do not author — point to the reference or route to detective.

9. **Preventive controls must be enforceable (preventability).** A preventive control is only authored when a condition key gates its target action at request time (`validate_preventability.py` verdict FEASIBLE). A control with no gating key is NOT preventable — route it to detective rather than author a non-firing SCP. The root-cause critic (`sa-generate-preventive-rootcause`) proves this for the whole `preventive/` directory.

10. **Target-service IAM actions must be sourced, never synthesized.** Every `Action` for the target service comes from `validated.json.api_surface.operations[].operation` or `capabilities.iam.permission_only_actions[]`. CHECK-17 blocks an action invented by analogy.

## Enum-accuracy rule (CRITICAL — #1 recurring failure)

Before writing any enum comparison in Guard/OPA/Checkov/TF validation blocks:

1. Find the parameter in `validated.json` `api_surface.operations[].parameters[]`
2. Read the `feasibility_note` for the relevant mitigation — it often lists valid enum values
3. Read the `enrichment_opportunities[]` and `condition_keys[]` for enforcement guidance
4. Use ONLY the values found — do NOT invent camelCase or SCREAMING_SNAKE_CASE transforms

Example failures:
- Using `IAM` instead of `IAM_AUTH`
- Using `CustomJWT` instead of `CUSTOM_JWT_AUTHORIZER`
- Using `awsvpc` instead of `AWSVPC`

Wrong enum → Guard `when` clause silently skipped; OPA `deny` false-negative; Checkov never triggers. All three layers quietly neutralized. CHECK-14b in `validate_controls.py` enforces at hook time on SCREAMING_SNAKE `[...]` list-form — equality-form and camelCase remain your responsibility.

## Artifact count ranges

Exact counts vary by service surface area. Observed ranges:

| Category | Files | Notes |
|----------|-------|-------|
| Preventive | 9–12 | SCPs (split at 5120 bytes), resource policies, KMS key policy, permission boundary |
| Proactive | 12–15 | CFN Guard, OPA, Checkov, CFN Hooks |
| Detective | 34–47 | Config rules + Lambda handlers (+requirements.txt each), EventBridge rules |
| Responsive | 6 | Lambda remediator + SAM template + deps, SSM runbooks |
| IaC | 17–31 | 4 formats + Terraform modules (per-resource modules + shared + root) |

## PostToolUse hook behavior

`ide/hooks/post-tool-use.kiro.hook` fires on `fs_write` to anything under `.service-approval/<slug>/05-recommended-guidance/`. It runs:
- JSON/YAML parse validation
- Terraform `validate` + `fmt` on `.tf` files
- cfn-lint on `.yaml`/`.json` CFN templates
- Python compile on Lambda handler `.py` files
- cfn-guard syntax check on `.guard` files
- OPA `check` on `.rego` files

Failures exit 2 → Kiro auto-retries the write with the error in context.

## Post-Generate Completeness Contract

Each generator sub-skill MUST produce output across ALL supported engines/formats.
A single-format output is never acceptable. Specifically:

- `sa-generate-preventive-scp` / `-rcp` / `-iam` → policies with `_metadata` + `_simulation_tests`
- `sa-generate-detective` → Config Rules as BOTH CloudFormation YAML and Terraform
- `sa-generate-iac` → One template per format in `iac-support.json` where `supported: true`
- Proactive controls → MUST exist as Guard + OPA + Checkov (all three)

If a generator completes without meeting this contract, the self-review gate
(defined in `steering/pipeline.md`) will catch it and force re-generation.
