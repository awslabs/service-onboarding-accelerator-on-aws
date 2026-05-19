---
name: phase-generate
description: Rules for Phase 4 (Generate) sub-skills
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/*/05-generate/**"
---

# Phase 4 — Generate

Applies to: `sa-generate-preventive`, `sa-generate-detective`, `sa-generate-iac`.

## Parallel execution

Use `/spawn` to run all three concurrently. Each writes to a disjoint subtree of `.service-approval/<slug>/05-generate/`:

```
/spawn sa-generate-preventive    → 05-generate/preventive/, 05-generate/proactive/
/spawn sa-generate-detective     → 05-generate/detective/, 05-generate/responsive/
/spawn sa-generate-iac           → 05-generate/iac/{cdk,cloudformation,cdktf,terraform}/
```

## Hard rules

1. **IaC must be parameterized.** No hardcoded account IDs (`123456789012`, `000000000000`) or placeholder ARNs. Integrity rule P4 blocks.

2. **SCPs must have at least one Deny.** Allow-only SCPs are a safety violation. Integrity rule P3 blocks.

3. **`StringEquals` and `StringNotEquals` in the same Condition must target the same key.** Conditions AND together — different keys means the statement can never fire. Integrity rule P3 blocks.

4. **Every artifact gets a control ID annotation.** Every resource property that implements a control must have an inline comment with the control ID (e.g., `# CTRL-ACC-PRV-001` in Terraform, `// CTRL-ACC-PRV-001` in CDK, `Comment: CTRL-ACC-PRV-001` in CFN).

5. **`_metadata` must be top-level only.** IAM policy Statements reject underscore-prefixed fields (`_description`, `_comment`, `_control_ids`). Put per-statement context in the `Sid` field. `_metadata` sits outside the `Statement` array.

6. **Every SCP needs `_simulation_tests` metadata.** Required for the test harness to simulate deny/allow behavior. See `skills/generate-preventive/SKILL.md` for the full shape.

7. **Every generate sub-skill must read `mapping-results.json`, not `map-controls-generated.json`.** `mapping-results` is the assembled, framework-mapped truth.

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

`ide/hooks/post-tool-use.kiro.hook` fires on `fs_write` to anything under `.service-approval/<slug>/05-generate/`. It runs:
- JSON/YAML parse validation
- Terraform `validate` + `fmt` on `.tf` files
- cfn-lint on `.yaml`/`.json` CFN templates
- Python compile on Lambda handler `.py` files
- cfn-guard syntax check on `.guard` files
- OPA `check` on `.rego` files

Failures exit 2 → Kiro auto-retries the write with the error in context.
