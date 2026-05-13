---
name: phase-map
description: Rules for Phase 3 (Map) sub-skills
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/state/map*.json"
---

# Phase 3 — Map

Applies to: `sa-map-parse-framework`, `sa-map-generate-controls`, `sa-map-framework-mapping`, `sa-map-assemble`.

## Phase structure

```
┌────────────────────────┐
│  sa-map-parse-framework│ (parallel)
│  sa-map-generate-       │
│  controls              │
└───────────┬────────────┘
            │ both complete
            ▼
┌────────────────────────┐
│ sa-map-framework-mapping│ (sequential)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│  sa-map-assemble       │ (sequential — writes mapping-results.json)
└────────────────────────┘
```

Use `/spawn` for the first two. After both complete, run framework-mapping and assemble sequentially.

## Output files

| Sub-skill | Output | Schema |
|-----------|--------|--------|
| `map-parse-framework` | `state/map-framework-parsed.json` | `map-framework-parsed.schema.json` |
| `map-generate-controls` | `state/map-controls-generated.json` | `map-controls-generated.schema.json` |
| `map-framework-mapping` | `state/map-framework-mapped.json` | `map-framework-mapped.schema.json` |
| `map-assemble` | `state/mapping-results.json` + `controls-catalog.md` + `framework-mapping.md` | `mapping-results.schema.json` |

## Control ID format

Every generated control has an ID matching `^CTRL-(ORG|ACC|RES)-(PRO|PRV|DET|COR)-\d{3}$`. The schema enforces this. Do NOT use service-prefixed IDs (`S3-ORG-PRV-001`) — they fail CHECK-S11.

Scope prefixes:
- `ORG` — organization-wide (SCPs, org policies)
- `ACC` — account-level (account boundaries, permission boundaries)
- `RES` — resource-level (KMS key policies, S3 bucket policies)

Category prefixes:
- `PRO` — proactive (CFN Guard, Checkov, OPA — evaluated before deploy)
- `PRV` — preventive (SCPs, resource policies — IAM-level blocks)
- `DET` — detective (Config rules, EventBridge — observe deployed state)
- `COR` — responsive (Lambda remediators, SSM runbooks — act on findings)

## Hard rules

1. **Every control must map to at least one framework objective.** `controls[].framework_keywords` must be non-empty. The mapping validator cross-checks against the parsed framework.

2. **`mapping-results.json` is the richest state file.** It has 60+ controls, full traceability (threat → mitigation → control → framework objective), and the coverage matrix. Phase 4 reads THIS, not the intermediates.

3. **Coverage gaps need rationale.** Integrity rule P5: if framework coverage is below 15%, every N/A objective must have a rationale (≥30 chars) explaining why it's not applicable to this service.
