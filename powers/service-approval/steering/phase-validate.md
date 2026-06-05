---
name: phase-validate
description: Rules for Phase 2 (Validate) sub-skill
inclusion: fileMatch
fileMatchPattern: "**/.service-approval/*/03-validate/validated.json"
---

# Phase 2 — Validate

Applies to: `sa-validate`.

## What this phase does

Cross-references every claim in `<slug>/02-research/research.json` (merged output of Phase 1)
against live MCP responses. Produces `<slug>/03-validate/validated.json` with per-item
verification evidence.

## Hard rules

1. **Every item must have a unique `verification_note`.** Integrity rule P2 enforces <50% duplication across all notes. Templated notes (same string, different items) fail.

2. **Minimum note length**: 40 characters for `verification.summary` field. Shorter summaries look templated.

3. **UNVERIFIED items must be excluded from Phase 4.** If a claim can't be verified via MCP, mark it `UNVERIFIED` in `validated.json`. Phase 4 (Generate) reads only `VERIFIED` items.

4. **Validator integration**: `validate_state.py::check_validated` runs the 11 schemas against this file. Shape errors block.

## Output contract

`state/validated.json` must match `schemas/validated.schema.json`:
- Top-level required: `schema_version`, `service`, `verified_count`, `verification`, plus the verified mitigations/capabilities/api_surface/condition_keys arrays
- Each item: `id`, `status`, `verification_note`, `verified_via` (MCP server), `verified_at`

## MCP call strategy

For each item:
1. Call the most specific MCP for its type:
   - Capabilities, features → `@awsknowledge`
   - IAM condition keys, actions → `@awsknowledge` (SAR)
   - CFN resource schema, CDK constructs → `@awsiac`
   - Free-form feature docs → `@aws-documentation`
2. If the MCP confirms: `status: VERIFIED`, note includes the server response summary
3. If MCP returns nothing or conflicts: `status: UNVERIFIED`, note explains why

## What triggers this steering

`inclusion: fileMatch` with `**/.service-approval/*/03-validate/validated.json` — loads
only when the validator sub-skill is writing this file.
