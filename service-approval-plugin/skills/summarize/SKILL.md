---
name: summarize
description: Produce final APPROVAL-REPORT.md with CCMv4 matrix, control inventory, test evidence, and verdict
disable-model-invocation: false
---

# Service Approval — Summarizer

Read all state files and generate the final approval report at `.service-approval/APPROVAL-REPORT.md`.

## Prerequisites

- [ ] Check required inputs:
  ```bash
  test -f .service-approval/state/research.json && echo "research: OK" || echo "research: MISSING"
  test -f .service-approval/state/validated.json && echo "validated: OK" || echo "validated: MISSING"
  test -d .service-approval/controls && echo "controls: OK" || echo "controls: MISSING"
  ```
  Proceed even if `test-results.json` is absent (mark test as NOT RUN in the report).

## Step 1: Determine verdict

Read `validated.json` for `unverified_count`. Read `test-results.json` if it exists.

| Condition | Verdict |
|-----------|---------|
| `test_results.passed = true` AND `unverified_count = 0` | APPROVED |
| `test_results.passed = true` AND `unverified_count > 0` | APPROVED WITH EXCEPTIONS |
| `test_results.skipped = true` AND `unverified_count = 0` | APPROVED (test not run) |
| `test_results.passed = false` | REQUIRES REMEDIATION |
| `test-results.json` absent | APPROVED (test not run) |

Note: `passed: null` (dry-run) is treated the same as `skipped: true`.

## Step 2: Build CCMv4 coverage matrix

From `validated.json` `ccmv4_mappings[]`, build a table:

| CCMv4 Control ID | Title | Domain | Satisfied By | Coverage |

Where "Satisfied By" = comma-separated control IDs that map to this CCMv4 objective.

## Step 3: Build control inventory

For each file in `.service-approval/controls/`, read its `_metadata` or header comments
(lines starting with `# SCOPE:`, `# LAYER:`, `# CONTROLS:`, `# CCMv4:`).

Build a table per layer:
| Layer | Scope | Artifact | Controls | CCMv4 |

## Step 4: Build artifact manifest

```bash
find .service-approval/controls -type f | sort
```

## Step 5: Write APPROVAL-REPORT.md

Write `.service-approval/APPROVAL-REPORT.md` with exactly these 8 H2 sections:

## Verdict
[Verdict string with date, service name, resource count]

## Executive Summary
[Coverage numbers: N controls generated, N CCMv4 objectives covered, test result]

## CCMv4 Coverage Matrix
[Full table from Step 2 — all 197 CCMv4 IDs, mapped or N/A]

## Control Inventory
[Per-layer table from Step 3, organized by Controls Matrix cell]

## Test Evidence
[Security Hub finding count, Config compliance status — or "Test not run" if skipped]

## UNVERIFIED Items
[List with reasons, or "None — all items verified" if unverified_count = 0]

## Artifact Manifest
[Full file list from Step 4]

## Next Steps
Deployment order:
1. **Org level**: Apply SCPs, RCPs, tag policies via AWS Organizations
2. **Account level**: Deploy Config conformance pack, Security Hub standards, Access Analyzer
3. **Service level**: Deploy CloudFormation Hooks, Config org rules
4. **Resource level**: Deploy detective controls (EventBridge, CloudWatch alarms, Lambda remediator), then create the compliant resource using the IaC template in `controls/iac/`

Print:
```
Report written: .service-approval/APPROVAL-REPORT.md
Verdict: <APPROVED|APPROVED WITH EXCEPTIONS|REQUIRES REMEDIATION>
CCMv4 objectives covered: N / 197
Total control artifacts: N
```
