---
name: test
description: Deploy compliant resource template and validate zero Config rule findings. Requires AWS credentials.
disable-model-invocation: false
argument-hint: '[--env=<profile>] [--keep] [--dry-run] [--timeout=<minutes>]'
---

# Service Approval — Tester

Deploy the generated compliant resource template and validate that it produces zero Config rule
findings and no Config compliance violations. Write results to `.service-approval/state/test-results.json`.

## Prerequisites

- [ ] Check controls exist:
  ```bash
  test -d .service-approval/controls && echo "OK" || echo "ERROR: run generator first"
  ```

- [ ] Parse flags:
  - `--env=<profile>`: AWS CLI profile (REQUIRED for full mode)
  - `--keep`: keep deployed resources after test
  - `--dry-run`: lint only, no deployment
  - `--timeout=<minutes>`: Config evaluation timeout (default: 30)

## Dry-run mode (--dry-run or no --env)

Run the deployability validator (Tier 1 + Tier 2 if credentials available):

```bash
python3 tools/validate/validate_deployable.py \
  [--profile {env}] [--tier1-only] .service-approval/controls/
```

**Without `--env`**: Runs Tier 1 only (static checks — JSON, YAML, terraform validate/fmt,
CDK/CDKTF tsc, py_compile, cfn-lint). No AWS credentials needed.

**With `--env=<profile>`**: Runs Tier 1 + Tier 2 (CloudFormation validate-template, IAM
Access Analyzer validate-policy for SCPs, identity policies, resource policies).

If credentials are missing when `--env` is provided, print instructions:
```
Run: aws sso login --profile <profile>
```

Write to `.service-approval/state/test-results.json`:
```json
{
  "passed": null,
  "skipped": true,
  "skip_reason": "dry-run — deployability validation only",
  "tier1_result": "PASS|FAIL",
  "tier2_result": "PASS|FAIL|SKIPPED",
  "config_findings": null,
  "config_compliance": null,
  "cloudwatch_alarms_triggered": null,
  "deployed_resources": [],
  "teardown_complete": true
}
```

## Full mode

### Step 1: Verify credentials

```bash
aws sts get-caller-identity --profile {env}
```
Display account ID and alias. Confirm with user before proceeding.
If account alias contains: prod, prd, production, live → ask for explicit double confirmation.

### Step 2: Deploy + verify + teardown via smoke-deploy-test.sh

DO NOT invoke `aws cloudformation deploy` directly — the script handles the full
deploy/verify/teardown cycle AND substitutes `${ACCOUNT_ID}` placeholders in
`smoke-test-params.json` (line 161 of the script). Invoking raw `aws deploy`
bypasses the substitution and fails with "ARN in the specified key policy is invalid."

```bash
AWS_PROFILE="{env}" bash scripts/smoke-deploy-test.sh --cloudformation
```

The script:
1. Verifies AWS identity and refuses production-alias accounts.
2. Resolves `${ACCOUNT_ID}` in `smoke-test-params.json` → a temp file.
3. `aws cloudformation deploy` with `--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM`.
4. Verifies stack outputs inline (ExecutionRoleArn, FunctionArn, KmsKeyArn,
   LogGroupArn — see script lines 218-222). No separate wait-and-poll step.
5. `aws cloudformation delete-stack` + `wait stack-delete-complete`.

Capture the stack name and outputs from the script's stdout for Step 4b.
Exit code 0 = PASS, 1 = deploy failed, 2 = teardown failed (resources may remain).

### Step 3: Detective-stack deploy (SKIP for now)

Deploying the generated Config rules is handled by
`python3 scripts/smoke-deploy-controls.py --tier 2` as a separate smoke-test
step, not by this skill. The `/test` skill focuses on compliant-resource
deployability + coverage verification. If you need end-to-end Config-rule
evaluation, run `smoke-deploy-controls.py --tier 2` after Step 2 succeeds.

### Step 4: Evaluate results

Script exit code from Step 2:
- 0 → deploy + teardown PASSED
- 1 → deploy FAILED (check script stdout for `describe-stack-events` output)
- 2 → teardown FAILED (resources may remain; follow cleanup instructions)

### Step 4b: Coverage Verification

**Single source of truth for "control has deployed artifact" is
`scripts/smoke-check-traceability.py`.** That script already indexes every
control ID by scanning BOTH filenames AND file contents (first 64KB of each
`.json`, `.yaml`, `.py`, `.tf`, `.ts`, `.rego`, `.guard`, `.md`), which
correctly handles multi-control artifacts like `opa-policies/function.rego`,
`cloudwatch-alarms.json`, `scp-policy.json`, `iam-policies.json` where
`_metadata.controls[]` lists several IDs in one file.

Do NOT re-implement filename-only `_has_deployed_artifact(control_id)` in this
skill. That heuristic produces false negatives when one artifact covers
multiple controls — the symptom is a deflated "framework coverage %" in
`test-results.json`.

**Procedure:**

```bash
# Run the traceability script; it prints control-to-file indexing stats
# AND writes a machine-readable index JSON used below.
python3 scripts/smoke-check-traceability.py > /tmp/traceability.txt
```

Parse `scripts/smoke-check-traceability.py`'s output for:
- `file_control_ids` — the set of control IDs found in ANY file (filename or content).
- `missing_ids` — control IDs in mapping-results with NO deployed artifact.

Then compute the three coverage figures from `mapping-results.json`:

**Mitigation coverage:**
- For every entry in `threat_mitigation_map[]`:
  - `has_artifact = any(cid in file_control_ids for cid in threat.control_ids)`
  - If `coverage == "NONE"` OR no controls have artifacts, flag uncovered.
- `mitigation_coverage = covered / total`.

**Framework coverage:**
- For every entry in `framework_mapping[]` where `status == "MAPPED"`:
  - `has_artifact = any(c.control_id in file_control_ids for c in objective.controls)`
  - If no mapped control has an artifact, flag the objective.
- `framework_coverage = objectives_with_artifacts / total_mapped`.

**Assessment gap coverage (if mapping-results.json references assessment gaps):**
- For controls linked to `assessment_gap_ids[]`, verify presence in `file_control_ids`.
- Flag any assessment gap without at least one deployed control artifact.

Rationale: `smoke-check-traceability.py` is the single authoritative indexer.
Duplicating its logic here leads to silent coverage drift when one skill
evolves and the other doesn't.

### Step 5: Teardown (covered by Step 2)

`smoke-deploy-test.sh` performs `aws cloudformation delete-stack` +
`wait stack-delete-complete` as part of its normal run. No separate teardown
step is required. If the script exited with code 2, teardown failed — record
the stack name (captured from Step 2 stdout) in `test-results.json` under
`teardown_failed` so operators can finish cleanup manually.

### Step 6: Write test-results.json

Write `.service-approval/state/test-results.json`:
```json
{
  "passed": true,
  "skipped": false,
  "skip_reason": null,
  "config_findings": {
    "total": 0,
    "by_resource": {},
    "filtered_ambient": 3
  },
  "config_compliance": {
    "status": "COMPLIANT",
    "non_compliant_rules": []
  },
  "cloudwatch_alarms_triggered": 0,
  "deployed_resources": [
    { "type": "AWS::...", "arn": "arn:aws:..." }
  ],
  "mitigation_coverage": {
    "total": 37,
    "covered": 35,
    "uncovered": ["M-AgentRuntime.15", "M-Gateway.12"],
    "percentage": 94.6
  },
  "framework_coverage": {
    "total_mapped": 112,
    "with_deployed_artifacts": 110,
    "missing": ["CEK-19", "LOG-11"],
    "percentage": 98.2
  },
  "teardown_complete": true
}
```

Print summary:
```
Test complete:
  Config rule findings (filtered): N
  Config compliance: COMPLIANT/NON_COMPLIANT
  CloudWatch alarms triggered: N
  Deployed resources: N
  Mitigation coverage: N/N ({percentage}%)
  Framework coverage: N/N ({percentage}%)
  Teardown: complete/skipped (--keep)
  RESULT: PASS/FAIL
```

```bash
```

```bash
```

