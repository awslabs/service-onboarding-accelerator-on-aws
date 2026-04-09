---
name: test
description: Deploy compliant resource template and validate zero Config rule findings. Requires AWS credentials.
disable-model-invocation: false
argument-hint: "[--env=<profile>] [--keep] [--dry-run] [--timeout=<minutes>]"
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
python3 service-approval-plugin/tools/validate/validate_deployable.py \
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

### Step 2: Deploy compliant resource

```bash
STACK_NAME="service-approval-test-$(date +%s)"
aws cloudformation deploy \
  --template-file .service-approval/controls/iac/compliant-resource.cfn.yaml \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --profile {env}
```

Capture deployed resource ARNs from stack outputs:
```bash
aws cloudformation describe-stack-resources \
  --stack-name "$STACK_NAME" \
  --profile {env} \
  --query 'StackResources[*].PhysicalResourceId' \
  --output json
```

### Step 3: Deploy detective controls

```bash
aws cloudformation deploy \
  --template-file .service-approval/controls/remediation/lambda-remediator/template.yaml \
  --stack-name "${STACK_NAME}-detective" \
  --capabilities CAPABILITY_IAM \
  --profile {env}
```

### Step 4: Wait for Config evaluations to stabilize

Wait 60 seconds for initial evaluations to complete. Then poll every 60 seconds up to `--timeout` minutes.

```bash
sleep 60
aws configservice get-compliance-details-by-resource \
  --resource-type "<cfn-resource-type>" \
  --resource-id "<resource-id>" \
  --profile {env} \
  --query 'EvaluationResults[*].{RuleName:EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName,ComplianceType:ComplianceType}' \
  --output json
```

Filter evaluations: only count those where the resource matches a deployed resource ARN.
Record `filtered_ambient` count (evaluations on other resources, ignored).

### Step 5: Evaluate results

- `config_compliance.non_compliant_rules` is empty: PASS
- All Config rules COMPLIANT: PASS
- No CloudWatch alarms in ALARM state: PASS

### Step 5b: Coverage Verification

Read `.service-approval/state/mapping-results.json` and verify:

**Mitigation coverage:**
- For every entry in `threat_mitigation_map[]`:
  - Verify at least one control from `controls[]` has a deployed artifact
  - If `coverage == "NONE"`, flag as uncovered
- Calculate `mitigation_coverage`: covered / total mitigations

**Framework coverage:**
- For every entry in `framework_mapping[]` where `status == "MAPPED"`:
  - Verify at least one mapped control has a deployed artifact
  - If no deployed artifact exists for any mapped control, flag the objective
- Calculate `framework_coverage`: objectives with deployed artifacts / total mapped objectives

**Assessment gap coverage (if mapping-results.json references assessment gaps):**
- For controls linked to `assessment_gap_ids[]`, verify deployed artifacts exist
- Flag any assessment gap without a deployed control artifact

### Step 6: Teardown (unless --keep)

```bash
aws cloudformation delete-stack --stack-name "${STACK_NAME}-detective" --profile {env}
aws cloudformation delete-stack --stack-name "$STACK_NAME" --profile {env}
# Wait for deletion
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --profile {env}
```

If teardown fails, record failed resource ARNs in `test-results.json` under `teardown_failed`.

### Step 7: Write test-results.json

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

