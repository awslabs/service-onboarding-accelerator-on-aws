---
name: test
description: Deploy compliant resource template and validate zero Security Hub findings. Requires AWS credentials.
disable-model-invocation: false
argument-hint: "[--env=<profile>] [--keep] [--dry-run] [--timeout=<minutes>]"
---

# Service Approval — Tester

Deploy the generated compliant resource template and validate that it produces zero Security Hub
findings and no Config rule violations. Write results to `.service-approval/state/test-results.json`.

## Prerequisites

- [ ] Check controls exist:
  ```bash
  test -d .service-approval/controls && echo "OK" || echo "ERROR: run generator first"
  ```

- [ ] Parse flags:
  - `--env=<profile>`: AWS CLI profile (REQUIRED for full mode)
  - `--keep`: keep deployed resources after test
  - `--dry-run`: lint only, no deployment
  - `--timeout=<minutes>`: Security Hub polling timeout (default: 30)

## Dry-run mode (--dry-run or no --env)

Run cfn-lint via `awsiac` MCP on `controls/iac/compliant-resource.cfn.yaml`.
Write to `.service-approval/state/test-results.json`:
```json
{
  "passed": null,
  "skipped": true,
  "skip_reason": "dry-run — template syntax validated only",
  "security_hub_findings": null,
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

### Step 4: Wait for Security Hub to stabilize

Wait 60 seconds for initial findings to appear. Then poll every 60 seconds up to `--timeout` minutes.

```bash
sleep 60
aws securityhub get-findings \
  --filters '{"ResourceId":[{"Value":"<resource-arn>","Comparison":"PREFIX"}]}' \
  --profile {env} \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}' \
  --output json
```

Filter findings: only count those where `Resources[].Id` matches a deployed resource ARN.
Record `filtered_ambient` count (findings on other resources, ignored).

### Step 5: Evaluate results

- `security_hub_findings.total = 0`: PASS
- All Config rules COMPLIANT: PASS
- No CloudWatch alarms in ALARM state: PASS

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
  "security_hub_findings": {
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
  "teardown_complete": true
}
```

Print summary:
```
Test complete:
  Security Hub findings (filtered): N
  Config compliance: COMPLIANT/NON_COMPLIANT
  CloudWatch alarms triggered: N
  Deployed resources: N
  Teardown: complete/skipped (--keep)
  RESULT: PASS/FAIL
```

