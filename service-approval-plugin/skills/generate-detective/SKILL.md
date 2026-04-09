---
name: generate-detective
description: >
  Generate detective and corrective security control artifacts — Config rules with Lambda
  handlers, EventBridge rules, CloudWatch alarms, SSM runbooks, Step Functions workflows,
  CloudTrail configuration. Reads from mapping-results.json and validated.json.
disable-model-invocation: false
argument-hint: "[--service=<name>] [--include-unverified]"
---

# Service Approval — Generator: Detective & Corrective Controls

Generate all detective and corrective security control artifacts from the Controls Matrix.
This covers Organisation×Detective, Organisation×Corrective, Account×Detective,
Account×Corrective, Resource×Detective, and Resource×Corrective cells.

**Output:** `.service-approval/controls/detective/` and `.service-approval/controls/remediation/`

This is one of 3 focused generate sub-skills. Each writes to separate directories.

---

## Prerequisites

```bash
test -f .service-approval/state/mapping-results.json && echo "mapping-results: OK" || echo "ERROR"
test -f .service-approval/state/validated.json && echo "validated: OK" || echo "ERROR"
mkdir -p .service-approval/controls/detective/config-rule-lambdas
mkdir -p .service-approval/controls/remediation/lambda-remediator
```

Load detective and corrective controls:
```bash
python3 -c "
import json
mr = json.load(open('.service-approval/state/mapping-results.json'))
det = [c for c in mr['controls'] if c['category'] == 'DET']
cor = [c for c in mr['controls'] if c['category'] == 'COR']
print(f'Detective controls: {len(det)}')
print(f'Corrective controls: {len(cor)}')
"
```

Unless `--include-unverified` is set, skip controls where `verified: false`.

## Artifact Header Template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|resource>
# LAYER: <detective|remediation>
# CONTROLS: <comma-separated control IDs>
# FRAMEWORK: <framework-name> — <FULL sorted union of ALL MAPPED objective IDs>
# MITIGATIONS: <comma-separated mitigation IDs>
# GENERATED: service-approval v3.0.0
# SERVICE: <service-name>
```
For JSON files, add as `"_metadata"` key. For Python, use comment block at top.

The `FRAMEWORK` list MUST be the FULL sorted union from ALL `framework_mapping[]` entries
where `status == "MAPPED"` — the identical list in every file header.

---

## Organisation × Detective

### Config Org Rules (`detective/config-org-rules.json`)
- Use `awsknowledge` MCP to find managed Config rules for each resource type
- Deploy org-wide via AWS Config Organizations aggregator

### Config Conformance Pack (`detective/config-conformance-pack.yaml`)
- List Config conformance pack rules to enable org-wide
- Map to specific controls

### CloudTrail Org Trail (`detective/cloudtrail-org-config.json`)
- Org trail with data events for the service's resource types
- Use resource types from `validated.json` `capabilities.logging.cloudtrail.data_events`

---

## Organisation × Corrective

### Org SSM Runbook (`remediation/ssm-runbook-org.yaml`)
- SSM Automation document for org-level corrective actions
- Triggered by Config Org Rule non-compliance events

---

## Account × Detective

### Config Rules (`detective/config-rules.json`)
- Use `awsknowledge` MCP to find managed Config rules
- For uncovered controls, generate CUSTOM_LAMBDA rules
- **MANDATORY:** For every CUSTOM_LAMBDA rule, generate a corresponding Lambda handler

Each custom Config rule entry:
```json
{
  "rule_name": "runtime-vpc-check",
  "source_type": "CUSTOM_LAMBDA",
  "resource_type": "AWS::BedrockAgentCore::Runtime",
  "evaluation_logic": "Check if networkMode is VPC and subnets/securityGroups are configured",
  "control_ids": ["CTRL-ACC-DET-001"]
}
```

### Config Rule Lambda Handlers

For EVERY `CUSTOM_LAMBDA` rule, generate:
- `detective/config-rule-lambdas/<rule-name>/handler.py`
- `detective/config-rule-lambdas/<rule-name>/requirements.txt`

Handler template:
```python
import json, boto3

def handler(event, context):
    config_item = json.loads(event['invokingEvent'])['configurationItem']
    # Implement evaluation_logic specific to this rule
    compliance = 'COMPLIANT' if <rule-specific-condition> else 'NON_COMPLIANT'
    annotation = '<explanation of why non-compliant>' if compliance == 'NON_COMPLIANT' else ''
    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': config_item['resourceType'],
            'ComplianceResourceId': config_item['resourceId'],
            'ComplianceType': compliance,
            'Annotation': annotation,
            'OrderingTimestamp': config_item['configurationItemCaptureTime']
        }],
        ResultToken=event['resultToken']
    )
```

Each handler MUST implement rule-specific logic — do NOT copy-paste identical handlers.

**Config Rule Lambda Quality Rules:**
- **Enum validation**: When checking a property against valid values (e.g., `exceptionLevel`
  in `{"ERROR", "WARN", "DEBUG"}`), unknown/invalid values MUST be NON_COMPLIANT, not COMPLIANT.
  Never write `elif value:` → COMPLIANT as a catch-all for unknown values.
- **Cross-layer enum consistency**: The set of VALID enum values in detective handlers MUST
  match the corresponding CFN Guard rules in `proactive/cfn-guard-rules.guard`. If a Guard
  rule allows `["JWT", "CustomJWT", "IAM", "CUSTOM"]`, the detective handler must use the
  SAME set — not a different representation like `{"IAM_AUTH", "CustomJWT"}`. Read the Guard
  file before generating handlers to ensure alignment. If the API documentation uses different
  enum names in different contexts (e.g., create-time vs. describe-time), use the describe/
  GetConfiguration representation for detective (Config items) and the create-time
  representation for proactive (Guard rules), but document the mapping.
- **Config item nesting**: AWS Config configuration items may nest properties differently from
  the API request structure. Before generating a handler, verify the Config item schema by
  checking the AWS Config resource type documentation. For example, if the API uses
  `authorizerConfiguration.customJwtConfiguration.discoveryUrl`, the Config item may use the
  same nesting — the handler MUST navigate to the correct depth. Do NOT assume Config items
  flatten nested structures.
- **Boto3 client name consistency**: All generated Python artifacts (Config rule handlers, Lambda
  remediators, SSM runbooks with Lambda steps) MUST use the same boto3 client name for the
  target service. Before generating, verify the correct client name by checking the boto3
  documentation or the service's API model. Common error: using `bedrock-agent-core` in one
  handler and `bedrock-agentcore-control` in another. Pick the correct name and use it
  consistently across ALL generated Python files. Add a comment at the top of each handler
  documenting the boto3 client: `# boto3 client: '<service-client-name>'`
- **Deleted resources**: Always check `configurationItemStatus == "ResourceDeleted"` first → NOT_APPLICABLE
- **Annotation truncation**: Always truncate annotation to 256 chars: `annotation[:256]`
- **Error handling**: If an external API call fails (e.g., ec2:DescribeSubnets), log the error
  and mark the resource as NON_COMPLIANT with an annotation explaining the evaluation failure
- **IAM permissions for external API calls**: If a handler calls APIs outside the Config service
  (e.g., `ec2:DescribeSubnets` for AZ validation), the Config rule Lambda execution role MUST
  include those permissions. Add them to the `config-rules.json` execution role policy or
  document them as a deployment prerequisite.

### Config Conformance Pack (`detective/config-conformance-pack.yaml`)
- Bundle all account-level Config rules into a conformance pack

### EventBridge Rules (`detective/eventbridge-rules.json`)
- One rule per critical API operation (Create, Update, Delete, PutResourcePolicy)
- Target: SNS topic for notifications + optional Lambda for enrichment
- **Service prefix accuracy (CRITICAL)**: The EventBridge `source` field MUST use the EXACT
  service prefix from `validated.json` (e.g., the `service` field or
  `capabilities.logging.cloudtrail.event_source`). The format is `aws.<service-prefix>`.
  The `eventSource` in detail patterns MUST be `<service-prefix>.amazonaws.com`. Do NOT
  hardcode or guess the service name — always read it from state files. Verify that the
  generated rules match the state file value before writing.
- **EventBridge target input mapping**: When wiring EventBridge rules to SSM runbooks or
  Step Functions, use the correct event field names from the upstream event source.
  AWS Config compliance change events use `$.detail.resourceARN` (capital ARN) for the full
  resource ARN and `$.detail.resourceId` for the identifier only. Map SSM/Step Functions
  `ResourceArn` parameters to `$.detail.resourceARN`, not `$.detail.resourceId`.
- **Complete mutation coverage**: Generate rules for ALL mutation operations from the API surface,
  not just Create/Delete. Check `validated.json` `api_surface.operations[]` for every operation
  starting with `Create`, `Update`, `Delete`, `Put`, `Associate`, `Disassociate`, `Attach`,
  `Detach`, `Tag`, `Untag`. Missing an Update* operation means configuration changes go
  undetected. Cross-check the generated rule list against the full API surface to ensure no
  mutation operation is missing.

### CloudWatch Alarms (`detective/cloudwatch-alarms.json`)
- Use `awsknowledge` MCP to confirm available metrics
- Alarm per key metric from `capabilities.logging.cloudwatch`

### Access Analyzer (`detective/access-analyzer.json`)
- Only if any resource type supports resource-based policies
- **Resource type support**: IAM Access Analyzer supports a specific set of resource types
  (S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, Secrets Manager secrets,
  SNS topics, EBS snapshots, RDS snapshots, ECR repositories, EFS file systems). If the
  service's resource types are NOT in this list, document it as a KNOWN GAP with a comment
  explaining which resource types are not yet supported by Access Analyzer. Do NOT generate
  an Access Analyzer config that references unsupported resource types.

---

## Account × Corrective

### Lambda Remediator (`remediation/lambda-remediator/handler.py`)
Python Lambda: receive EventBridge event → parse resource ARN + violation → remediate → log.

### Lambda CFN Template (`remediation/lambda-remediator/template.yaml`)
Lambda + least-privilege IAM role + EventBridge trigger.

**CRITICAL — SAM template metadata:** Do NOT use `_metadata` as a top-level key in
CloudFormation/SAM templates — cfn-lint rejects unknown top-level keys (E1001). Instead,
place pipeline metadata under the standard `Metadata` key:
```yaml
Metadata:
  ServiceApproval:
    scope: account
    layer: remediation
    controls: "CTRL-ACC-COR-001,CTRL-ACC-COR-002"
    framework: "BCR-01,BCR-03,..."
    generated: "service-approval v3.0.0"
    service: "<service-name>"
```
This passes cfn-lint validation while preserving traceability metadata for cross-validation.

### SSM Runbook (`remediation/ssm-runbook.yaml`)
SSM Automation document for manual/scheduled remediation.
- **API parameter cross-reference (CRITICAL)**: Every parameter in SSM `aws:executeAwsApi` steps
  MUST match the exact parameter name from `validated.json` `api_surface.operations[]`. Read the
  validated API surface for each operation before generating runbook steps.
- **Parameter mutability check**: If an encryption or configuration parameter is only accepted on
  `Create*` operations and NOT on `Update*` operations, the setting is immutable after creation.
  Do NOT generate a remediation step that attempts to update an immutable parameter — instead
  document it as requiring resource recreation or flag as manual intervention required.

### Step Functions Workflow (`remediation/stepfunctions-workflow.json`)
Workflow: detect → notify → remediate → verify → close finding.

**CRITICAL — ResultPath on SDK integration tasks:** Every Task state that calls an AWS SDK
action (e.g., `arn:aws:states:::aws-sdk:...`) MUST use `ResultPath` to place the API response
into a sub-key of the state, preserving the original event context. Without `ResultPath`, the
SDK response OVERWRITES the entire state input — subsequent steps lose access to the resource
ARN, violation details, and other fields from the original event.

```json
{
  "Type": "Task",
  "Resource": "arn:aws:states:::aws-sdk:bedrock-agent-core:getMemory",
  "Parameters": { "MemoryId.$": "$.resourceId" },
  "ResultPath": "$.getMemoryResult",
  "Next": "CheckCompliance"
}
```

Do NOT omit `ResultPath` — this is the #1 cause of broken Step Functions workflows where
the remediation step cannot find the resource ARN because the describe step overwrote it.

**CRITICAL — Policy parameter serialization:** When a Step Functions Task state includes a
`Policy` parameter that expects a JSON string (common in PutResourcePolicy-style API calls),
the `Parameters` block must serialize it with `States.JsonToString()`:
```json
{
  "Parameters": {
    "ResourceArn.$": "$.resourceArn",
    "Policy.$": "States.JsonToString($.policyDocument)"
  }
}
```
Passing a raw JSON object where the API expects a JSON string causes a runtime error. Check
the API documentation for each SDK integration task — if the parameter type is `String` and
the value is a policy document, use `States.JsonToString()` to convert it.

---

## Resource × Detective

Append resource-specific rules to `detective/config-rules.json` with resource-level scope.
Generate corresponding Lambda handlers for any custom rules.

---

## Resource × Corrective

Extend `remediation/stepfunctions-workflow.json` with resource-level remediation steps.

---

## Compensating Control Documentation

Some controls in mapping-results have `mechanism: "Compensating Control Documentation"`. These
document capabilities that are NOT available for the service (e.g., RCP not supported, FIPS
endpoints not available, RAM not shareable, declarative policies not applicable) and explain
what compensating controls exist.

Generate: `detective/compensating-controls-documentation.json`

```json
{
  "_metadata": {
    "scope": "ORG/ACC",
    "layer": "detective",
    "controls": "<comma-separated control IDs>",
    "framework": "<FULL sorted union of ALL MAPPED objective IDs>",
    "generated": "service-approval v3.0.0",
    "service": "<service-name>"
  },
  "<control-id>": {
    "control_id": "<CTRL-xxx-DET-nnn>",
    "name": "<from mapping-results>",
    "description": "<from mapping-results>",
    "gap_reason": "<why the capability is unavailable>",
    "compensating_controls": ["<list of compensating control IDs>"],
    "assessment_gap_ids": ["<from mapping-results>"],
    "recommendation": "<what the customer should do>"
  }
}
```

Filter controls from mapping-results where `mechanism` contains "Documentation" or
"Compensating". Every such control MUST appear in this file's `_metadata.controls` list
so cross-validation (CHECK-X2) can find it.

---

## Per-Control Rule Differentiation

Even when multiple controls share the same artifact type, generate distinct rules per
control based on each control's `description` and `parameters_controlled`:
- Rule name/comment must reference the specific control ID
- Do NOT copy-paste one rule for every control

---

## Validate Generated Artifacts

Artifact validation runs automatically via PostToolUse hook (validate_controls.py) and Stop hook (validate_cross.py Check X8).

## Print Summary

```
Generate (detective/corrective) complete:
  Org×Detective:    config-org-rules, conformance-pack, cloudtrail-org-config
  Org×Corrective:   ssm-runbook-org
  Acc×Detective:    config-rules ({N} managed, {N} custom), eventbridge-rules, cloudwatch-alarms [, access-analyzer]
  Acc×Corrective:   lambda-remediator, ssm-runbook, stepfunctions-workflow
  Res×Detective:    resource-level config rules
  Res×Corrective:   resource-level remediation steps
  Compensating:     compensating-controls-documentation ({N} gap documentations)
  Lambda handlers:  {N} custom rule handlers generated
  Output: .service-approval/controls/detective/, .service-approval/controls/remediation/
```
