---
name: generate-detective
description: Generate detective control artifacts — Config rules with Lambda handlers, EventBridge rules, CloudWatch alarms, CloudTrail configuration — and responsive references to pre-authored AWS SSM Automation runbooks. Reads from mapping-results.json and validated.json.
disable-model-invocation: false
argument-hint: '[--service=<name>] [--include-unverified]'
---

# Service Approval — Generator: Detective & Responsive Controls

Generate all detective control artifacts from the Controls Matrix, plus responsive
guidance that **references** pre-authored AWS SSM Automation runbooks (we source,
we do not author remediation). This covers Organisation×Detective,
Organisation×Responsive, Account×Detective, Account×Responsive, Resource×Detective,
and Resource×Responsive cells.

**Output:** `.service-approval/<slug>/05-recommended-guidance/detective/` and `.service-approval/<slug>/05-recommended-guidance/responsive/`

This is one of the focused generate sub-skills. Each writes to separate directories.

## Citation discipline (REQUIRED for every authored artifact)

Every JSON artifact this skill writes under `detective/` and `responsive/` MUST
carry a **resolvable citation** in its `_metadata`, enforced by
`validate_citation_coverage.py` (Stop-hook P12). There are three forms; use the
one the table below specifies for each artifact:

- **Canopy anchor (first-priority when a Canopy is present)** — `_metadata.citation
  = {type: "canopy", id: "<alias>", url: "<REFERENCE href>", verified_via: "mcp"}`
  whose `id` resolves to a mitigation/implementation `alias` in
  `.service-approval/<slug>/02-research/canopy-index.json`. See "Canopy-first
  sourcing" below.
- **Repo anchor** — `_metadata.reference = {example_id, repo, url}` whose
  `example_id` resolves to an entry in `data/reference-repos/index.yaml`. Used for
  **custom Config rules** (CUSTOM_LAMBDA / CUSTOM_POLICY), which anchor to
  `aws-config-custom-policy-rule-samples` (a Guard-DSL sample repo). Resolve the
  anchor with `tools/reference_index.py` `best_anchor("AWS Config Rule", [], [],
  resource_types=[<the CFN resource type the rule evaluates>])`.
- **Doc anchor** — `_metadata.citation = {type: "aws_doc", title, url,
  verified_via: "mcp"}` where `url` is an AWS documentation page **fetched via MCP
  at generation time** (`awsknowledge` / `aws-documentation`) to prove it is live,
  and the call logged to `pipeline.log`. NEVER hardcode a URL from training data.

### Canopy-first sourcing (when a Canopy threat-model was provided)

Before the managed-rule / custom-rule lookup for a control, check
`.service-approval/<slug>/02-research/canopy-index.json` for a `behavior ==
"DETECTIVE"` implementation matching the control's resource type / monitored
operation:

- A `mechanism == "Config Rule"` implementation carries `governed_api_operations[]`
  (`service` + `operation` + `response_parameters[].path`) — use those to shape the
  Config rule's evaluation, and cite it (`type: "canopy"`, id = the implementation
  `alias`), linking to the implementation's REFERENCE `href` (or its mapped
  mitigation's cited link) as the doc URL.
- A `mechanism == "CloudTrail"` implementation carries `monitored_operations[]`
  (`operation` + `request_parameters[].path`) — use those to shape the CloudTrail /
  EventBridge rule, cited the same way.

MCP-verify the REFERENCE `href` at generation time (`awsknowledge` /
`aws-documentation`) and log the call to `pipeline.log`; stamp `verified_via:
"mcp"`. **Fall through** to the managed-rule / repo-anchor / doc-anchor paths below
only when Canopy has no matching implementation for the control.

| Artifact | Citation form |
|----------|---------------|
| `detective/config-rules.json` AWS_MANAGED rule | doc anchor → the managed-rule's AWS Config developer-guide page |
| `detective/config-rules.json` CUSTOM_LAMBDA / CUSTOM_POLICY rule | repo anchor → `aws-config-custom-policy-rule-samples` example (or doc anchor if none fits) |
| `detective/config-org-rules.json`, `detective/config-conformance-pack.yaml` | same as the rule kind above |
| `detective/eventbridge-rules.json` | doc anchor → the EventBridge / relevant service-event AWS doc |
| `detective/cloudwatch-alarms.json` | doc anchor → the CloudWatch metric/alarm AWS doc |
| `detective/cloudtrail-org-config.json` | doc anchor → the CloudTrail AWS doc |
| `detective/access-analyzer.json` | doc anchor → the IAM Access Analyzer AWS doc |
| `responsive/ssm-runbook-reference*.json` | doc anchor → the SSM automation-runbook-reference doc + the specific runbook page |

When a rule is CUSTOM but no `aws-config-custom-policy-rule-samples` example
matches its resource type, fall back to a doc anchor (the service's AWS Config
custom-rule authoring doc). Every artifact ends with at least one resolvable
citation — no exceptions except explicit gap/skip stubs
(`_metadata.status: "NOT_APPLICABLE"`).

---

## Prerequisites

```bash
test -f .service-approval/<slug>/04-map/mapping-results.json && echo "mapping-results: OK" || echo "ERROR"
test -f .service-approval/<slug>/03-validate/validated.json && echo "validated: OK" || echo "ERROR"
mkdir -p .service-approval/<slug>/05-recommended-guidance/detective/config-rule-lambdas
mkdir -p .service-approval/<slug>/05-recommended-guidance/responsive
```

Load detective and responsive controls:
```bash
python3 -c "
import json
mr = json.load(open('.service-approval/<slug>/04-map/mapping-results.json'))
det = [c for c in mr['controls'] if c['category'] == 'DET']
cor = [c for c in mr['controls'] if c['category'] == 'COR']
print(f'Detective controls: {len(det)}')
print(f'Responsive controls: {len(cor)}')
"
```

Unless `--include-unverified` is set, skip controls where `verified: false`.

### Routed-from-preventive objectives (top-up pass)

The preventive root-cause critic routes objectives it found NOT-preventable (no
condition key gates the action) to detective. If
`.service-approval/<slug>/05-recommended-guidance/detective-routing.json` exists, you MUST
also generate detective coverage for every entry in its `routed[]` array — these
objectives have no preventive control and would otherwise go uncovered.

```bash
test -f .service-approval/<slug>/05-recommended-guidance/detective-routing.json && python3 -c "
import json
r = json.load(open('.service-approval/<slug>/05-recommended-guidance/detective-routing.json'))
for e in r['routed']:
    print(e['control_id'], '←', e['reason'])
" || echo "(no routed objectives)"
```

For each routed entry, generate the appropriate detective artifact (Config rule,
EventBridge rule, etc.) for the control's resource/action, then **write the
artifact filename(s) back into that entry's `covered_by` field** so the routing
loop is closed. `validate_detective_routing.py` confirms every routed entry ends
up with a real `covered_by` artifact. This top-up runs AFTER the root-cause
critic; the orchestrator sequences a detective pass once the critic finishes.

## Config-supportability gate (REQUIRED before emitting any Config rule)

AWS Config cannot record every resource type — a Config rule for an unsupported
type is a silent no-op. **Before emitting a Config rule (managed or custom) for a
resource type, confirm AWS Config supports it.** Source of truth:
`data/config-supported-resource-types.json` (built from the botocore Config
`ResourceType` enum + doc-confirmed additions from the public AWS Config
"Supported Resource Types" reference).

Probe each candidate resource type:

```bash
python3 tools/validate/validate_config_support.py --resource-type "AWS::<Service>::<Resource>" --json
# {"resource_type": "...", "status": "SUPPORTED" | "UNSUPPORTED"}
```

- **SUPPORTED** → emit the Config rule as normal.
- **UNSUPPORTED** → do **NOT** emit a Config rule. Instead:
  - route the control to an alternate detective mechanism — a CloudTrail
    data/management event or an EventBridge rule on the control-plane API call, or
  - record the gap in `detective-routing.json` (or a `NOT_APPLICABLE` stub) with
    the reason `"AWS Config does not support AWS::<Service>::<Resource>"`, cited to
    the resource-config-reference doc
    (`https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html`).

**Canopy divergence:** if Canopy proposes a Config rule (`config_rule`
implementation) for a type the doc list does not support, the deterministic gate
wins — Canopy can be aspirational. Do not emit the Config rule; log the
divergence to `pipeline.log` and route/gap the control as above. (The doc is the
freshest source of truth and can be ahead of the SDK enum — e.g.
`AWS::DSQL::Cluster` is doc-supported; the data file carries such additions.)

`validate_config_support.py --slug <slug>` runs at generation review and the P13
Stop-hook integrity check hard-fails a run that emitted a Config rule for an
unsupported type.

## Artifact Header Template

Every generated artifact MUST include these comment lines at the top:
```
# SCOPE: <org|account|resource>
# LAYER: <detective|responsive>
# POSTURE: <reactive-detective|reactive-corrective>
# CONTROLS: <comma-separated control IDs>
# FRAMEWORK: <framework-name> — <FULL sorted union of ALL MAPPED objective IDs>
# MITIGATIONS: <comma-separated mitigation IDs>
# GENERATED: service-approval v3.0.0
# SERVICE: <service-name>
```
For JSON files, add as `"_metadata"` key AND set `_metadata.posture` to the exact
posture value from `mapping-results.json.controls[].posture` for the control this
artifact implements. For Python, use comment block at top.

**CHECK-15 enforcement:** Every generated artifact's `_metadata.posture` MUST match its
directory family:
- `reactive-detective` → `detective/config-rule-lambdas/**`, `detective/config-rules.json`,
  or `detective/access-analyzer.json`
- `reactive-corrective` → `responsive/**` (reference JSON pointing at a pre-authored
  AWS SSM Automation runbook; we do not author remediation code)

A Config rule Lambda tagged with `posture: "preventative-request"` would fail the hook —
Rule C1 in map-generate-controls should never have produced it. If the hook fires, fix
the posture classification in `map-controls-generated.json`, not the artifact.

---

## Rule C3 — API-driven mechanism contents (applies to ALL sections below except EventBridge)

Config rule Lambdas, managed Config rules, and Access Analyzer configs are all
**API-driven** — they read AWS resource state as exposed by the service's API
surface. Their contents MUST be grounded in
`validated.json.api_surface.operations[].parameters[]`:

1. **Every property path the handler reads (e.g., `configurationItem.configuration.<...>`)
   MUST map to a parameter path in `api_surface.operations[].parameters[]`.** AWS Config
   configuration items mirror the API request/response shape; a handler that checks a
   property not in the API surface is reading a path that doesn't exist at runtime.
2. **Every enum-literal list in Python `if x in [...]` comparisons MUST use values from
   `parameters[].enum`.** Do NOT re-scrape AWS docs; the enum values in `validated.json`
   are the single source of truth for this service run. Copy verbatim — substituting
   `IAM` for `IAM_AUTH` or `CustomJWT` for `CUSTOM_JWT_AUTHORIZER` causes detective
   handlers to mark compliant resources NON_COMPLIANT.

Validator CHECK-14b enforces rule 2 at hook time. An enum-literal value not in any
parameter's enum fails the hook. The check is scoped to `detective/config-rule-lambdas/**`.

---

## Rule C4 — EventBridge hybrid (SAR + API sources)

EventBridge rules are a **hybrid** mechanism — they need data from BOTH sources:

- **From SAR** (`validated.json.capabilities.iam.actions[]` + service prefix):
  - `source`: `aws.<service-prefix>`
  - `detail.eventSource`: `<service-prefix>.amazonaws.com`
  - `detail.eventName`: one of the IAM actions (e.g., `CreateCluster`, `UpdateService`)
- **From API Reference** (`api_surface.operations[].parameters[]`):
  - `detail.requestParameters.<path>`: sub-field schema for filtering on request
    parameter values. The parameter path (e.g., `detail.requestParameters.launchType`)
    MUST come from `parameters[].path`. Enum filter values (e.g., matching on
    `launchType == "EC2"`) MUST come from `parameters[].enum`.
  - `detail.responseElements.<path>`: for filtering on response fields (e.g., ARN
    patterns), the path MUST come from the operation's response shape documented in
    `api_surface.operations[].response_parameters[]` (if present) or the service's
    CloudTrail event documentation.

**Both sources are required.** An EventBridge rule that cites only `eventName` without
filtering on any parameter is a coarse-grained rule — acceptable for broad monitoring,
but for security-critical mutation tracking, pair `eventName` with a `requestParameters`
filter whose parameter path + enum values come from the API source.

The existing "Service prefix accuracy" rule in the EventBridge Rules section below is
the SAR-source half of this rule. The new half is the API-driven detail.requestParameters
filter schema.

The `FRAMEWORK` line MUST be copied VERBATIM from
`mapping-results.json.framework_header_canonical` — `scripts/map-assemble.py` precomputes
this sorted-union string once so every artifact emits the identical header. Do NOT re-derive
the list from `_metadata.controls[]` or from per-control `framework_objectives[]` — that
produces per-artifact subsets and fails CHECK-X1 (`validate_cross.py:120`), which asserts
every artifact shares one framework header. Read `framework_header_canonical`, paste it
after `# FRAMEWORK: ` (and into `_metadata.framework` for JSON files), done.

---

## Organisation × Detective

### Config Org Rules (`detective/config-org-rules.json`)
- Use `awsknowledge` MCP to find managed Config rules for each resource type
- Deploy org-wide via AWS Config Organizations aggregator
- **Citation:** each rule entry carries its citation — an AWS_MANAGED rule cites
  the managed-rule's developer-guide page (doc anchor); a custom rule cites its
  `aws-config-custom-policy-rule-samples` example (repo anchor). See the per-rule
  citation block in "Config Rules" below; the org file uses the same shapes.

### Config Conformance Pack (`detective/config-conformance-pack.yaml`)
- List Config conformance pack rules to enable org-wide
- Map to specific controls
- Cite the AWS Config conformance-pack developer-guide page (doc anchor) in a
  leading comment header (this is a YAML file, cited via its sibling
  `config-org-rules.json`/`config-rules.json` entries).

### CloudTrail Org Trail (`detective/cloudtrail-org-config.json`)
- Org trail with data events for the service's resource types
- Use resource types from `validated.json` `capabilities.logging.cloudtrail.data_events`
- **Citation (doc anchor):** MCP-fetch and cite the CloudTrail data-events AWS doc
  page; put it in `_metadata.citation` (`{type:"aws_doc", title, url,
  verified_via:"mcp"}`).

---

## Organisation × Responsive

Responsive is **reference-only** — we do not author remediation code. For an
org-level remediation need, find the pre-authored AWS SSM Automation runbook via
MCP and emit a reference (see "Account × Responsive" for the full contract). Write
`responsive/ssm-runbook-org-reference.json` with the org-scoped runbook reference +
how-to-use guide, cited to the automation-runbook-reference doc.

---

## Account × Detective

### Config Rules (`detective/config-rules.json`)
- Use `awsknowledge` MCP to find managed Config rules
- For uncovered controls, generate CUSTOM_LAMBDA rules
- **MANDATORY:** For every CUSTOM_LAMBDA rule, generate a corresponding Lambda handler
- **MANDATORY citation on every rule** (per the citation-discipline table above).

Each Config rule entry carries a citation. **AWS_MANAGED** rules cite the managed
rule's AWS Config developer-guide page as a doc anchor:
```json
{
  "rule_name": "<managed-rule-identifier>",
  "source_type": "AWS_MANAGED",
  "resource_type": "AWS::<Service>::<Resource>",
  "control_ids": ["CTRL-ACC-DET-001"],
  "citation": {
    "type": "aws_doc",
    "title": "AWS Config Managed Rules — <rule-identifier>",
    "url": "https://docs.aws.amazon.com/config/latest/developerguide/<rule-identifier>.html",
    "verified_via": "mcp"
  }
}
```
**CUSTOM_LAMBDA / CUSTOM_POLICY** rules cite the
`aws-config-custom-policy-rule-samples` example they adapt (repo anchor). Resolve
it with `best_anchor("AWS Config Rule", [], [], resource_types=["AWS::<Service>::<Resource>"])`:
```json
{
  "rule_name": "<resource>-<check-name>",
  "source_type": "CUSTOM_LAMBDA",
  "resource_type": "AWS::<Service>::<Resource>",
  "evaluation_logic": "Check if <property> meets <requirement>",
  "control_ids": ["CTRL-ACC-DET-001"],
  "reference": {
    "example_id": "<resolved index example id>",
    "repo": "aws-config-custom-policy-rule-samples",
    "url": "<example source_url from the index>"
  }
}
```
If no sample matches the resource type, fall back to a doc anchor citing the AWS
Config custom-rule authoring guide. The file's top-level `_metadata` also carries
the citation for the *primary* rule so `validate_citation_coverage.py` (which reads
`_metadata`) resolves; each rule additionally carries its own `citation`/`reference`
as shown.

### Config Rule Lambda Handlers

For EVERY `CUSTOM_LAMBDA` rule, generate:
- `detective/config-rule-lambdas/<rule-name>/handler.py`
- `detective/config-rule-lambdas/<rule-name>/requirements.txt`

**Handler directory name MUST equal the `rule_name` field byte-for-byte**:
`validate_cross.py` CHECK-X8 asserts that every `CUSTOM_LAMBDA` rule's
`rule_name` has a matching directory under `detective/config-rule-lambdas/`
with exactly that name. Pick ONE convention (prefer hyphens: `ctrl-acc-det-001-...`)
and apply it identically to:
- the `rule_name` field in `config-rules.json`
- the handler subdirectory name
- the rule's Sid/name inside the Lambda source
Mixing hyphens and underscores between the config entry and the directory
silently decouples the rule from its handler at deploy time.

Handler template:
```python
import json, boto3

def _evaluate(config_item: dict) -> tuple[str, str]:
    if config_item.get("configurationItemStatus") == "ResourceDeleted":
        return "NOT_APPLICABLE", ""
    # Implement evaluation_logic specific to this rule
    compliance = 'COMPLIANT' if <rule-specific-condition> else 'NON_COMPLIANT'
    annotation = '<explanation of why non-compliant>' if compliance == 'NON_COMPLIANT' else ''
    return compliance, annotation

def lambda_handler(event, context):
    config_item = json.loads(event['invokingEvent'])['configurationItem']
    compliance, annotation = _evaluate(config_item)
    # TESTMODE: smoke-deploy-controls.py passes resultToken="TESTMODE" and reads
    # result["ComplianceType"] from the return value — skip put_evaluations.
    if event.get('resultToken') == 'TESTMODE':
        return {"ComplianceType": compliance, "Annotation": annotation[:256]}
    boto3.client('config').put_evaluations(
        Evaluations=[{
            'ComplianceResourceType': config_item['resourceType'],
            'ComplianceResourceId': config_item['resourceId'],
            'ComplianceType': compliance,
            'Annotation': annotation[:256],
            'OrderingTimestamp': config_item['configurationItemCaptureTime']
        }],
        ResultToken=event['resultToken']
    )
    return {"ComplianceType": compliance}
```

Each handler MUST implement rule-specific logic — do NOT copy-paste identical handlers.

**Smoke Test Events (REQUIRED for every handler):**

Every Config handler MUST include a `SMOKE_TEST_EVENTS` module-level dict with `compliant`
and `non_compliant` mock events. The smoke-deploy-controls script uses these for local unit
testing without AWS credentials. Handlers without `SMOKE_TEST_EVENTS` will fail validation.

```python
SMOKE_TEST_EVENTS = {
    "compliant": {
        "invokingEvent": json.dumps({
            "configurationItem": {
                "resourceType": "<AWS::Service::Resource>",
                "resourceId": "smoke-test-resource",
                "configurationItemCaptureTime": "2026-01-01T00:00:00Z",
                "configurationItemStatus": "OK",
                "configuration": {<properties that make this COMPLIANT>},
                "tags": {<required tags if checked>},
            },
            "messageType": "ConfigurationItemChangeNotification",
        }),
        "resultToken": "TESTMODE",
    },
    "non_compliant": {
        "invokingEvent": json.dumps({
            "configurationItem": {
                "resourceType": "<AWS::Service::Resource>",
                "resourceId": "smoke-test-resource",
                "configurationItemCaptureTime": "2026-01-01T00:00:00Z",
                "configurationItemStatus": "OK",
                "configuration": {<properties that make this NON_COMPLIANT>},
                "tags": {},
            },
            "messageType": "ConfigurationItemChangeNotification",
        }),
        "resultToken": "TESTMODE",
    },
}
```

The compliant event MUST include all properties the handler checks with passing values.
The non_compliant event MUST omit or invalidate the primary property the handler evaluates.
When `resultToken == "TESTMODE"`, the handler MUST skip the `put_evaluations` call (or the
unit test mocks boto3 to intercept it).

**CRITICAL — Self-contained evaluation for smoke test events**: Handlers that call external
AWS APIs (kms:DescribeKey, lambda:GetCodeSigningConfig, accessanalyzer:CheckAccessNotGranted,
lambda:GetFunction, lambda:ListFunctionUrlConfigs, etc.) MUST be able to determine compliance
from the `configurationItem.configuration` dict alone when the event is a smoke test. The
smoke test events include ALL data the handler needs in the `configuration` field. Do NOT
call external APIs when the data is already in the configuration item. Structure the handler
to extract everything from `configuration` first, and only call APIs as a fallback for
periodic rules where the Config item doesn't have the needed data. The unit test runner
mocks `boto3.client` to return empty/error responses — any handler that depends on external
API calls for its primary check WILL fail the smoke test.

**Config Rule Lambda Quality Rules:**
- **Python dict literals MUST use Python values, not JSON tokens**: The SMOKE_TEST_EVENTS
  module-level dict is Python source code. Inside any `{...}` used as a Python dict
  literal, use `None`/`True`/`False` — NOT `null`/`true`/`false`. JSON-syntax tokens
  are valid ONLY inside the string argument to `json.dumps(...)` or inside a quoted
  `invokingEvent` string. Example:
    `"configuration": {"encrypted": True}` — correct (Python bool)
    `"configuration": {"encrypted": true}` — wrong (NameError: name 'true' is not defined
    at module load; the smoke-test harness fails to import the handler).
  Serialization handles the conversion: `json.dumps({"encrypted": True})` → `'{"encrypted": true}'`.
- **non_compliant SMOKE_TEST_EVENTS must be self-consistent**: The `non_compliant` fixture
  MUST NOT contain any attribute, tag, or configuration value that the handler evaluates
  as a compliance-positive OVERRIDE. If the handler has a fallback check (e.g., "else if
  tags contain FlowLogsEnabled=true, return COMPLIANT"), the non_compliant event must
  omit or invert every such override — otherwise the fixture silently flips the test
  result. This is a STRONGER form of the earlier rule "the non_compliant event MUST
  omit or invalidate the primary property": the non_compliant event must omit or invert
  BOTH the primary property AND every compliance-override the handler recognizes.
- **Return value contract (REQUIRED)**: `lambda_handler` MUST return a dict shaped
  `{"ComplianceType": "<COMPLIANT|NON_COMPLIANT|NOT_APPLICABLE>"}` (optionally with
  `"Annotation"`) in BOTH the TESTMODE branch and after the `put_evaluations` call.
  The smoke-test harness (`scripts/smoke-deploy-controls.py`) reads
  `result["ComplianceType"]` when `resultToken == "TESTMODE"`. Do NOT use keys like
  `compliance`, `status`, or `result` — only `ComplianceType` (capital C, capital T).
  AWS Config itself discards the Lambda return value; the return exists solely so
  the smoke-test harness can unit-test handlers without mocking boto3.
- **Enum validation**: When checking a property against valid values (e.g., `exceptionLevel`
  in `{"ERROR", "WARN", "DEBUG"}`), unknown/invalid values MUST be NON_COMPLIANT, not COMPLIANT.
  Never write `elif value:` → COMPLIANT as a catch-all for unknown values.
- **Cross-layer enum consistency (CRITICAL — #1 recurring failure)**: ALL detective handlers
  MUST use the EXACT same enum values as proactive controls (Guard, OPA, Checkov). The
  single source of truth for enum values is `validated.json`:
  1. Find the parameter's `feasibility_note` in `existing_mitigations[]` — it lists valid values
  2. Cross-reference with `api_surface.operations[].parameters[]` for the parameter definition
  3. Use ONLY the values found in validated.json — do NOT invent alternatives
  Example: if validated.json says `authorizerType (IAM_AUTH, CUSTOM_JWT_AUTHORIZER)`, then
  ALL layers (Guard, OPA, Checkov, Config Lambda, Step Functions, SSM) MUST use exactly
  `IAM_AUTH` and `CUSTOM_JWT_AUTHORIZER`. Common error: substituting `IAM` for `IAM_AUTH`
  or `CustomJWT` for `CUSTOM_JWT_AUTHORIZER` — these invented values cause detective
  handlers to mark compliant resources as NON_COMPLIANT and proactive rules to silently skip.
  **Before writing ANY enum comparison, grep validated.json for the exact parameter name and
  copy the values verbatim.**
- **Config item nesting**: AWS Config configuration items may nest properties differently from
  the API request structure. Before generating a handler, verify the Config item schema by
  checking the AWS Config resource type documentation. For example, if the API uses
  `authorizerConfiguration.customJwtConfiguration.discoveryUrl`, the Config item may use the
  same nesting — the handler MUST navigate to the correct depth. Do NOT assume Config items
  flatten nested structures.
- **Boto3 client name consistency**: All generated Python artifacts (Config rule handlers)
  MUST use the same boto3 client name for the
  target service. Before generating, verify the correct client name by checking the boto3
  documentation or the service's API model. Common error: using inconsistent hyphenation or
  suffixes across handlers. Pick the correct name and use it
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
- **Allow-list handlers MUST fail closed (REQUIRED for security)**: When a handler uses an
  environment variable to carry an allow-list (approved Lambda ARNs, approved VPC IDs,
  approved KMS key ARNs, approved account IDs, etc.) and the env var is empty or unset,
  the handler MUST return `NON_COMPLIANT`, NOT `COMPLIANT`. An empty allow-list means
  "nothing is approved" — every resource evaluates non-compliant. Defaulting to
  `COMPLIANT` is fail-open and silently bypasses the control in misconfigured deployments
  (env var typo, deploy-time variable not set, etc.).

  Two-part pattern:

  1. **Inline override for smoke-test fixtures** — check an `_Approved*` field on the
     Config configuration item BEFORE the env var. This lets SMOKE_TEST_EVENTS declare
     the allow-list without mutating process env.

  2. **Env-var fallback + fail-closed** — if the inline override is absent, read the
     env var. If the resulting list is empty, return NON_COMPLIANT with an Annotation
     explaining why.

  ```python
  def _approved_list(ci: dict) -> list[str]:
      # (1) Inline override — smoke-test fixtures carry `_ApprovedLambdaArns` on the
      # Config configuration item; check this BEFORE the env var so tests don't need
      # to mutate process env.
      inline = ci.get("configuration", {}).get("_ApprovedLambdaArns")
      if isinstance(inline, list):
          return [s for s in inline if s]
      # (2) Env-var fallback
      raw = os.environ.get("APPROVED_LAMBDA_ARNS", "")
      return [s.strip() for s in raw.split(",") if s.strip()]

  def lambda_handler(event, context):
      ...
      approved = _approved_list(configuration_item)
      if not approved:
          return {
              "ComplianceType": "NON_COMPLIANT",
              "Annotation": "APPROVED_LAMBDA_ARNS is empty or unset; failing closed (nothing is approved until an allow-list is configured).",
          }
      ...
  ```

  Do NOT generate `if not approved: return {"ComplianceType": "COMPLIANT"}`. That
  pattern silently passes every resource when the allow-list is misconfigured. No
  current validator catches fail-open allow-lists (handlers are opaque Python) — the
  rule lives only here. Verified observation: iter-17 Athena detective sub-agent
  invented this pattern ad-hoc; codifying prevents future runs from regressing to
  fail-open.

### Config Conformance Pack (`detective/config-conformance-pack.yaml`)
- Bundle all account-level Config rules into a conformance pack

### EventBridge Rules (`detective/eventbridge-rules.json`)
- One rule per critical API operation (Create, Update, Delete, PutResourcePolicy)
- Target: SNS topic for notifications + optional Lambda for enrichment
- **Citation (doc anchor, REQUIRED):** MCP-fetch and cite the EventBridge / relevant
  service-event AWS doc page. Put it in the file's top-level `_metadata.citation`
  (`{type:"aws_doc", title, url, verified_via:"mcp"}`).
- **Top-level schema (REQUIRED for smoke-test deploy)**:
  ```json
  {
    "_metadata": {
      "citation": {"type": "aws_doc", "title": "...", "url": "https://docs.aws.amazon.com/...", "verified_via": "mcp"}
    },
    "rules": [
      {
        "rule_name": "ctrl-acc-det-NNN-description",
        "EventPattern": {"source": ["aws.<prefix>"], "detail": {...}},
        "control_ids": ["CTRL-ACC-DET-NNN"]
      }
    ]
  }
  ```
  The top-level key MUST be lowercase `rules` (not `Rules`). The Tier 2 deploy script
  (`scripts/smoke-deploy-controls.py` `deploy_eventbridge_rules`) iterates the lowercase
  `rules` array. Each rule object uses `EventPattern` (PascalCase) for the pattern payload
  since that is the AWS API field name inside a PutRule request.
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
  starting with `Create`, `Update`, `Delete`, `Put`, `Set`, `Associate`, `Disassociate`, `Attach`,
  `Detach`, `Tag`, `Untag`. Missing an Update* operation means configuration changes go
  undetected. **Encryption key changes are always security-critical** — any `Set*Key`, `Set*CMK`,
  `Update*Encryption`, or `Put*KeyPolicy` operation MUST have an explicit EventBridge rule even
  if it is low-volume. Cross-check the generated rule list against the full API surface to ensure
  no mutation operation is missing. Also include `Start*PolicyGeneration`, `Start*ExtractionJob`,
  and similar control-plane operations that trigger data processing. For any mutation operation
  intentionally excluded from EventBridge rules (e.g., high-volume data-plane Batch* operations),
  add an `"excluded_operations"` array in the eventbridge-rules.json `_metadata` with a
  `reason` field for each (e.g., `"reason": "Data-plane operation monitored via CloudTrail data events"`).

### CloudWatch Alarms (`detective/cloudwatch-alarms.json`)
- Use `awsknowledge` MCP to confirm available metrics
- Alarm per key metric from `capabilities.logging.cloudwatch`
- **Citation (doc anchor, REQUIRED):** MCP-fetch and cite the CloudWatch metrics/alarm
  AWS doc page for the service in the file's top-level `_metadata.citation`.

### Access Analyzer (`detective/access-analyzer.json`)
- Only if any resource type supports resource-based policies
- **Resource type support**: IAM Access Analyzer supports a specific set of resource types
  (S3 buckets, IAM roles, KMS keys, Lambda functions, SQS queues, Secrets Manager secrets,
  SNS topics, EBS snapshots, RDS snapshots, ECR repositories, EFS file systems). If the
  service's resource types are NOT in this list, document it as a KNOWN GAP with a comment
  explaining which resource types are not yet supported by Access Analyzer. Do NOT generate
  an Access Analyzer config that references unsupported resource types.
- **Citation (doc anchor, REQUIRED):** MCP-fetch and cite the IAM Access Analyzer AWS doc
  page in the file's top-level `_metadata.citation`.

---

## Account × Responsive — REFERENCE-ONLY

**We do not author remediation code.** No Lambda remediator, no authored SSM
document, no Step Functions workflow. For each `COR` (responsive) control, find
the relevant **pre-authored AWS SSM Automation runbook** via MCP and emit a
**reference + how-to-use guide** instead. This is the "we source, we don't
generate" rule applied to remediation.

For each responsive control, write one JSON reference file
`responsive/<control-id>-ssm-runbook-reference.json` (or a single
`responsive/ssm-runbook-references.json` keyed by control id):

```json
{
  "_metadata": {
    "scope": "account",
    "layer": "responsive",
    "posture": "reactive-corrective",
    "controls": "CTRL-ACC-COR-001",
    "framework": "<framework_header_canonical>",
    "generated": "service-approval v3.0.0",
    "service": "<service-name>",
    "citation": {
      "type": "aws_doc",
      "title": "AWS Systems Manager Automation runbook reference — AWS-<Runbook>",
      "url": "https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-<runbook>.html",
      "verified_via": "mcp"
    }
  },
  "runbook": {
    "name": "AWS-<Runbook>",
    "found_via": "mcp: awsknowledge / aws-documentation search of the SSM automation-runbook-reference",
    "how_to_use": {
      "invoke": "aws ssm start-automation-execution --document-name AWS-<Runbook> --parameters '{...}'",
      "required_parameters": ["<param1>", "<param2>"],
      "applies_to": "<which resource type / finding this runbook remediates>",
      "responds_to": "<the detective finding/control this closes>"
    }
  }
}
```

Rules:
- **Find the runbook via MCP.** Search the SSM automation-runbook-reference
  (`automation-runbook-reference.html`) via `awsknowledge` / `aws-documentation`
  for a pre-authored `AWS-*` runbook that remediates the control's finding. Log the
  MCP call to `pipeline.log`.
- **Citation is REQUIRED** (doc anchor): the `automation-runbook-reference` doc URL
  and, when the runbook has its own page, that page. MCP-verified, never hardcoded.
- **If no pre-authored AWS runbook fits**, do NOT author one. Emit the reference
  file with `"runbook": {"name": null, "note": "No pre-authored AWS SSM runbook
  covers this remediation; manual intervention required."}` and cite the SSM
  automation-runbook-reference index page so the customer can search it themselves.
- The `how_to_use` block tells the customer how to invoke it, its required
  parameters, where it applies, and which detective finding it responds to.

---

## Resource × Detective

Append resource-specific rules to `detective/config-rules.json` with resource-level scope
(each carrying its citation per the Config Rules section). Generate corresponding Lambda
handlers for any custom rules.

---

## Resource × Responsive

Reference-only, same as Account × Responsive: emit a resource-scoped
`responsive/<control-id>-ssm-runbook-reference.json` pointing at the pre-authored
AWS SSM runbook that remediates the resource-level finding, cited to the SSM
automation-runbook-reference doc.

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
    "posture": "preventative-proactive",
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

**Posture note — filename-scoped exception to the general rule.** The `posture` field
on this file is ALWAYS `preventative-proactive`, regardless of the posture on the
underlying controls it documents. Compensating-controls documentation is proactive
documentation about *why* a capability is missing — not a detective control itself.
This is the single filename-scoped exception to the general "copy posture from
`mapping-results.json.controls[].posture`" rule stated earlier (see the posture
consistency section near the top of this skill). Enforced by
`validate_controls.py::check_posture_mechanism_consistency_15` via
`_PREV_PROACTIVE_CROSS_CUTTING_BASENAMES = ("compensating-controls-documentation.json",)`
and `test_validate_controls.py:591-598`. Copying `reactive-detective` or
`reactive-corrective` from the underlying control fails CHECK-15 at hook time.

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
Generate (detective/responsive) complete:
  Org×Detective:    config-org-rules, conformance-pack, cloudtrail-org-config
  Org×Responsive:   ssm-runbook-org-reference (pre-authored AWS runbook reference)
  Acc×Detective:    config-rules ({N} managed, {N} custom), eventbridge-rules, cloudwatch-alarms [, access-analyzer]
  Acc×Responsive:   ssm-runbook-reference(s) (pre-authored AWS runbook references)
  Res×Detective:    resource-level config rules
  Res×Responsive:   resource-level ssm-runbook-reference(s)
  Compensating:     compensating-controls-documentation ({N} gap documentations)
  Lambda handlers:  {N} custom rule handlers generated
  Citations:        every detective/responsive artifact carries a repo or doc anchor
  Output: .service-approval/<slug>/05-recommended-guidance/detective/, .service-approval/<slug>/05-recommended-guidance/responsive/
```
