---
name: research
description: Analyze input files and AWS docs to discover security gaps, map to CCMv4, and produce research.json
disable-model-invocation: false
argument-hint: "[./input-folder] [--service=<name>]"
---

# Service Approval — Researcher

Analyze the target AWS service against its threat model, live API surface, and CCMv4 controls.
Produce `.service-approval/state/research.json` following the schema exactly.

## Prerequisites

- [ ] Create output directory:
  ```bash
  mkdir -p .service-approval/state
  touch .service-approval/state/mcp-calls.log
  ```

## Inputs

Parse arguments:
- `./input-folder` (optional) — read all `.md`, `.json`, `.xlsx`, `.pdf`, `.docx` files in this folder
- `--service=<name>` — AWS service identifier (e.g., `bedrock-agentcore-control`)

If both are provided, use input-folder files AND --service name.
If only --service is provided, use MCP-only mode.
If neither is provided, ask the user for a service name before proceeding.

## Step 1: Parse input files

For each file in the input folder:
- `.json` files: attempt to parse as mitigation report (look for `entities` key with mitigation arrays)
- `.md` files: extract mitigation IDs (pattern: `M-<Resource>.<N>`), threats, request parameters
- `.xlsx` files: if filename contains "CCMv4" or "ccmv4", this is the CCMv4 source — note its path
- Other files: read for context

Build an initial list of `existing_mitigations` with fields: `id`, `statement`, `mitigation_goal`,
`request_parameters[]`, `resource_type`.

## Step 2: Fetch live API surface

Call `awsknowledge` MCP to retrieve the API reference for `--service`:
- List all API operations (CreateX, UpdateX, DeleteX, GetX, ListX, TagResource, UntagResource, etc.)
- For each operation, list all request parameters with their types and required flags
- Populate `api_surface.operations[]` in research.json

Log this MCP call to `.service-approval/state/mcp-calls.log`:
```
[TIMESTAMP] awsknowledge: GetAPIReference service=<name>
```

## Step 3: Fetch security documentation

Call `aws-documentation` MCP to read these doc pages for the service (use actual URLs from MCP):
1. Security overview / security guide
2. IAM / how this service works with IAM
3. Data protection / encryption
4. VPC / network configuration
5. Cross-service confused deputy prevention
6. Resource-based policies
7. CloudTrail integration / logging
8. Resilience / disaster recovery

For each page, note URL and key security requirements found. Populate `doc_sources[]`.

## Step 4: Cross-reference — find uncovered parameters

Compare `api_surface.operations[].parameters[]` against `existing_mitigations[].request_parameters[]`.

Parameters not covered by any mitigation = potential gap. For each uncovered parameter:
- Determine if it has security relevance (skip purely functional params like pagination tokens)
- If security-relevant: add to `missing_threats[]` with STRIDE category and priority

When cross-referencing API parameters, also check mitigation `request_parameters` against the cataloged `api_surface`. If a mitigation references a parameter path not present in any cataloged operation, flag it as a potential gap in the api_surface catalog and add the missing parameter.

## Step 5: Identify STRIDE gaps

For each resource asset, work through STRIDE categories:
- **Spoofing**: Is identity verified? Is there auth? Can another account impersonate?
- **Tampering**: Can data be modified in transit or at rest without detection?
- **Repudiation**: Are all actions logged (CloudTrail, CloudWatch)?
- **Information Disclosure**: Can data leak via misconfigured policies or tags?
- **Denial of Service**: Are there availability controls (multi-AZ, quotas)?
- **Elevation of Privilege**: Can roles be assumed beyond their intended scope?

Cross-reference each gap with AWS docs from Step 3. Add to `missing_threats[]` with:
`id` (THREAT-NNN), `asset`, `title`, `stride_category`, `priority` (HIGH/MEDIUM/LOW),
`aws_doc_ref`, `ccmv4_objectives[]`, `suggested_mitigation`.

For each existing mitigation, set `stride_categories[]` based on which STRIDE categories the mitigation addresses.

## Step 6: Map to CCMv4

Open the CCMv4 xlsx file (path noted in Step 1). Read columns: `Control ID`, `Control Title`,
`Control Specification`, `Domain`.

Map EVERY `existing_mitigation` and EVERY `missing_threat`. Do not skip items. Each item must have at least one CCMv4 mapping.

For each item, apply the mapping algorithm:
- "IAM / Identity / Role / Principal" keywords → IAM domain controls (IAM-01 through IAM-09)
- "Encryption / KMS / CMK / at-rest / in-transit" → DSP domain (DSP-01 through DSP-19)
- "Network / VPC / subnet / endpoint / firewall" → IVS domain (IVS-01 through IVS-09)
- "Logging / CloudTrail / CloudWatch / audit" → LOG domain (LOG-01 through LOG-13)
- "Tagging / owner / classification" → GRC domain (GRC-01 through GRC-07)
- "Confused deputy / cross-account / resource policy" → IAM domain
- "Backup / recovery / resilience / multi-AZ" → BCR domain (BCR-01 through BCR-11)

Mapping accuracy rules:
- Encryption/KMS → DSP-17 (Encryption and Key Management), not DSP-03
- Supply chain/artifact integrity → STA-06 (Supply Chain Security Assessment), not IAM-06
- Data integrity/tampering → DSP-10 (Data Integrity), not DSP-07
- Data retention → DSP-07 (Data Retention and Disposal), not GRC-05
- When in doubt, read the CCMv4 Control Specification column — match on specifics, not just domain keywords

Select 1-3 most specific matching Control IDs per item. Set `coverage`: FULL / PARTIAL / SUPPORTS.
Populate `ccmv4_mappings[]`.

For each existing mitigation, set `ccmv4_objectives[]` from the matching `ccmv4_mappings` entry.

## Step 7: Write output

Write `.service-approval/state/research.json` with this schema:

```json
{
  "service": "<service-name>",
  "resources": ["<ResourceType1>", "<ResourceType2>"],
  "assets": [
    {
      "name": "<ResourceName>",
      "cfn_type": "AWS::<Service>::<Resource>",
      "stride_categories": ["Spoofing", "Tampering", "Repudiation", "InformationDisclosure", "ElevationOfPrivilege"]
    }
  ],
  "existing_mitigations": [
    {
      "id": "M-AgentRuntime.0",
      "statement": "...",
      "mitigation_goal": "...",
      "request_parameters": ["..."],
      "resource_type": "AWS::...",
      "stride_categories": ["Spoofing"],
      "ccmv4_objectives": ["IAM-01"]
    }
  ],
  "missing_threats": [
    {
      "id": "THREAT-001",
      "asset": "<ResourceName>",
      "title": "...",
      "stride_category": "Repudiation",
      "priority": "HIGH",
      "aws_doc_ref": "https://docs.aws.amazon.com/...",
      "ccmv4_objectives": ["LOG-01"],
      "suggested_mitigation": "..."
    }
  ],
  "enrichment_opportunities": [
    {
      "id": "ENRICH-001",
      "mitigation_id": "M-AgentRuntime.0",
      "description": "...",
      "aws_doc_ref": "https://docs.aws.amazon.com/...",
      "recommended_action": "..."
    }
  ],
  "api_surface": {
    "operations": [
      {
        "name": "CreateX",
        "http_method": "PUT",
        "path": "/resources/",
        "parameters": [
          { "name": "fieldName", "type": "String", "required": true }
        ],
        "resource_type": "AWS::Service::Resource"
      }
    ]
  },
  "ccmv4_mappings": [
    {
      "mitigation_id": "M-AgentRuntime.0",
      "ccmv4_controls": ["IAM-04", "IAM-09"],
      "coverage": "FULL",
      "rationale": "..."
    }
  ],
  "doc_sources": [
    {
      "url": "https://docs.aws.amazon.com/...",
      "title": "...",
      "topics_covered": ["..."],
      "key_findings": "..."
    }
  ]
}
```

Print summary:
```
Research complete:
  - Existing mitigations: N
  - Missing threats found: N (HIGH: X, MEDIUM: Y, LOW: Z)
  - Enrichment opportunities: N
  - CCMv4 objectives mapped: N
  - API operations analyzed: N
  - Doc sources reviewed: N
  Output: .service-approval/state/research.json
```
