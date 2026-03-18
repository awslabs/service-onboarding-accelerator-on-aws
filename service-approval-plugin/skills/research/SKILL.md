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
- `--service=<name>` — AWS service identifier (e.g., `bedrock-agentcore`)

If both are provided, use input-folder files AND --service name.
If only --service is provided, use MCP-only mode.
If neither is provided, ask the user for a service name before proceeding.

## Step 1: Parse input files

For each file in the input folder:
- `.json` files: attempt to parse as mitigation report (look for `entities` key with mitigation arrays)
- `.md` files: extract mitigation IDs (pattern: `M-<Resource>.<N>`), threats, request parameters
- `.xlsx` files:
  - If filename contains "CCMv4" or "ccmv4" → this is the CCMv4 source — note its path
  - Any other compliance framework file (NIST, PCI-DSS, ISO 27001, SOC2, CIS, internal catalog, etc.) → note its path and framework name
- Other files: read for context

Build an initial list of `existing_mitigations` with fields: `id`, `statement`, `mitigation_goal`,
`request_parameters[]`, `resource_type`.

## Step 2: Fetch live API surface

Call `awsknowledge` MCP to retrieve the API reference for `--service`:
- List all API operations (CreateX, UpdateX, DeleteX, GetX, ListX, TagResource, UntagResource, etc.)
- For each operation, capture: name, HTTP method, path, all request parameters (name, type, required), resource type
- Populate `api_surface.operations[]` in research.json

Log this MCP call to `.service-approval/state/mcp-calls.log`:
```
[TIMESTAMP] [Researcher] MCP CALL: awsknowledge
  service=<name>
  result: <N> operations cataloged
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

For each page, note URL, title, topics covered, and key security requirements found. Populate `doc_sources[]`.

## Step 4: Cross-reference — find uncovered parameters

Compare `api_surface.operations[].parameters[]` against `existing_mitigations[].request_parameters[]`.

Parameters not covered by any mitigation = potential gap. For each uncovered parameter:
- Determine if it has security relevance (skip purely functional params like pagination tokens)
- If security-relevant: add to `missing_threats[]` with STRIDE category and priority

Also check in reverse: if a mitigation references a parameter path not present in any cataloged
operation, flag it as a discrepancy — note the mitigation may reference a deprecated or renamed parameter.

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

For each existing mitigation, set `stride_categories[]` based on which STRIDE categories it addresses.

## Step 6: Map to MITRE ATT&CK for Cloud

For each `existing_mitigation` and each `missing_threat`, assign the closest MITRE ATT&CK technique
using this STRIDE → ATT&CK mapping table. Pick the most specific sub-technique when applicable.

| STRIDE Category | Primary Techniques |
|---|---|
| Spoofing | T1078.004 Valid Accounts: Cloud Accounts, T1606 Forge Web Credentials, T1556 Modify Authentication Process |
| Tampering | T1565 Data Manipulation, T1070 Indicator Removal, T1490 Inhibit System Recovery |
| Repudiation | T1562.008 Impair Defenses: Disable Cloud Logs, T1070.004 File Deletion |
| Information Disclosure | T1530 Data from Cloud Storage, T1552 Unsecured Credentials, T1619 Cloud Storage Object Discovery |
| Denial of Service | T1499 Endpoint Denial of Service, T1496 Resource Hijacking, T1578 Modify Cloud Compute Infrastructure |
| Elevation of Privilege | T1098 Account Manipulation, T1548 Abuse Elevation Control Mechanism, T1484 Domain Policy Modification |

Refine by asset context:
- Data/storage asset + Information Disclosure → prefer T1530
- IAM/role asset + Elevation of Privilege → prefer T1098 or T1548
- Logging/audit asset + Repudiation → prefer T1562.008
- Network/endpoint asset + DoS → prefer T1499

Add `mitre_attack` to each `existing_mitigation` and `missing_threat`:
```json
"mitre_attack": {
  "tactic": "<tactic-name>",
  "technique_id": "<T####.###>",
  "technique_name": "<name>",
  "url": "https://attack.mitre.org/techniques/<T####>/"
}
```

## Step 7: Map to compliance frameworks

### CCMv4 mapping

If a CCMv4 xlsx file was found in Step 1:
- Read ALL rows from it. Extract every `Control ID`, `Control Title`, `Control Specification`, `Domain`
- For each `existing_mitigation` and `missing_threat`, semantically match against the actual
  `Control Specification` text in the file — do NOT use hardcoded keyword lists or ID ranges
- Select the 1-3 controls whose specification text most directly addresses the mitigation/threat
- Set `coverage`: FULL (control fully addressed), PARTIAL (partially addressed), SUPPORTS (relevant but indirect)
- Add a `rationale` explaining why this control was selected
- Populate `ccmv4_mappings[]` using the actual Control IDs read from the file
- For each existing mitigation, set `ccmv4_objectives[]` from its matching `ccmv4_mappings` entries

If NO CCMv4 file was provided:
- Set `ccmv4_mappings: []` and `"ccmv4_note": "No CCMv4 file provided in input — skipped"`
- Do NOT invent or guess control IDs

### Other compliance frameworks

For any other compliance/framework files found in the input folder:
- Read the file and extract its control structure (ID, title, description)
- Semantically map each `existing_mitigation` and `missing_threat` to relevant controls
- Add a top-level key named after the framework (e.g., `nist_mappings[]`, `pci_mappings[]`)
  using the same structure as `ccmv4_mappings[]`
- Never hardcode control IDs for any framework — always derive from the provided file

## Step 8: Write output

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
      "ccmv4_objectives": ["<control-id-from-input-file>"],
      "mitre_attack": {
        "tactic": "Defense Evasion",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/004/"
      }
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
      "ccmv4_objectives": ["<control-id-from-input-file>"],
      "suggested_mitigation": "...",
      "mitre_attack": {
        "tactic": "Defense Evasion",
        "technique_id": "T1562.008",
        "technique_name": "Impair Defenses: Disable Cloud Logs",
        "url": "https://attack.mitre.org/techniques/T1562/008/"
      }
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
      "ccmv4_controls": ["<control-id-from-input-file>"],
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
  - MITRE ATT&CK techniques mapped: N
  - API operations analyzed: N
  - Doc sources reviewed: N
  Output: .service-approval/state/research.json
```

