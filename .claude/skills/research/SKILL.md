---
name: research-v2
description: >
  Comprehensive AWS service security research producing three artifacts:
  (1) controls-catalog.md — all controls categorised as Proactive/Preventive/Detective/Corrective,
  (2) threat-model.md — full threat-mitigation-control mapping,
  (3) ccmv4-mapping.md — CCMv4 control objective mapping.
  Uses MCP servers for AWS documentation, service authorization, whitepapers, best practices,
  blogs, and prescriptive policy.
disable-model-invocation: false
argument-hint: "[./input-folder] [--service=<name>]"
---

# Service Approval — Researcher v2

Analyze the target AWS service to produce three security artifacts:

1. **`controls-catalog.md`** — Complete controls inventory categorised by type
2. **`threat-model.md`** — Threat-mitigation-control mapping document
3. **`ccmv4-mapping.md`** — CCMv4 control objective crosswalk

All outputs are written to `.service-approval/state/`.

---

## Prerequisites

```bash
mkdir -p .service-approval/state
touch .service-approval/state/mcp-calls.log
```

## Inputs

Parse arguments:
- `./input-folder` (optional) — read all `.md`, `.json`, `.xlsx`, `.pdf`, `.docx` files
- `--service=<name>` — AWS service identifier (e.g., `bedrock-agentcore-control`, `s3`, `lambda`)

If both are provided, use input-folder files AND --service name.
If only --service is provided, use MCP-only mode.
If neither is provided, ask the user for a service name before proceeding.

For each file in the input folder:
- `.json` files: parse as mitigation report (look for `entities` key with mitigation arrays)
- `.md` files: extract mitigation IDs (pattern: `M-<Resource>.<N>`), threats, request parameters
- `.xlsx` files: if filename contains "CCMv4" or "ccmv4", note as CCMv4 source
- `.pdf` / `.docx` files: extract security-relevant content (threat models, control descriptions)
- Other files: read for context

Build an initial list of `existing_mitigations` with fields: `id`, `statement`, `mitigation_goal`,
`request_parameters[]`, `resource_type`.

---

## MCP Data Collection

All MCP calls MUST be logged to `.service-approval/state/mcp-calls.log` with format:
```
[TIMESTAMP] <mcp-server>: <action> <params>
```

### Source 1: Service Authorization Reference

Use `aws-documentation` MCP to fetch the IAM service authorization reference:
- Actions table — all API actions with resource types, condition keys, dependent actions
- Condition keys — all service-specific condition keys (e.g., `aws:RequestTag`, `<service>:ResourceTag`)
- Resource types — all resource ARN patterns

This provides the definitive list of what IAM can control for this service.

### Source 2: Security Documentation

Use `aws-documentation` MCP to read these pages (adapt URLs per service):
1. Security overview / security pillar guide
2. Identity and access management / how the service works with IAM
3. Data protection / encryption at rest and in transit
4. VPC / network configuration / PrivateLink
5. Cross-service confused deputy prevention
6. Resource-based policies
7. CloudTrail integration / logging and monitoring
8. Resilience / disaster recovery / multi-AZ
9. Compliance validation
10. Configuration and vulnerability analysis

### Source 3: AWS Prescriptive Guidance & Best Practices

Use `aws-documentation` MCP to search for:
- AWS Security Best Practices for the service
- AWS Well-Architected Framework security pillar guidance
- AWS Prescriptive Guidance patterns for the service
- Any AWS Security Blog posts about the service

### Source 4: AWS Config Rules & Security Hub

Use `aws-documentation` MCP to find:
- AWS Config managed rules applicable to the service
- AWS Security Hub controls/standards that cover the service
- AWS CloudFormation Guard rules for the service

### Source 5: API Surface

Retrieve the full API reference for the service:
- List all API operations (Create, Update, Delete, Get, List, Tag, Untag, etc.)
- For each operation, list all request parameters with types and required flags
- Identify security-relevant parameters (encryption, auth, network, policy, tagging)

---

## Phase 1: Controls Catalog

**Output:** `.service-approval/state/controls-catalog.md`

### 1.1 Identify All Possible Controls

Using data from MCP Sources 1–5, build a comprehensive list of every security control
that can be applied to this service. A "control" is any configurable security mechanism,
policy enforcement, or monitoring capability.

Control sources to enumerate:
- **IAM controls** — identity policies, resource policies, permission boundaries, SCPs, condition keys
- **Encryption controls** — KMS CMK, SSE, TLS enforcement, key rotation
- **Network controls** — VPC, subnets, security groups, NACLs, VPC endpoints, PrivateLink
- **Logging controls** — CloudTrail, CloudWatch, data events, access logging
- **Configuration controls** — AWS Config rules, Security Hub standards, CloudFormation Guard
- **Tagging controls** — tag policies, required tags, PII prevention
- **Availability controls** — multi-AZ, backup, replication, lifecycle policies
- **Access controls** — resource policies, authorizer configs, JWT/OIDC, unauthenticated access prevention
- **AI-specific controls** — guardrails, prompt validation, data poisoning prevention (if applicable)

### 1.2 Control Matrix — Category × Scope

Assign each control a primary **category** (X-axis) and a **scope level** (Y-axis):

**Categories (X-axis):**

| Category | Definition | Examples |
|----------|-----------|----------|
| **Proactive** | Prevents non-compliant resources from being created. Enforced at deployment/provisioning time. | CloudFormation Guard rules, SCP deny policies, AWS Config proactive rules, OPA policies, Checkov checks |
| **Preventive** | Blocks unauthorized actions at runtime. Enforced during API calls. | IAM policies, resource policies, SCPs, VPC security groups, KMS key policies, permission boundaries |
| **Detective** | Identifies non-compliant or suspicious state after the fact. | AWS Config rules (detective mode), Security Hub findings, CloudTrail log analysis, CloudWatch alarms, Access Analyzer findings |
| **Corrective** | Automatically remediates non-compliant state. | SSM Automation runbooks, Lambda remediation functions, Config auto-remediation, EventBridge → Step Functions workflows |

**Scope Levels (Y-axis):**

| Scope | Definition | Examples |
|-------|-----------|----------|
| **Organisation** | Applied across the AWS Organization via management account or delegated admin. Affects all accounts. | SCPs, tag policies, AI opt-out policies, OPA policies, Config Organization rules, Security Hub org enablement |
| **Account** | Applied within a single AWS account. Affects all resources in that account. | IAM policies, permission boundaries, AWS Config account rules, CloudTrail trails, VPC configurations, CloudWatch alarms |
| **Resource** | Applied directly to an individual resource. Affects only that resource. | Resource-based policies, KMS key policies, S3 bucket policies, security group rules, encryption settings, backup configurations |

**Control Matrix:**

| | Proactive | Preventive | Detective | Corrective |
|---|---|---|---|---|
| **Organisation** | Tag policies, OPA org policies, SCP deny (provisioning) | SCPs (runtime deny), AI opt-out policies | Config Org rules, Security Hub org standards, CloudTrail org trail | Config org auto-remediation, org-level SSM runbooks |
| **Account** | Config proactive rules, CloudFormation Guard, Checkov | IAM policies, permission boundaries, VPC security groups | Config account rules, Security Hub account findings, CloudWatch alarms, Access Analyzer | SSM Automation runbooks, Lambda remediation, EventBridge rules |
| **Resource** | CFN Guard per-resource rules, pre-deploy validation | Resource policies, KMS key policies, bucket policies, endpoint policies | Resource-level Config rules, resource-specific CloudWatch alarms | Resource-specific auto-remediation, Step Functions workflows |

Each control MUST be assigned exactly one category AND one scope level.

### 1.3 Write controls-catalog.md

```markdown
# Security Controls Catalog — {service-name}

**Service:** {service-name}
**Date Generated:** {date}
**Total Controls:** {count}
**Resources:** {resource-list}

## Control Matrix Summary

|  | Proactive | Preventive | Detective | Corrective | Total |
|---|---|---|---|---|---|
| **Organisation** | N | N | N | N | N |
| **Account** | N | N | N | N | N |
| **Resource** | N | N | N | N | N |
| **Total** | N | N | N | N | N |

## Organisation-Level Controls

### Proactive

#### {CTRL-ORG-PRO-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control does}
- **Enforcement Point:** {Tag Policy / OPA Org Policy / SCP (provisioning deny)}
- **Implementation:** {how to implement — policy snippet, rule name, or config}
- **Parameters Controlled:** {API parameters this control validates}
- **AWS Doc Reference:** {URL}

[repeat for each organisation proactive control]

### Preventive

#### {CTRL-ORG-PRV-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control does}
- **Enforcement Point:** {SCP / AI Opt-Out Policy / Organization-wide policy}
- **Implementation:** {policy snippet or configuration}
- **Condition Keys:** {relevant IAM condition keys}
- **AWS Doc Reference:** {URL}

[repeat for each organisation preventive control]

### Detective

#### {CTRL-ORG-DET-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control detects}
- **Detection Mechanism:** {Config Org Rule / Security Hub Org Standard / CloudTrail Org Trail}
- **Rule Identifier:** {rule name or control ID, if applicable}
- **Severity:** {CRITICAL / HIGH / MEDIUM / LOW}
- **AWS Doc Reference:** {URL}

[repeat for each organisation detective control]

### Corrective

#### {CTRL-ORG-COR-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Organisation
- **Description:** {what this control remediates}
- **Trigger:** {Config Org Rule / Security Hub / EventBridge}
- **Remediation Mechanism:** {Org-level SSM Runbook / Delegated Admin Lambda}
- **Auto-Remediation:** {Yes/No}
- **AWS Doc Reference:** {URL}

[repeat for each organisation corrective control]

## Account-Level Controls

### Proactive

#### {CTRL-ACC-PRO-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Account
- **Description:** {what this control does}
- **Enforcement Point:** {Config Proactive Rule / CloudFormation Guard / Checkov}
- **Implementation:** {how to implement}
- **Parameters Controlled:** {API parameters this control validates}
- **AWS Doc Reference:** {URL}

[repeat for each account proactive control]

### Preventive

#### {CTRL-ACC-PRV-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Account
- **Description:** {what this control does}
- **Enforcement Point:** {IAM Policy / Permission Boundary / VPC Security Group}
- **Implementation:** {policy snippet or configuration}
- **Condition Keys:** {relevant IAM condition keys}
- **AWS Doc Reference:** {URL}

[repeat for each account preventive control]

### Detective

#### {CTRL-ACC-DET-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Account
- **Description:** {what this control detects}
- **Detection Mechanism:** {Config Rule / Security Hub / CloudWatch Alarm / Access Analyzer}
- **Rule Identifier:** {rule name or control ID, if applicable}
- **Severity:** {CRITICAL / HIGH / MEDIUM / LOW}
- **AWS Doc Reference:** {URL}

[repeat for each account detective control]

### Corrective

#### {CTRL-ACC-COR-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Account
- **Description:** {what this control remediates}
- **Trigger:** {Config Rule / Security Hub / EventBridge / CloudWatch Alarm}
- **Remediation Mechanism:** {SSM Runbook / Lambda / Step Functions}
- **Auto-Remediation:** {Yes/No}
- **AWS Doc Reference:** {URL}

[repeat for each account corrective control]

## Resource-Level Controls

### Proactive

#### {CTRL-RES-PRO-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Resource
- **Description:** {what this control does}
- **Enforcement Point:** {CFN Guard per-resource / Pre-deploy validation}
- **Implementation:** {how to implement}
- **Parameters Controlled:** {API parameters this control validates}
- **AWS Doc Reference:** {URL}

[repeat for each resource proactive control]

### Preventive

#### {CTRL-RES-PRV-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Resource
- **Description:** {what this control does}
- **Enforcement Point:** {Resource Policy / KMS Key Policy / Bucket Policy / Endpoint Policy}
- **Implementation:** {policy snippet or configuration}
- **Condition Keys:** {relevant IAM condition keys}
- **AWS Doc Reference:** {URL}

[repeat for each resource preventive control]

### Detective

#### {CTRL-RES-DET-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Resource
- **Description:** {what this control detects}
- **Detection Mechanism:** {Resource-level Config Rule / Resource-specific CloudWatch Alarm}
- **Rule Identifier:** {rule name or control ID, if applicable}
- **Severity:** {CRITICAL / HIGH / MEDIUM / LOW}
- **AWS Doc Reference:** {URL}

[repeat for each resource detective control]

### Corrective

#### {CTRL-RES-COR-001} — {Control Title}

- **Resource:** {resource-type}
- **Scope:** Resource
- **Description:** {what this control remediates}
- **Trigger:** {Config Rule / CloudWatch Alarm / EventBridge}
- **Remediation Mechanism:** {Resource-specific Lambda / Step Functions workflow}
- **Auto-Remediation:** {Yes/No}
- **AWS Doc Reference:** {URL}

[repeat for each resource corrective control]
```

---

## Phase 2: Threat Model

**Output:** `.service-approval/state/threat-model.md`

### 2.1 Asset Inventory

For each resource type in the service, document:
- Resource name and CloudFormation type
- Data classification (what data does it store/process?)
- Trust boundaries (who/what interacts with it?)
- Entry points (API operations, network interfaces, event triggers)

### 2.2 Threat Identification — MITRE ATT&CK Tactics

For each resource asset, identify threats using MITRE ATT&CK for Cloud tactics as the
primary classification. Analyse the service through each tactic lens:

| ATT&CK Tactic | Tactic ID | Guiding Questions |
|----------------|-----------|-------------------|
| **Initial Access** | TA0001 | Can an attacker gain an initial foothold via misconfigured policies, public endpoints, or stolen credentials? |
| **Execution** | TA0002 | Can an attacker execute code or invoke operations within the service (Lambda, custom runtimes, agent invocations)? |
| **Persistence** | TA0003 | Can an attacker maintain access by creating roles, keys, backdoor policies, or resource-based trust? |
| **Privilege Escalation** | TA0004 | Can an attacker escalate from limited to broader permissions via role chaining, policy manipulation, or confused deputy? |
| **Defense Evasion** | TA0005 | Can an attacker disable logging, modify CloudTrail, remove Config rules, or bypass guardrails? |
| **Credential Access** | TA0006 | Can credentials, tokens, or secrets be extracted from the service (environment variables, metadata, API responses)? |
| **Discovery** | TA0007 | Can an attacker enumerate resources, configurations, tags, or policies to map the environment? |
| **Collection** | TA0009 | Can an attacker gather sensitive data from the service (S3 objects, DB records, model outputs, logs)? |
| **Exfiltration** | TA0010 | Can data be exfiltrated via cross-account access, public endpoints, or misconfigured sharing? |
| **Impact** | TA0040 | Can an attacker destroy data, disrupt availability, or cause financial harm (resource hijacking, DoS)? |

### 2.3 MITRE ATT&CK Technique Mapping

For each threat, assign the closest MITRE ATT&CK for Cloud technique(s):

| ATT&CK Tactic | Primary Techniques |
|----------------|-------------------|
| Initial Access (TA0001) | T1078.004 Valid Accounts: Cloud, T1190 Exploit Public-Facing Application, T1199 Trusted Relationship |
| Execution (TA0002) | T1059.009 Cloud API, T1648 Serverless Execution, T1204 User Execution |
| Persistence (TA0003) | T1098.001 Additional Cloud Credentials, T1136.003 Cloud Account, T1078.004 Valid Accounts: Cloud |
| Privilege Escalation (TA0004) | T1548 Abuse Elevation Control, T1484 Domain Policy Modification, T1098 Account Manipulation |
| Defense Evasion (TA0005) | T1562.008 Impair Defenses: Disable Cloud Logs, T1070 Indicator Removal, T1578 Modify Cloud Compute |
| Credential Access (TA0006) | T1552.005 Cloud Instance Metadata, T1528 Steal Application Access Token, T1606 Forge Web Credentials |
| Discovery (TA0007) | T1619 Cloud Storage Object Discovery, T1580 Cloud Infrastructure Discovery, T1526 Cloud Service Discovery |
| Collection (TA0009) | T1530 Data from Cloud Storage, T1213 Data from Information Repositories, T1119 Automated Collection |
| Exfiltration (TA0010) | T1537 Transfer Data to Cloud Account, T1567 Exfiltration Over Web Service |
| Impact (TA0040) | T1485 Data Destruction, T1499 Endpoint DoS, T1496 Resource Hijacking, T1490 Inhibit System Recovery |

### 2.4 Map Threats → Mitigations → Controls

For each identified threat:
1. Link to existing mitigations from input files (if any)
2. Link to controls from Phase 1 controls-catalog that address this threat
3. Identify gaps where no mitigation or control exists
4. Assign a residual risk rating: CRITICAL / HIGH / MEDIUM / LOW / ACCEPTED

### 2.5 Write threat-model.md

```markdown
# Threat Model — {service-name}

**Service:** {service-name}
**Date Generated:** {date}
**Resources Analyzed:** {count}
**Total Threats Identified:** {count}
**Mitigations Mapped:** {count}
**Controls Mapped:** {count}

## Asset Inventory

### {Resource Name}

- **CloudFormation Type:** {AWS::Service::Resource}
- **Data Classification:** {what data it stores/processes}
- **Trust Boundaries:** {who interacts with it}
- **Entry Points:** {API operations, network interfaces}

[repeat for each resource]

## Threat Register

### {THREAT-001} — {Threat Title}

- **Asset:** {resource name}
- **MITRE ATT&CK Tactic:** {tactic name} ({tactic ID})
- **MITRE ATT&CK Technique:** {technique-id} — {technique-name} ([link])
- **Description:** {detailed threat description}
- **Attack Vector:** {how this threat could be exploited}
- **Likelihood:** {HIGH / MEDIUM / LOW}
- **Impact:** {HIGH / MEDIUM / LOW}
- **Risk Rating:** {CRITICAL / HIGH / MEDIUM / LOW}

**Existing Mitigations:**

| Mitigation ID | Statement | Coverage |
|--------------|-----------|----------|
| {M-Resource.N} | {statement} | {FULL / PARTIAL} |

**Mapped Controls:**

| Control ID | Control Title | Category | Scope | Effectiveness |
|-----------|--------------|----------|-------|---------------|
| {CTRL-ACC-PRV-001} | {title} | Preventive | Account | {HIGH / MEDIUM / LOW} |

**Gaps:** {description of any remaining gaps}
**Residual Risk:** {CRITICAL / HIGH / MEDIUM / LOW / ACCEPTED}
**Recommended Actions:** {what should be done to close gaps}

---

[repeat for each threat]

## Risk Summary Matrix

| Risk Rating | Count | Threats |
|------------|-------|---------|
| CRITICAL | N | THREAT-xxx, ... |
| HIGH | N | THREAT-xxx, ... |
| MEDIUM | N | THREAT-xxx, ... |
| LOW | N | THREAT-xxx, ... |
| ACCEPTED | N | THREAT-xxx, ... |

## Threat-Mitigation-Control Traceability Matrix

| Threat ID | ATT&CK Tactic | ATT&CK Technique | Mitigation IDs | Control IDs | Residual Risk |
|-----------|---------------|-------------------|---------------|-------------|---------------|
| THREAT-001 | Initial Access (TA0001) | T1078.004 | M-Resource.0, M-Resource.1 | CTRL-ACC-PRV-001, CTRL-ACC-DET-003 | LOW |
[repeat for all threats]
```

---

## Phase 3: CCMv4 Mapping

**Output:** `.service-approval/state/ccmv4-mapping.md`

### 3.1 CCMv4 Domain Reference

Use the following valid CCMv4 domains and control ID ranges. NEVER invent control IDs.

| Prefix | Domain Name | Range |
|--------|-------------|-------|
| AIS | AI Security | AIS-01 to AIS-06 |
| A&A | Audit & Assurance | A&A-01 to A&A-06 |
| BCR | Business Continuity Management & Operational Resilience | BCR-01 to BCR-11 |
| CCC | Change Control & Configuration Management | CCC-01 to CCC-09 |
| CEK | Cryptography, Encryption & Key Management | CEK-01 to CEK-21 |
| DCS | Datacenter Security | DCS-01 to DCS-15 |
| DSP | Data Security & Privacy Lifecycle Management | DSP-01 to DSP-19 |
| GRC | Governance, Risk & Compliance | GRC-01 to GRC-08 |
| HRS | Human Resources | HRS-01 to HRS-13 |
| IAM | Identity & Access Management | IAM-01 to IAM-16 |
| IPY | Interoperability & Portability | IPY-01 to IPY-04 |
| IVS | Infrastructure & Virtualization Security | IVS-01 to IVS-09 |
| LOG | Logging & Monitoring | LOG-01 to LOG-13 |
| SEF | Security Incident Management & Forensics | SEF-01 to SEF-08 |
| STA | Supply Chain Management & Accountability | STA-01 to STA-14 |
| TVM | Threat & Vulnerability Management | TVM-01 to TVM-10 |
| UEM | Universal Endpoint Management | UEM-01 to UEM-15 |

### 3.2 Mapping Algorithm

The primary index is the **CCMv4 control ID**, not the service control. Iterate over every
CCMv4 control ID in every domain defined in Phase 3.1 (197 total). For each CCMv4 ID:

1. **Search Phase 1 controls-catalog** for service controls that align with this CCMv4 objective.
   Use keyword matching to identify candidates:
   - Access/Identity/Role/Principal/Auth → IAM
   - Encryption/KMS/CMK/TLS/Certificate → CEK
   - Network/VPC/Subnet/Endpoint/Firewall/PrivateLink → IVS
   - Logging/CloudTrail/CloudWatch/Audit → LOG
   - Tagging/Owner/Classification/Governance → GRC
   - Config Rule/Security Hub/Compliance → A&A
   - Backup/Recovery/Resilience/Multi-AZ → BCR
   - Change/Configuration/Baseline/Drift → CCC
   - Vulnerability/Patch/Scan/Pen-test → TVM
   - Incident/Forensics/Response → SEF
   - Supply Chain/Third-party/Vendor → STA
   - AI/ML/Model/Guardrail/Prompt → AIS
   - Data/Privacy/PII/Classification/Retention → DSP

2. **If one or more controls match**, produce a mapping table entry for each with:
   - **Confidence:** High (direct alignment), Medium (partial overlap), Low (tangential)
   - **Coverage:** FULL (fully satisfies), PARTIAL (partially addresses), SUPPORTS (contributes to)

3. **If no controls match**, mark the CCMv4 ID as:
   - **N/A — {reason}** (e.g., "Managed by AWS under shared responsibility", "Organisational HR control outside service scope", "No endpoint agents — cloud-native service")

Every CCMv4 ID in the domain reference MUST appear in the output — either with a mapping table or an N/A status.

### 3.3 Write ccmv4-mapping.md

```markdown
# CCMv4 Control Mapping — {service-name}

**Source:** {service-name} Controls Catalog + Threat Model
**Date Generated:** {date}
**Total Service Controls:** {count from Phase 1}
**CCMv4 IDs Total:** 197
**CCMv4 IDs Mapped:** {count with at least one control}
**CCMv4 IDs N/A:** {count marked N/A}
**CCMv4 Domains Covered:** {count with ≥1 mapped ID} / 17

## Domain Coverage Summary

| CCMv4 Domain | IDs in Domain | IDs Mapped | IDs N/A | Coverage Level | Notes |
|---|---|---|---|---|---|
| AIS — AI Security | 6 | N | N | High/Medium/Low/None | {brief note} |
| A&A — Audit & Assurance | 6 | N | N | ... | ... |
| BCR — Business Continuity & Operational Resilience | 11 | N | N | ... | ... |
| CCC — Change Control & Configuration Management | 9 | N | N | ... | ... |
| CEK — Cryptography, Encryption & Key Management | 21 | N | N | ... | ... |
| DCS — Datacenter Security | 15 | N | N | N/A (managed service) | ... |
| DSP — Data Security & Privacy Lifecycle Management | 19 | N | N | ... | ... |
| GRC — Governance, Risk & Compliance | 8 | N | N | ... | ... |
| HRS — Human Resources | 13 | N | N | N/A (organizational) | ... |
| IAM — Identity & Access Management | 16 | N | N | ... | ... |
| IPY — Interoperability & Portability | 4 | N | N | ... | ... |
| IVS — Infrastructure & Virtualization Security | 9 | N | N | ... | ... |
| LOG — Logging & Monitoring | 13 | N | N | ... | ... |
| SEF — Security Incident Management & Forensics | 8 | N | N | ... | ... |
| STA — Supply Chain Management & Accountability | 14 | N | N | ... | ... |
| TVM — Threat & Vulnerability Management | 10 | N | N | ... | ... |
| UEM — Universal Endpoint Management | 15 | N | N | N/A (cloud-native) | ... |

## Detailed Mappings by Domain

### {Domain Name} ({Prefix}-01 to {Prefix}-NN)

#### {CCMv4-ID} — {CCMv4 Control Title}

<!-- IF mapped controls exist: -->
**Mapped Controls:**

| Control ID | Control Title | Category | Scope | Confidence | Coverage | Rationale |
|---|---|---|---|---|---|---|
| {CTRL-xxx-NNN} | {title} | {Proactive/Preventive/Detective/Corrective} | {Organisation/Account/Resource} | {High/Medium/Low} | {FULL/PARTIAL/SUPPORTS} | {specific rationale} |

<!-- IF no mapped controls: -->
**Status:** N/A — {reason why this CCMv4 objective does not apply to this service}

<!-- EVERY ID from {Prefix}-01 to {Prefix}-NN must appear -->

---

[repeat for each domain, listing ALL IDs in the domain range]

## Unmapped Service Controls

| Control ID | Control Title | Reason |
|---|---|---|
| {CTRL-xxx-NNN} | {title} | {why no CCMv4 mapping exists} |

## CCMv4 Coverage Gaps

| CCMv4 Domain | Gap Description | Recommendation |
|---|---|---|
| {domain} | {what is not covered} | {what should be done} |

## Cross-Reference: Threats → CCMv4

| Threat ID | Threat Title | CCMv4 Controls | Gap? |
|---|---|---|---|
| THREAT-001 | {title} | IAM-01, IAM-05 | No |
| THREAT-002 | {title} | LOG-01 | Yes — LOG-07 partial |
[repeat for all threats]
```

---

## Phase 4: Write research.json (Structured State)

In addition to the three markdown artifacts, write `.service-approval/state/research.json`
as the machine-readable state file consumed by downstream skills (validator, generator, etc.).

```json
{
  "service": "<service-name>",
  "resources": ["<ResourceType1>", "<ResourceType2>"],
  "assets": [
    {
      "name": "<ResourceName>",
      "cfn_type": "AWS::<Service>::<Resource>",
      "data_classification": "<what data it stores/processes>",
      "trust_boundaries": ["<who interacts>"],
      "entry_points": ["<API operations>"]
    }
  ],
  "controls": [
    {
      "id": "CTRL-ORG-PRO-001",
      "title": "...",
      "category": "Proactive|Preventive|Detective|Corrective",
      "scope": "Organisation|Account|Resource",
      "resource_type": "AWS::...",
      "description": "...",
      "enforcement_point": "...",
      "parameters_controlled": ["..."],
      "aws_doc_ref": "https://docs.aws.amazon.com/..."
    }
  ],
  "existing_mitigations": [
    {
      "id": "M-Resource.0",
      "statement": "...",
      "mitigation_goal": "...",
      "request_parameters": ["..."],
      "resource_type": "AWS::...",
      "threat_categories": ["Initial Access"],
      "mitre_attack_tactic": "Initial Access (TA0001)",
      "ccmv4_objectives": ["IAM-01"],
      "mapped_controls": ["CTRL-ACC-PRV-001"],
      "mitre_attack": {
        "tactic": "...",
        "technique_id": "T####.###",
        "technique_name": "...",
        "url": "https://attack.mitre.org/techniques/T####/"
      }
    }
  ],
  "threats": [
    {
      "id": "THREAT-001",
      "asset": "<ResourceName>",
      "title": "...",
      "mitre_tactic": "Initial Access (TA0001)",
      "mitre_tactic_id": "TA0001",
      "description": "...",
      "attack_vector": "...",
      "likelihood": "HIGH|MEDIUM|LOW",
      "impact": "HIGH|MEDIUM|LOW",
      "risk_rating": "CRITICAL|HIGH|MEDIUM|LOW",
      "mitre_attack": { "...": "..." },
      "existing_mitigations": ["M-Resource.0"],
      "mapped_controls": ["CTRL-ACC-PRV-001", "CTRL-ACC-DET-003"],
      "gaps": "...",
      "residual_risk": "HIGH|MEDIUM|LOW|ACCEPTED",
      "ccmv4_objectives": ["IAM-01"],
      "aws_doc_ref": "https://docs.aws.amazon.com/...",
      "suggested_mitigation": "..."
    }
  ],
  "enrichment_opportunities": [
    {
      "mitigation_id": "M-Resource.0",
      "current_gap": "...",
      "enhancement": "...",
      "aws_doc_ref": "https://docs.aws.amazon.com/...",
      "priority": "HIGH|MEDIUM|LOW"
    }
  ],
  "api_surface": {
    "operations": [
      {
        "operation": "CreateX",
        "parameters": [
          { "path": "$.fieldName", "type": "string", "required": true }
        ]
      }
    ]
  },
  "ccmv4_mappings": [
    {
      "control_id": "CTRL-ACC-PRV-001",
      "ccmv4_control_id": "IAM-01",
      "ccmv4_control_title": "...",
      "domain": "Identity & Access Management",
      "confidence": "High|Medium|Low",
      "coverage": "FULL|PARTIAL|SUPPORTS",
      "rationale": "..."
    }
  ],
  "doc_sources": ["https://docs.aws.amazon.com/..."]
}
```

---

## Execution Order

Execute phases in this strict order:

```
1. Parse inputs (input folder + --service arg)
2. MCP data collection (Sources 1–5, log all calls)
3. Phase 1 → write .service-approval/state/controls-catalog.md
4. Phase 2 → write .service-approval/state/threat-model.md
5. Phase 3 → write .service-approval/state/ccmv4-mapping.md
6. Phase 4 → write .service-approval/state/research.json
```

Each phase builds on the previous. Do NOT skip phases or write outputs out of order.

## Output Verification

After all phases complete, verify:

- [ ] `.service-approval/state/controls-catalog.md` exists and contains controls organised by Scope (Organisation/Account/Resource) × Category (Proactive/Preventive/Detective/Corrective) matrix
- [ ] `.service-approval/state/threat-model.md` exists and contains MITRE ATT&CK tactic-based threat analysis + traceability matrix
- [ ] `.service-approval/state/ccmv4-mapping.md` exists and contains domain coverage summary + detailed mappings
- [ ] `.service-approval/state/research.json` exists and is valid JSON with all required top-level keys
- [ ] `.service-approval/state/mcp-calls.log` contains timestamped entries for all MCP calls made
- [ ] All CCMv4 control IDs used are valid (see Phase 3 domain reference table)
- [ ] No control is left uncategorised or without a scope level in controls-catalog.md
- [ ] Every threat in threat-model.md has a MITRE ATT&CK tactic and technique assignment
- [ ] Every threat in threat-model.md links to at least one control or documents a gap
- [ ] All controls have a source documentation link
- [ ] Validate that all information is accurate based on knowledge and resources used and that no information has been left out 

## Print Summary

```
Research v2 complete:
  Artifacts:
    - controls-catalog.md    ({N} controls — matrix: {O} org, {A} account, {R} resource × {P} proactive, {V} preventive, {D} detective, {C} corrective)
    - threat-model.md        ({N} threats across {T} MITRE ATT&CK tactics: {CR} critical, {H} high, {M} medium, {L} low)
    - ccmv4-mapping.md       ({N} mappings across {D}/17 CCMv4 domains)
    - research.json          (structured state for downstream skills)
  Stats:
    - Existing mitigations:  {N}
    - Controls identified:   {N} (Org: {O}, Account: {A}, Resource: {R})
    - Threats identified:    {N}
    - MITRE ATT&CK tactics:  {N} / 10
    - MITRE ATT&CK techniques: {N}
    - CCMv4 controls mapped: {N}
    - API operations:        {N}
    - MCP calls made:        {N}
    - Doc sources reviewed:  {N}
  Output: .service-approval/state/
```
