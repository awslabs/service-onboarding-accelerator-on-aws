---
name: research-attack-surface
description: Identify applicable MITRE ATT&CK Cloud techniques for the target service based on API surface analysis and customer STRIDE-based threat model. Produces research-attack-surface.json consumed by the research merge step.
disable-model-invocation: false
argument-hint: '[--service=<name>]'
---

# Service Approval — Research: ATT&CK Attack Surface

Identify which MITRE ATT&CK Cloud techniques are applicable to the target AWS service.
Uses the service's API surface, capabilities, and (when available) customer STRIDE-based
threat model to produce a prioritized list of attack techniques.

**Input:** SAR facts, customer threat model (optional), reference data
**Output:** `.service-approval/state/research-attack-surface.json`

This is one of 4 focused research sub-skills. Each writes to a separate intermediate
state file. This sub-skill is **optional** — the pipeline works without it, but when
present it enriches controls with threat-based traceability.

---

## Prerequisites

```bash
mkdir -p .service-approval/state
```

Load reference data:
```bash
test -f data/attack-cloud-matrix.json && echo "attack-matrix: OK" || echo "ERROR"
test -f data/stride-to-attack-bridge.json && echo "stride-bridge: OK" || echo "ERROR"
test -f data/attack-nist-ccm-crosswalk.json && echo "crosswalk: OK" || echo "ERROR"
```

If SAR facts exist from Phase 0, load them:
```bash
test -f .service-approval/state/sar-facts.json && echo "sar-facts: OK" || echo "sar-facts: not found (will use --service flag)"
```

---

## Step 1: Parse Customer STRIDE Threat Model (if provided)

Scan input files for STRIDE threat model content. Look for:
- Files with "threat" in the filename
- Files containing STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Mitigation reports that reference threat categories

For each STRIDE category found, extract:
- Which mitigations reference it (by mitigation ID if available, or by keyword)
- Indicator phrases that signal this threat type

Build `customer_stride_profile`:
```json
{
  "Spoofing": {
    "mitigations_referenced": ["M-AgentRuntime.0", "M-AgentRuntime.9"],
    "indicators": ["confused deputy", "role assumption", "principal trust"]
  }
}
```

**If no customer threat model exists**, leave `customer_stride_profile` empty `{}`.
The auto-derivation in Step 2 still runs.

---

## Step 2: Auto-Derive Attack Surface from Service API

This step always runs, regardless of whether a customer threat model exists.

### 2.1 Load reference data

```python
import json

cloud_matrix = json.load(open('data/attack-cloud-matrix.json'))
stride_bridge = json.load(open('data/stride-to-attack-bridge.json'))
crosswalk = json.load(open('data/attack-nist-ccm-crosswalk.json'))
```

### 2.2 Analyze service API patterns

If SAR facts exist, extract API operations. Otherwise use the `--service` flag to
identify the service. Map API action patterns to ATT&CK techniques:

| API Action Pattern | ATT&CK Technique | Confidence | Rationale |
|---|---|---|---|
| `Create*` with IAM role parameter | T1078.004 (Cloud Accounts) | HIGH | Service uses assumable roles — credential compromise enables access |
| `PutResourcePolicy`, `SetResourcePolicy` | T1098 (Account Manipulation) | HIGH | Resource policies can be modified to grant unauthorized access |
| `Delete*` any resource | T1485 (Data Destruction) | MEDIUM | Resources can be deleted to disrupt service |
| Data-plane `Invoke*`, `Get*` on user content | T1530 (Data from Cloud Storage) | HIGH if no auth required, MEDIUM if auth required | Data-plane reads expose customer content |
| Encryption parameter is optional (not required) | T1530 (Data from Cloud Storage) | HIGH | Unencrypted data is exposed at rest |
| Public endpoint available (no VPC-only mode) | T1190 (Exploit Public-Facing App) | MEDIUM | Public endpoints are attack surface |
| VPC mode optional | T1190 (Exploit Public-Facing App) | MEDIUM | Network perimeter not enforced |
| `Tag*`, `Untag*` operations | T1565 (Data Manipulation) | LOW | Tag manipulation enables classification evasion |
| Cross-account role trust | T1199 (Trusted Relationship) | HIGH | Cross-account trust enables lateral movement |
| `*CredentialProvider*`, `*Token*` operations | T1528 (Steal Application Access Token) | HIGH | Credential material in the service |
| `*WorkloadIdentity*`, `*OAuth*` operations | T1556 (Modify Authentication Process) | MEDIUM | Authentication config can be tampered with |
| Streaming/logging to external services | T1537 (Transfer Data to Cloud Account) | MEDIUM | Data channels can be redirected |

### 2.3 Cross-reference with STRIDE bridge

For each identified technique, check if the corresponding STRIDE category appears in
the customer profile. If yes, boost confidence by one level (MEDIUM→HIGH, LOW→MEDIUM).

### 2.4 Build applicable techniques list

For each technique, calculate applicability:
- **HIGH**: Direct API pattern match + customer STRIDE alignment
- **MEDIUM**: Direct API pattern match without STRIDE data, OR indirect pattern
- **LOW**: Tangential relevance (generic cloud risk, not service-specific)

**Filter**: Only include techniques with MEDIUM or HIGH applicability. Discard LOW.
Target: 15-25 applicable techniques per service. If >30, raise the threshold.

---

## Step 3: Build STRIDE-to-ATT&CK Bridge Entries

Using `stride-to-attack-bridge.json`, for each STRIDE category in the customer profile
(or all 6 if no customer profile):

```json
{
  "stride_category": "Spoofing",
  "mitigations_referenced": ["M-AgentRuntime.0"],
  "attack_tactics": ["TA0001", "TA0006"],
  "attack_techniques": ["T1078", "T1078.004", "T1199"]
}
```

Only include techniques from the bridge that are also in the applicable_techniques list.

---

## Step 4: Build Tactic Coverage Summary

Group applicable techniques by ATT&CK tactic:

```json
{
  "TA0001": {
    "name": "Initial Access",
    "technique_count": 3,
    "applicability_high": 2,
    "applicability_medium": 1,
    "techniques": ["T1078.004", "T1190", "T1199"]
  }
}
```

---

## Step 5: Write Output

Write `.service-approval/state/research-attack-surface.json`:

```json
{
  "phase": "research-attack-surface",
  "schema_version": "1.0",
  "service": "<service-name>",
  "attack_matrix_version": "16.1",
  "customer_stride_profile": {
    "Spoofing": {
      "mitigations_referenced": ["M-AgentRuntime.0"],
      "indicators": ["confused deputy", "role assumption"]
    }
  },
  "stride_to_attack_bridge": [
    {
      "stride_category": "Spoofing",
      "mitigations_referenced": ["M-AgentRuntime.0"],
      "attack_tactics": ["TA0001", "TA0006"],
      "attack_techniques": ["T1078", "T1078.004"]
    }
  ],
  "applicable_techniques": [
    {
      "technique_id": "T1078.004",
      "technique_name": "Cloud Accounts",
      "tactic_id": "TA0001",
      "tactic_name": "Initial Access",
      "applicability": "HIGH",
      "applicability_reason": "Service uses IAM roles for agent execution (CreateAgentRuntime $.roleArn). Confused deputy prevention required.",
      "api_surface_evidence": ["CreateAgentRuntime", "UpdateAgentRuntime"],
      "stride_categories": ["Spoofing", "Elevation of Privilege"],
      "nist_controls": ["AC-2", "AC-3", "AC-6", "IA-2", "IA-5", "IA-8"],
      "ccmv4_objectives": ["IAM-01", "IAM-02", "IAM-03", "IAM-04", "IAM-05", "IAM-06", "IAM-12"]
    }
  ],
  "tactic_coverage_summary": {
    "TA0001": {
      "name": "Initial Access",
      "technique_count": 3,
      "applicability_high": 2,
      "applicability_medium": 1,
      "techniques": ["T1078.004", "T1190", "T1199"]
    }
  }
}
```

**Schema rules:**
- `phase` MUST be `"research-attack-surface"`
- `applicable_techniques` MUST be a non-empty array
- Every technique MUST have: `technique_id`, `technique_name`, `tactic_id`, `tactic_name`, `applicability`, `applicability_reason`, `api_surface_evidence`
- `technique_id` MUST match pattern `T\d{4}(\.\d{3})?`
- `applicability` MUST be `"HIGH"` or `"MEDIUM"` (LOW is filtered out)
- `nist_controls` and `ccmv4_objectives` come from `attack-nist-ccm-crosswalk.json`
- `stride_categories` lists which STRIDE categories this technique maps to (from bridge)

---

## Validate Output

Output validation runs automatically via PostToolUse hook (validate_state.py Check S14).

## Print Summary

```
Research (ATT&CK Attack Surface) complete:
  Service: {service-name}
  ATT&CK matrix version: {version}
  Customer STRIDE profile: {N categories found | none}
  Applicable techniques: {N} (HIGH: {N}, MEDIUM: {N})
  Tactics covered: {N}/{total ATT&CK Cloud tactics}
  STRIDE bridge entries: {N}
  Output: .service-approval/state/research-attack-surface.json
```
