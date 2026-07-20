---
name: product
description: What service-approval is and who it's for
alwaysApply: true
---

# Service Approval — Product Context

## What it does

Generates a complete set of AWS security controls for any AWS service. Input: a service name plus optional customer docs. Output: a CCMv4-mapped control catalog, 85+ deployable artifacts, and an approval verdict.

## Who uses it

AWS service onboarding reviewers and security engineers. The typical user is running this against a new AWS service request to assess whether it's safe to onboard under their org's compliance framework.

## What problem it solves

Before this tool, generating compliant controls for a new AWS service required 2–4 weeks of manual work: reading Service Authorization Reference pages, cross-referencing CCMv4 objectives, writing SCPs and Config rules by hand, testing deployments. This Power compresses that to hours while enforcing framework coverage and parameter accuracy via MCP verification.

## Non-goals

- Not a deployment tool. It recommends controls + compliant IaC; deploying and testing them against a live account is the customer's responsibility.
- Not a threat model authoring tool. MITRE ATT&CK analysis always runs to identify applicable threats, but the threat model itself (your organization's risk context) is an input, not an output.
- Not a framework authoring tool. Frameworks (CCMv4, NIST 800-53) are inputs; this Power maps to them.

## Success criteria

- Every control traces to at least one framework objective
- Every capability claim is MCP-verified (no hardcoded training-data values)
- Every generated IaC artifact deploys cleanly in dry-run mode
- The final verdict matches the integrity check output (no false APPROVED)
