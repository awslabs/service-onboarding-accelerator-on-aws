# Service Approval — Safety Rules

These rules apply across all clients and all agents.

## Deployment & Teardown (customer responsibility)
- This pipeline produces recommended security controls; it does not deploy, test, or
  tear down resources against a live AWS account. Applying the generated artifacts —
  and removing them afterward — is the customer's responsibility.
- The generated control artifacts are what the customer reviews and applies
  in their own account through their own change process; no agent in this pipeline
  assumes an AWS profile or mutates account state.

## State Safety
- Always write state to `.service-approval/<slug>/<phase>/` relative to the current working directory.
- Never overwrite existing `research.json` or `validated.json` without user confirmation.
- State files from previous runs are preserved unless `--clean` flag is passed.

## Generation Safety
- Never generate controls for items with `verified: false` unless `--include-unverified` is passed.
- All generated JSON policy files must be validated with `python3 -m json.tool <file>` before use.
- For IAM policy files (SCP, RCP, permission boundaries), additionally validate with
  `aws iam validate-policy --policy-document file://<file> --policy-type SERVICE_CONTROL_POLICY`
  where applicable.
- Generated SCPs must include a Deny statement — never generate Allow-only SCPs as the only control.

## MCP Safety
- All API parameters, condition keys, and Config rule names must be sourced from MCP — never
  from model training data.
- Log every MCP call to `.service-approval/<slug>/mcp-calls.log`.
