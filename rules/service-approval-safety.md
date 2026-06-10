# Service Approval — Safety Rules

These rules apply across all clients and all agents.

## State Safety
- Always write state to `.service-approval/<slug>/<phase>/` relative to the current working directory.
- Never overwrite existing `research.json` or `validated.json` without user confirmation.
- State files from previous runs are preserved unless `--clean` flag is passed.

## MCP Safety
- All API parameters, condition keys, and Config rule names must be sourced from MCP — never
  from model training data.
- Log every MCP call to `.service-approval/<slug>/mcp-calls.log`.
