# Shared report-writing rules

These rules apply to customer-facing assessment, verification, and summary
prose on every client. Keep raw tool identifiers and execution diagnostics in
the audit logs; preserve the canonical `mcp:<server>:call` log format.

## Terminology

| Internal expression | Customer-facing wording |
|---------------------|-------------------------|
| `mcp__awsknowledge__aws___*`, `mcp__aws-documentation__*`, `gateway_aws-documentation-mcp___*` | AWS Documentation, with the actual source URL |
| Pre-researched findings | Findings, with their evidence |
| TOOL FAILURE GUARD, MCP session error, tool unavailable | Describe which evidence could not be verified |
| Agent/skill/synthesizer implementation details | Describe the service capability, control, or finding |

Remove editorial instructions such as “As a synthesizer”, “Direction should be”,
“Note to reviewer”, “Editorial note”, and “Internal note”. Preserve the substance:
unverified claims remain explicitly unverified, and unresolved questions remain
visible. Never replace missing evidence with an assertion that it was verified.

## Questionnaire answer direction

When the Assess skill requires a prefixed answer, start with one of `Yes`, `No`,
`Not found`, `Yes, partially`, or `This is`, supported by the evidence.
Normalize “Partially” to “Yes, partially”; remove stuttered directions.
Rewrite “No, partially” or “No with a nuance” as a clear negative answer plus
the supported qualification. Use “Not found” when evidence is missing, rather
than converting an unsuccessful search into “No”.

## Scope

The phase skill defines the report structure, source precedence, and domain
precision requirements. Follow those alongside these shared writing rules.
Do not remove source citations, threat/control identifiers, or companion-document
links needed for traceability. Machine-readable state retains its required schema
and identifiers; sanitize prose/tool-name strings only where its skill requires it.
