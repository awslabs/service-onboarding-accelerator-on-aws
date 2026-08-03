# Service Approval — Web Access Policy (No-MCP mode)

These rules apply **only in No-MCP mode** — when the run sets
`pipeline_flags.no_mcp == true` in `00-intake/intake-manifest.json` (via the
`--no-mcp` flag). MCP is the default; this policy is the fallback path, not a
replacement.

In No-MCP mode, a skill that needs documentation or schema data that lives
outside this repo fetches it over the web instead of calling MCP. Web access is
restricted to the allowlist below — no fall-through to general web search.

## Allowlisted Domains

| Domain | Used by |
|---|---|
| `docs.aws.amazon.com` | assess, validate, research-*, generate-* |
| `docs.aws.amazon.com/service-authorization/latest/reference` | validate, research-api-surface (condition keys / actions / resources) |
| `docs.aws.amazon.com/access-analyzer/latest/APIReference` | validate (SCP/RCP/permission-boundary feasibility) |
| `attack.mitre.org/matrices/enterprise/` | research-attack-surface |

Anything outside this list — block the call, emit a `web:blocked:fetch` event
to `pipeline.log`, and fall back to the source's bundled snapshot if one exists.

## Tool selection

- **`WebSearch`** — discovery. Use only when the URL is unknown. Always set
  `allowed_domains` to the SINGLE domain row from the table above.
- **`WebFetch`** — read a known URL. The default.

Never use general `WebSearch` without `allowed_domains` set, and never use
`WebFetch` on a URL outside the allowlist.

## Per-source patterns

### AWS Documentation

Service Authorization Reference (condition keys, actions, resources) — the
no-MCP equivalent of `awsknowledge` / `aws-documentation` SAR lookups:
- `WebFetch` URL: `https://docs.aws.amazon.com/service-authorization/latest/reference/list_<service>.html`
- Prompt: "Extract the condition keys table. For each row, return: key name, description, type, and the actions it applies to. Then extract the actions table (action, access level, resource types, condition keys)."

Service-specific user guides / API references — start with `WebSearch`:
- `WebSearch` query: `<service> <feature>`
- `allowed_domains: ["docs.aws.amazon.com"]`

### IAM Access Analyzer API

Policy validation feasibility checks:
- `WebFetch` URL: `https://docs.aws.amazon.com/access-analyzer/latest/APIReference/Welcome.html`
- Prompt: "Find the API operation that <validates / checks / simulates> X."

Plus direct API calls (already a deployment-safety prereq in
`rules/service-approval-safety.md`):
- `aws accessanalyzer validate-policy --policy-document file://<file> ...`

### MITRE ATT&CK

Top-level matrix — the no-MCP equivalent of the `mitre-attack` MCP:
- `WebFetch` URL: `https://attack.mitre.org/matrices/enterprise/`
- Prompt: "List tactics with their TA-IDs, then for each tactic list the technique IDs and names."

Per-technique detail:
- `WebFetch` URL: `https://attack.mitre.org/techniques/T<id>/`
- Prompt: "Return the technique description, sub-techniques (with IDs), detection guidance, and mitigations."

When `attack.mitre.org` is unreachable, fall back to
`data/attack-cloud-matrix.json` (bundled snapshot, ATT&CK 16.1). This snapshot
ships in the repo, so research-attack-surface always works offline.

## Logging

Every `WebFetch` / `WebSearch` call MUST emit a canonical event to `pipeline.log`:

```bash
python3 -m tools.validate.log \
    --slug <slug> \
    --phase <NN-name> \
    --source web:<source-key> \
    --verdict fetch \
    --message "<URL or query>: <one-line description>"
```

Use `--verdict search` instead of `fetch` for `WebSearch` invocations.

Source-key values: `aws-docs`, `access-analyzer`, `attack-mitre`.

The Stop-hook P1 check counts these `web:*:fetch` and `web:*:search` events
against the same minimum-call floor that MCP calls satisfy in the default mode.
Skip logging and the run fails P1.
