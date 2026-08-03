# Service Approval — Web Access Policy (No-MCP mode)

These rules apply **only in No-MCP mode** — when the run sets
`pipeline_flags.no_mcp == true` in `00-intake/intake-manifest.json` (via the
`--no-mcp` flag). MCP is the default; this policy is the fallback path, not a
replacement.

In No-MCP mode, a skill that needs documentation or schema data that lives
outside this repo reaches it over the web instead of calling MCP. The
`awsknowledge` / `aws-documentation` MCPs work in two steps internally: they
**search broadly** to locate the right page, then **return the authoritative
content** of that page. No-MCP mode mirrors that with a two-tier model.

## Two-tier model: open discovery, restricted fetch/cite

1. **Discovery is open.** `WebSearch` MAY run **without** `allowed_domains` — a
   free natural-language query whose only job is to *find* the right AWS page.
   This is the discovery step the MCPs perform internally. Read the result list
   as hints; do not treat any result as a fact.
2. **Reading is restricted.** `WebFetch` MAY only retrieve a URL whose host is on
   the **verified-AWS allowlist** below. A search hit that points off-allowlist
   is a discovery hint only — find the authoritative AWS page for the same fact
   and fetch THAT.
3. **Citing is narrow.** Artifact citations (`_metadata.citation.url`) stay on
   `docs.aws.amazon.com` (the Checkov policy-index host is the one non-AWS
   exception the P12 validator already allows). A fact discovered on an AWS blog
   or in an SDK reference must be confirmed on the authoritative
   `docs.aws.amazon.com` page before it is cited there. Repo-anchor citations
   (`github.com/{aws-samples,awslabs,...}`) resolve via
   `data/reference-repos/index.yaml`, not a URL regex.

Net effect: no-MCP mode can *examine all verified AWS sources* freely (open
discovery), while the "facts and citations come only from authoritative AWS
sources" guarantee is preserved. If no AWS-owned source confirms a fact, the
fact is **unverified** — same discipline as the MCP path.

## Verified-AWS allowlist (WebFetch)

AWS-owned / AWS-operated documentation and reference hosts only. `WebFetch`'s
host MUST match one of these entries (or `attack.mitre.org`).

| Domain | What it's for |
|---|---|
| `docs.aws.amazon.com` | Service docs, SAR, API refs, Config managed rules, dev guides — **the only citable AWS host** |
| `docs.aws.amazon.com/service-authorization/latest/reference` | Condition keys / actions / resources (SAR) |
| `docs.aws.amazon.com/access-analyzer/latest/APIReference` | SCP/RCP/permission-boundary feasibility |
| `aws.amazon.com` | Service/feature pages, `/blogs/`, FAQs, what's-new (discovery + read; re-confirm on docs before citing) |
| `api.aws`, `knowledge-mcp.global.api.aws` | Public AWS knowledge surfaces |
| `boto3.amazonaws.com` | boto3 API reference — cross-check API params/shapes |
| `awscli.amazonaws.com` | AWS CLI reference |
| `github.com/aws-samples`, `github.com/awslabs`, `github.com/aws-cloudformation`, `github.com/aws-actions` | AWS-owned sample/reference repos (the anchor source for reference-repo citations) |
| `attack.mitre.org/matrices/enterprise/` (+ `/techniques/`) | MITRE ATT&CK — not AWS, but the authoritative threat source, snapshot-backed |

**Host-match discipline (unchanged):** the WebFetch host must match a specific
entry above. Do **not** fetch bare `*.amazonaws.com` — customer S3 buckets and
data hosts live there. Anything off the allowlist → emit a `web:blocked:reject`
event to `pipeline.log` (`--source web:blocked --verdict reject`, so a refused
call does not count toward the P1 floor), then find the authoritative AWS page
for the same fact (or fall back to a bundled snapshot if one exists). If neither
confirms the fact, mark it unverified.

## Discovery → Verify loop

For any lookup where the exact URL is unknown (the MCP's "search then read"):

1. **Discover.** Run `WebSearch` — free query (e.g. `"<service> managed config
   rules"`) or scoped (`"<service> <feature> site:docs.aws.amazon.com"`). Log a
   `web:search:search` event. Read the result list; pick a candidate URL.
2. **Verify.** If the candidate host is on the allowlist, `WebFetch` it and log a
   `web:<source-key>:fetch` event. If it is **off-allowlist**, do not fetch it —
   use it as a hint to locate the authoritative AWS page (search again scoped to
   `docs.aws.amazon.com`, or navigate the service's doc tree) and fetch that.
3. **Cite.** Record the fact only if an allowlisted AWS source confirmed it.
   Citations in artifacts point at `docs.aws.amazon.com` (see tier 3 above).
4. **Fall back.** If no AWS source is reachable, use the source's bundled
   snapshot if one exists (`data/attack-cloud-matrix.json`, bundled botocore
   data); otherwise mark the fact unverified.

## Per-source patterns

### AWS Documentation (SAR, dev guides, API refs)

Service Authorization Reference (condition keys, actions, resources) — the
no-MCP equivalent of the `awsknowledge` / `aws-documentation` SAR lookups:
- `WebFetch` URL: `https://docs.aws.amazon.com/service-authorization/latest/reference/list_<service>.html`
- Prompt: "Extract the condition keys table (key name, description, type, applicable actions). Then extract the actions table (action, access level, resource types, condition keys)."

Service-specific user guides / API references — discover first, then read:
- `WebSearch` query: `<service> <feature>` (open, or scoped with
  `site:docs.aws.amazon.com`). Log `web:search:search`.
- `WebFetch` the chosen `docs.aws.amazon.com` URL. Log `web:aws-docs:fetch`.

### aws.amazon.com — blogs, FAQs, what's-new

Read-only discovery/enrichment (feature announcements, deep-dive blogs):
- `WebFetch` URL: `https://aws.amazon.com/blogs/...` or `https://aws.amazon.com/<service>/faqs/`
- Prompt: "Extract the specific claim about <capability>: what it does, any
  named condition key / API parameter, and the date."
- Log `web:aws-blog:fetch`. **A blog is a discovery/enrichment source, not a
  citable one** — confirm the fact on `docs.aws.amazon.com` before citing.

### boto3 / AWS CLI reference

Cross-check API operations, parameter names, and request/response shapes:
- `WebFetch` URL: `https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/<service>.html`
  or `https://awscli.amazonaws.com/v2/documentation/api/latest/reference/<service>/index.html`
- Log `web:boto3:fetch` / `web:awscli:fetch`. (The local, offline
  `tools/research/fetch_botocore_schema.py` remains the ground-truth API-shape
  source in both modes; these refs are a supplementary web cross-check.)

### GitHub — AWS-owned sample/reference repos

Reference examples that anchor generated controls (the same repos indexed in
`data/reference-repos/index.yaml`):
- `WebFetch` a raw file URL under `github.com/{aws-samples,awslabs,aws-cloudformation,aws-actions}/...`
- Log `web:github-samples:fetch`. Repo-anchor citations resolve through the
  reference index, not a URL regex.

### IAM Access Analyzer API

Policy validation feasibility checks:
- `WebFetch` URL: `https://docs.aws.amazon.com/access-analyzer/latest/APIReference/Welcome.html`
- Prompt: "Find the API operation that <validates / checks / simulates> X."
- Log `web:access-analyzer:fetch`.

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
- Log `web:attack-mitre:fetch`.

When `attack.mitre.org` is unreachable, fall back to
`data/attack-cloud-matrix.json` (bundled snapshot, ATT&CK 16.1). This snapshot
ships in the repo, so research-attack-surface always works offline.

## How this mirrors awsknowledge / aws-documentation

| MCP internal step | No-MCP equivalent |
|---|---|
| Broad documentation search to locate a page | **Open `WebSearch`** (no `allowed_domains`) — discovery |
| Returning the authoritative page content | **Allowlisted `WebFetch`** of the AWS-owned URL |
| Answers grounded only in AWS docs | Citations restricted to `docs.aws.amazon.com` |

Open search finds the page; allowlisted fetch reads authoritative content;
narrow citation records it. Discovery breadth matches the MCP; the
authoritative-source guarantee is unchanged.

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

Source-key values:
- `search` — open discovery query (`web:search:search`)
- `aws-docs` — `docs.aws.amazon.com` read
- `access-analyzer` — Access Analyzer API reference read
- `aws-blog` — `aws.amazon.com` blog / FAQ / what's-new read
- `boto3`, `awscli` — SDK / CLI reference read
- `github-samples` — AWS-owned reference-repo file read
- `attack-mitre` — MITRE ATT&CK read
- `blocked` — an off-allowlist fetch that was refused; log it with
  `--verdict reject` (`web:blocked:reject`), never `fetch`

The Stop-hook P1 check counts `web:*:fetch` and `web:*:search` events against
the same minimum-call floor that MCP calls satisfy in the default mode. A
refused call is logged as `web:blocked:reject` — verdict `reject`, not
`fetch`/`search` — so it does **not** inflate the P1 floor; it only records that
a call was refused. Skip logging and the run fails P1.
