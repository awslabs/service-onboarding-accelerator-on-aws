# How no-MCP mode works

MCP servers are the **default** and recommended path for the Service Onboarding
Accelerator. The whole pipeline can also run with **no MCP servers at all** — it
verifies the same facts over the web instead. This page is the canonical
reference for that mode; the per-client usage guides link here.

Use no-MCP mode when MCP servers can't be installed — no `uv`/`uvx`, a
locked-down or air-gapped environment, or a run that relies on the bundled
snapshots.

## What it is

In the default path, phases call the `awsknowledge` / `aws-documentation` MCP
servers (plus `mitre-attack` only when the user enables it) to look up AWS documentation, the
Service Authorization Reference (SAR), API shapes, and threat data. No-MCP mode
replaces those MCP calls with web access — `WebSearch` and `WebFetch` — while
preserving the guarantee that **facts and citations come only from
authoritative AWS sources**. Everything else — phases, flags, output tree, and
the fact-verification requirement — is identical to the default MCP run.

## How to enable it

Any one of these puts every phase into its **No-MCP mode** fallback. No config
changes and no need to remove `.vscode/mcp.json` / MCP configs:

| Where | How |
|---|---|
| CLI flag | add `--no-mcp` to the invocation, e.g. `@service-approval ./input --service=<name> --no-mcp` |
| Intake option | set `options.no_mcp: true` in an intake YAML |
| Intake manifest | recorded as `pipeline_flags.no_mcp: true` in `00-intake/intake-manifest.json` |

Keep the agent's `fetch` tool enabled (it is in the agent's tool list) so
`WebSearch` / `WebFetch` are available.

## How it searches — open discovery → allowlisted fetch → narrow cite

No-MCP mode mirrors what the MCPs do internally (search broadly to find a page,
then return that page's authoritative content) with a **two-tier model**, plus a
narrow citation rule. The full policy — allowlist table, per-source patterns,
and logging — lives in [`rules/web-access.md`](../rules/web-access.md).

1. **Discovery is open.** `WebSearch` may run **without** `allowed_domains` — a
   free query whose only job is to *find* the right AWS page. Search results are
   hints, never facts.
2. **Reading is restricted** to the verified-AWS allowlist (below). `WebFetch`
   only retrieves a URL whose host is on that list. An off-allowlist search hit
   is a hint — the agent finds the authoritative AWS page for the same fact and
   fetches that.
3. **Citing is narrow.** Artifact citations point at `docs.aws.amazon.com` (the
   Checkov policy-index host is the one non-AWS exception the validator allows).
   A fact discovered on a blog or SDK reference is re-confirmed on the
   authoritative doc page before it is cited. If no AWS-owned source confirms a
   fact, the fact is **unverified** — the same discipline as the MCP path.

### Which domains it searches and reads

Discovery (`WebSearch`) is open — any domain may appear in results. Reading
(`WebFetch`) is limited to these AWS-owned / AWS-operated hosts:

| Domain | Fetch (read) | Cite |
|---|:---:|:---:|
| `docs.aws.amazon.com` (incl. SAR, Access Analyzer API ref) | ✅ | ✅ |
| `aws.amazon.com` (feature pages, `/blogs/`, FAQs, what's-new) | ✅ | — |
| `api.aws`, `knowledge-mcp.global.api.aws` | ✅ | — |
| `boto3.amazonaws.com`, `awscli.amazonaws.com` (SDK/CLI refs) | ✅ | — |
| `github.com/{aws-samples,awslabs,aws-cloudformation,aws-actions}` | ✅ | via reference index |
| `attack.mitre.org/matrices/enterprise/` (+ `/techniques/`) | ✅ | — |
| `www.checkov.io` (policy index) | — | ✅ |

Bare `*.amazonaws.com` is **not** allowlisted — customer S3 buckets and data
hosts live there. Repo-anchor citations (`github.com/aws-*`) resolve through
`data/reference-repos/index.yaml`, not a URL match.

## How it maps to the MCPs

| MCP internal step | No-MCP equivalent |
|---|---|
| Broad documentation search to locate a page | Open `WebSearch` (no `allowed_domains`) |
| Returning the authoritative page content | Allowlisted `WebFetch` of the AWS-owned URL |
| Answers grounded only in AWS docs | Citations restricted to `docs.aws.amazon.com` |

`awsknowledge` / `aws-documentation` SAR and doc lookups → `WebFetch` of the
`docs.aws.amazon.com` page. `mitre-attack` → `WebFetch` of `attack.mitre.org`
(or the bundled snapshot). The offline botocore helper
(`tools/research/fetch_botocore_schema.py`) is the ground-truth API-shape source
in **both** modes.

## Logging and the P1 floor

Every web call emits a canonical event to `pipeline.log`:

```
<ts> [<NN-phase>] [web:<source-key>:<verdict>]  <URL or query>: <description>
```

- `--verdict search` for `WebSearch`, `--verdict fetch` for `WebFetch`.
- Source keys: `search` (open discovery), `aws-docs`, `access-analyzer`,
  `aws-blog`, `boto3`, `awscli`, `github-samples`, `attack-mitre`.
- A refused off-allowlist fetch is logged as `web:blocked:reject`
  (verdict `reject`, not `fetch`) so it does not count toward the floor.

The pipeline-integrity check (P1) counts `web:*:fetch` and `web:*:search` events
toward the same minimum-lookup floor that MCP calls satisfy in the default mode,
so a no-MCP run still passes its integrity gate. Skip logging and the run fails
P1.

## Offline-snapshot fallbacks

When an allowlisted domain is unreachable, no-MCP mode falls back to bundled
snapshots so the pipeline still completes:

- **MITRE ATT&CK:** `data/attack-cloud-matrix.json` (ATT&CK 16.1 snapshot) when
  `attack.mitre.org` is unreachable — threat-surface analysis works offline.
- **API shapes:** the offline botocore data behind
  `tools/research/fetch_botocore_schema.py`.

If neither a live AWS source nor a bundled snapshot confirms a fact, the fact is
marked unverified — it is never guessed from training data.
