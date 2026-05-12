---
name: headless
description: Run service-approval in CI via Kiro CLI 2.0 headless mode
inclusion: fileMatch
fileMatchPattern: "**/.gitlab-ci.yml"
---

# Headless mode — service-approval in CI

Kiro CLI 2.0 added `--no-interactive` mode (April 2026 release). Combined with
`KIRO_API_KEY`, `--trust-tools`, and the `/spawn` command, the full pipeline
runs in CI without user intervention.

## Minimum CI recipe

```yaml
service-approval:
  image: python:3.11-slim
  before_script:
    - curl -fsSL https://cli.kiro.dev/install | bash
    - ./install.sh
  script:
    - export KIRO_API_KEY=$KIRO_API_KEY_SECRET
    - kiro-cli
        --no-interactive
        --trust-tools="aws-documentation,awsknowledge,awsiac,terraform,kb-search"
        "run service approval for ${AWS_SERVICE} using ./input --env=delegated-admin"
  artifacts:
    paths:
      - .service-approval/
    expire_in: 30 days
```

## Required environment variables

| Variable | Source | Purpose |
|----------|--------|---------|
| `KIRO_API_KEY` | Kiro dashboard → API Keys | Authenticates `kiro-cli` non-interactively |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | CI secret | Phase 5 Tier 2 validation only |
| `AWS_SERVICE` | CI variable | Service name (e.g., `s3`, `lambda`) |

## Trust flags

`--trust-tools` pre-authorizes MCP servers so the pipeline doesn't stall waiting
for interactive approval. List ALL servers the pipeline uses:

```
--trust-tools="aws-documentation,awsknowledge,awsiac,terraform,kb-search"
```

`--trust-all-tools` is also valid but wider than needed. Prefer the explicit list.

## Detecting failure in CI

The Stop hook exits 2 on integrity failure. Kiro CLI 2.0 propagates this as the
process exit code. Gate your CI on exit code:

```yaml
script:
  - kiro-cli --no-interactive --trust-tools="..." "..."
  - |
    if [ $? -ne 0 ]; then
      echo "Pipeline integrity failed — see APPROVAL-REPORT.md"
      cat .service-approval/APPROVAL-REPORT.md
      exit 1
    fi
```

## Budget limits

Headless mode burns tokens for every subagent. Typical run costs:
- `service` of small surface (e.g., SQS): ~150K tokens
- `service` of medium surface (e.g., Lambda): ~300K tokens
- `service` of large surface (e.g., ECS, S3): ~500K–800K tokens

Set a Kiro workspace token budget in the dashboard if running on a schedule.

## Artifacts for review

Upload `.service-approval/` as a CI artifact. Reviewers can inspect:
- `APPROVAL-REPORT.md` — customer-facing verdict
- `controls/` — all generated artifacts
- `state/mcp-calls.log` — audit trail of every MCP call
- `state/validated.json` — proof of MCP verification for every item

## Troubleshooting CI runs

### `kiro-cli: Pipeline integrity failed`
Read `.service-approval/APPROVAL-REPORT.md` for the verdict and root cause. The
integrity script prints which of P1–P6 failed.

### `Too few MCP calls in mcp-calls.log`
The research phase didn't run — likely because `--trust-tools` omitted a server.
Verify the flag includes every server in `mcp.json`.

### Timeouts on `sa-generate-iac`
IaC generation is the largest phase. If hitting token or time limits, narrow
scope: skip ATT&CK enrichment (`--skip-attack`), or split by IaC format.
