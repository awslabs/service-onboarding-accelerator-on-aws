# Service Approval — Kiro Power

Kiro CLI 2.0 Power that generates AWS security controls for any AWS service via a 7-phase pipeline. Produces SCPs, Config rules, CFN Guard rules, Checkov policies, OPA policies, and compliant Terraform/CloudFormation/CDK/CDKTF templates, all mapped to a control framework (CCMv4, NIST 800-53, CIS, ISO).

## Install

From a local checkout (this repo):

```bash
cd /path/to/service-onboarding
./install.sh
```

The installer runs `kiro-cli power install --local powers/service-approval` under the hood, creating a symlink so `git pull` auto-updates the Power.

From GitHub (Kiro desktop app):
1. Open the **Powers** panel
2. Click **Add power from GitHub**
3. Paste `https://gitlab.aws.dev/lightninglane/service-onboarding` and choose `/powers/service-approval` as the path

## Prerequisites

1. **Kiro CLI 2.0+** — `kiro-cli --version` should report 2.0.0 or later
2. **Python 3.9+** — required for validators and hooks
3. **Docker** — required for `terraform` MCP server
4. **MCP servers** — registered in `mcp.json`, loaded automatically when the Power activates

## Usage

Once installed, Kiro activates this Power when you mention any of:

- "run service approval for <service-name>"
- "generate AWS security controls for <service-name>"
- "service approval ./input --service=<name>"
- explicit: "use the service-approval Power for Amazon S3"

Full parameter reference is in [`POWER.md`](POWER.md).

## What this Power does

1. Reads customer inputs (`./input/` folder with .md, .json, .xlsx, .pdf, .docx)
2. Runs a 7-phase pipeline (Assess, Research, Validate, Map, Generate, Test, Summarize)
3. Writes state and artifacts to `.service-approval/` in the working directory
4. Produces `APPROVAL-REPORT.md` with a framework-coverage matrix and a verdict

## Pipeline

```
Phase 0 Assess       → state/sar-facts.json, state/checkpoint-results.json
Phase 1 Research     → state/research.json (4 parallel sub-skills)
Phase 2 Validate     → state/validated.json (cross-MCP verification)
Phase 3 Map          → state/mapping-results.json (+ framework-mapping.md)
Phase 4 Generate     → controls/ (78–111 files)
Phase 5 Test         → state/test-results.json (optional, needs --env)
Phase 6 Summarize    → APPROVAL-REPORT.md
```

Uses Kiro CLI 2.0 `/spawn` for parallel execution in Phases 1, 3, and 4.

## Repository layout

```
powers/service-approval/
├── POWER.md                     Manifest + body (keywords, invocation, pipeline)
├── README.md                    (this file)
├── mcp.json                     MCP server registrations
├── steering/
│   ├── product.md               What and why (always-on)
│   ├── tech.md                  Stack + validators (always-on)
│   ├── structure.md             Layout + conventions (always-on)
│   ├── pipeline.md              Full phase-by-phase guide
│   ├── phase-research.md        Loads for research state files
│   ├── phase-validate.md        Loads for validated.json
│   ├── phase-map.md             Loads for map-* state files
│   ├── phase-generate.md        Loads for controls/ artifacts
│   └── headless.md              CI / headless invocation recipe
├── agents/
│   ├── sa-assess.json
│   ├── sa-research-mitigations.json    (parallel, phase 1)
│   ├── sa-research-capabilities.json   (parallel, phase 1)
│   ├── sa-research-api-surface.json    (parallel, phase 1)
│   ├── sa-research-attack-surface.json (parallel, phase 1 — optional)
│   ├── sa-validate.json
│   ├── sa-map-parse-framework.json     (parallel, phase 3)
│   ├── sa-map-generate-controls.json   (parallel, phase 3)
│   ├── sa-map-framework-mapping.json
│   ├── sa-map-assemble.json
│   ├── sa-generate-preventive.json     (parallel, phase 4)
│   ├── sa-generate-detective.json      (parallel, phase 4)
│   └── sa-generate-iac.json            (parallel, phase 4)
└── hooks/
    ├── post-tool-use.json       fs_write → validates state files
    ├── stop.json                Stop → runs pipeline integrity checks
    └── README.md                How to test hooks manually
```

## Hard rules

The Stop hook (`hooks/stop.json`) runs `tools/validate/hook_stop.py` which invokes `validate_pipeline_integrity.py`. Exit code 2 blocks on:

1. No one-shot generator scripts — every phase runs through its `SKILL.md`
2. Every claim MCP-verified — no training-data values
3. `mcp-calls.log` has ≥10 entries
4. `validated.json` notes unique (≥50% uniqueness)
5. IaC parameterized — no `123456789012` or placeholder ARNs
6. SCPs have ≥1 `Deny`; `StringEquals`/`StringNotEquals` target same key
7. Verdict matches integrity — no false `APPROVED`

Full list in [`POWER.md`](POWER.md) and [`steering/pipeline.md`](steering/pipeline.md).

## Headless / CI

Kiro CLI 2.0 headless mode works with this Power. Set `KIRO_API_KEY`, pass `--no-interactive --trust-tools="aws-documentation,awsknowledge,awsiac,terraform,kb-search"`. Full recipe in [`steering/headless.md`](steering/headless.md).

## Updating

```bash
cd /path/to/service-onboarding
git pull
```

The Power is symlink-installed — changes in the repo take effect on next session. No re-install.

## Uninstalling

```bash
kiro-cli power uninstall service-approval
```

Or: Kiro app → Powers panel → service-approval → Uninstall.

## Testing and troubleshooting

Full testing guide at [`docs/TESTING-KIRO.md`](../../docs/TESTING-KIRO.md). Covers:
- Verifying the install populated `.kiro/agents/`, `.kiro/hooks/`, `.kiro/steering/`
- Confirming MCP servers connect (requires `uv` on PATH for `aws-documentation` and `awsiac`)
- Keyword activation tests
- Hook-fire verification via `.service-approval/state/mcp-calls.log`
- Fixes for "fetch failed", "aws-cdk-mcp-server Connection closed", and the "workspaceRoot not approved" security warning

## License

MIT
