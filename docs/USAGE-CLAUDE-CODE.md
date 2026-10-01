# Usage Guide — Claude Code

Step-by-step guide to install and run the Service Approval Plugin with Claude Code.

---

## Prerequisites

- [Claude Code](https://code.claude.com) installed (CLI or VS Code extension)
- [`git`](https://git-scm.com/downloads) — to clone this repository
- [Python](https://www.python.org/downloads/) 3.9+ (`python3 --version`) — validators and hooks
- The Python packages in [`requirements.txt`](../requirements.txt) — installed in Step 2 below
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH — only for default MCP mode; skip if you always use `--no-mcp`

No AWS account or credentials are required to generate controls.

---

## Step 1: Clone the repo and install Python packages

```bash
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

> On Windows PowerShell, use `py -m venv .venv ; .\.venv\Scripts\pip install -r requirements.txt`.

Then confirm everything the pipeline needs is present (each line prints `PASS`
or `MISSING`; a `MISSING` for `uv` is fine if you only use `--no-mcp`):

```bash
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS     $1"; else echo "MISSING  $1"; fi; }
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
check "git"                "command -v git"
check "python3 (>=3.9)"    "$PY -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,9) else 1)'"
check "pyyaml"             "$PY -c 'import yaml'"
check "jsonschema"         "$PY -c 'import jsonschema'"
check "pytest"             "$PY -c 'import pytest'"
check "uv (MCP mode only)" "command -v uv"
```

(The PowerShell equivalent is in the [README](../README.md#verify-your-setup).)

## Step 2: Run the installer

```bash
./install-claude.sh
```

This script:
- Creates the `/service-approval` slash command (symlink)
- Regenerates MCP server configs from `manifest.yaml`
- Writes `.claude/settings.json` (permissions, MCP allowlist, plugin enablement)
- Registers the repo as a local plugin marketplace
- Installs the plugin at user scope (available from any directory)

You should see output like:
```
  ✓ Slash command /service-approval linked
  ✓ MCP configs regenerated from manifest.yaml
  ✓ .claude/settings.json written
  ✓ Marketplace registered — plugin available from any directory
  ✓ Plugin installed (user scope)
  ✓ uv found
  ✓ python3 found
```

## Step 3: Create your working directory

Run the plugin from your **own working directory**, not the cloned repo:

```bash
mkdir ~/my-service-approval
cd ~/my-service-approval
```

Add the required matching AWS Threat Model JSON export and optional framework:
```bash
mkdir input
cp /path/to/service-aws-threat-model.json ./input/
cp /path/to/ccmv4-framework.json ./input/
```

The pipeline stops before assessment/research without a valid matching AWS
Threat Model export. You may instead pass `--threat-model-file=<path>`.
This requirement also applies to saved intake, resume, and `--no-mcp`.

## Step 4: Start Claude Code

Launch Claude Code from your working directory:

```bash
claude
```

Or open the folder in VS Code with the Claude Code extension active.

## Step 5: Run the plugin

Use the slash command:

```
/service-approval --service=s3
```

With custom input files:
```
/service-approval ./input --service=s3
```

With additional flags:
```
/service-approval ./input --service=bedrock-agentcore --framework=ccmv4
/service-approval --service=kms --dry-run
/service-approval ./input --service=s3 --clean
```

## Step 6: Follow the pipeline

The plugin runs an Intake precursor plus 6 numbered phases automatically:

1. **Intake** — collects service name and framework choice
2. **Assess** — security posture assessment against 5 CAF domains
3. **Research** — discovers service capabilities, API surface, attack surface (4 parallel sub-skills)
4. **Validate** — verifies research findings via MCP
5. **Map** — maps capabilities to control framework objectives
6. **Recommended Guidance** — produces all security control artifacts
7. **Summarize** — produces SUMMARY-REPORT.md

The pipeline recommends controls that you deploy yourself; it does not deploy,
test, or attest against a live account.

You'll see MCP server connections activate as the pipeline progresses. Approve any
permission prompts for MCP tools (aws-documentation, awsknowledge, etc.).

## Step 7: Review output

Output lands in `.service-approval/<service-slug>/` in your working directory:

```
.service-approval/s3/
  00-intake/          ← intake manifest
  01-assess/          ← SAR facts, assessment summary
  02-research/        ← research.json
  03-validate/        ← validated.json
  04-map/             ← mapping-results.json, controls-catalog.md
  05-recommended-guidance/        ← all generated artifacts
  06-summarize/       ← SUMMARY-REPORT.md (Summary Report)
```

The key deliverable is `06-summarize/SUMMARY-REPORT.md` — contains the coverage matrix, mitigation traceability, and artifact inventory.

---

## Available flags

| Flag | Description | Default |
|------|-------------|---------|
| `--service=<name>` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore`) | Required |
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect |
| `--framework-specification="<text>"` | Free-text notes on a custom framework's structure (control/sub-control ID format, columns, grouping); with a custom framework, intake also offers to ask | None |
| `--include-unverified` | Include unverified findings in generation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--clean` | Delete existing state before run | false |
| `--no-mcp` | Run without MCP servers — verify facts over the web (see "Running without MCP" below) | false (MCP is the default) |

---

## Running without MCP

MCP servers are the **default** and recommended path. The pipeline can also run
with no MCP servers at all — pass the **`--no-mcp` flag** and every fact is
verified over the web instead:

```
/service-approval ./input --service=<name> --no-mcp
```

The flag is recorded in the intake manifest as `pipeline_flags.no_mcp` and puts
every phase into its **No-MCP mode** fallback (you can also set
`options.no_mcp: true` in an intake YAML). No-MCP mode uses an **open discovery →
allowlisted fetch → narrow cite** loop: an open `WebSearch` finds the right AWS
page, an allowlisted `WebFetch` reads it, and citations stay on
`docs.aws.amazon.com`. Threat data comes from `attack.mitre.org` or the bundled
`data/attack-cloud-matrix.json` snapshot, so the pipeline works offline too.

See [How no-MCP mode works](NO-MCP.md) for the full walkthrough and
[`rules/web-access.md`](../rules/web-access.md) for the policy.

---

## Troubleshooting

**`/service-approval` command not found**
Run `./install-claude.sh` again from the repo, or manually:
```
/plugin marketplace add /path/to/service-onboarding-accelerator-on-aws
/plugin install service-approval@service-approval
/reload-plugins
```

**MCP server not connecting**
- Check `uv` is on PATH: `which uv`
- Approve the MCP connection when prompted

**Plugin works in repo but not from other directories**
The marketplace registration may have failed. Run from the repo:
```bash
claude plugin marketplace add .
claude plugin install service-approval@service-approval --scope user
```

---

## Updating

```bash
cd /path/to/service-onboarding-accelerator-on-aws
git pull
./install-claude.sh
```

The plugin auto-updates since it's symlinked from the marketplace.

---

## Uninstall

```
/plugin uninstall service-approval@service-approval
/plugin marketplace remove service-approval
```

Then delete the cloned repo (and the `.venv/` inside it). Removing the repo is
enough on its own — Claude Code stops discovering the plugin once the
marketplace symlink target is gone.
