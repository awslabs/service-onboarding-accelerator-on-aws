# Usage Guide — Claude Code

Step-by-step guide to install and run the Service Approval Plugin with Claude Code.

---

## Prerequisites

- [Claude Code](https://code.claude.com) installed (CLI or VS Code extension)
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH (for MCP servers)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) running (for Terraform MCP)
- Python 3.9+ (for kb-search MCP and validators)

---

## Step 1: Clone the repo

```bash
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
```

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
  ✓ docker found
  ✓ python3 found
```

## Step 3: Create your working directory

Run the plugin from your **own working directory**, not the cloned repo:

```bash
mkdir ~/my-service-approval
cd ~/my-service-approval
```

Optionally add custom input files (threat models, framework spreadsheets):
```bash
mkdir input
cp /path/to/threat-model.xlsx ./input/
cp /path/to/ccmv4-framework.json ./input/
```

If you don't add input files, the plugin uses built-in defaults (CCMv4 + MITRE ATT&CK).

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
/service-approval ./input --service=s3 --env=delegated-admin
```

## Step 6: Follow the pipeline

The plugin runs 9 phases automatically:

1. **Intake** — collects service name, framework choice, testing preferences
2. **Assess** — security posture assessment against 5 CAF domains
3. **Research** — discovers service capabilities, API surface, attack surface (4 parallel sub-skills)
4. **Validate** — verifies research findings via MCP
5. **Map** — maps capabilities to control framework objectives
6. **Generate** — produces all security control artifacts and IaC templates
7. **Test** — deploys and validates (if `--env` provided)
8. **Summarize** — produces SUMMARY-REPORT.md
9. **Evidence** — runs CLI probes for attestation (if Test passed)

You'll see MCP server connections activate as the pipeline progresses. Approve any
permission prompts for MCP tools (aws-documentation, awsknowledge, awsiac, etc.).

## Step 7: Review output

Output lands in `.service-approval/<service-slug>/` in your working directory:

```
.service-approval/s3/
  00-intake/          ← intake manifest
  01-assess/          ← SAR facts, assessment summary
  02-research/        ← research.json
  03-validate/        ← validated.json
  04-map/             ← mapping-results.json, controls-catalog.md
  05-recommended-guidance/        ← all generated artifacts (85+ files)
  06-test/            ← test-results.json, deployed-resources.json (if --env)
  07-summarize/       ← SUMMARY-REPORT.md (Summary Report)
  08-evidence/        ← attestation-report.md, attestation-results.json (if Test passed)
```

The key deliverable is `07-summarize/SUMMARY-REPORT.md` — contains the coverage matrix, mitigation traceability, and artifact inventory.

---

## Available flags

| Flag | Description | Default |
|------|-------------|---------|
| `--service=<name>` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore`) | Required |
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--env=<profile>` | AWS CLI profile for Test phase + Tier 2 validation | None (skips Test) |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect |
| `--skip-test` | Skip deployment validation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--clean` | Delete existing state before run | false |

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
- Check Docker is running: `docker ps`
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
