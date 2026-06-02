# Usage Guide — GitHub Copilot (VS Code)

Step-by-step guide to install and run the Service Approval Plugin with GitHub Copilot in VS Code.

---

## Prerequisites

- [VS Code](https://code.visualstudio.com/) with [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) extension installed
- GitHub Copilot subscription (Individual, Business, or Enterprise)
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH (for MCP servers)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) running (for Terraform MCP)
- Python 3.9+ (for kb-search MCP and validators)

---

## Step 1: Clone the repo

```bash
git clone https://gitlab.aws.dev/lightninglane/service-onboarding.git
```

## Step 2: Open the repo in VS Code

```bash
code service-onboarding
```

Or: **File** → **Open Folder** → select `service-onboarding/`.

Copilot auto-discovers the plugin — no install step required. It reads:
- `.github/copilot-instructions.md` (repo-wide rules)
- `.github/agents/service-approval.agent.md` (the agent definition)
- `.github/prompts/service-approval.prompt.md` (the slash command)
- `.github/skills/` (skill bundles)
- `.vscode/mcp.json` (MCP server definitions)

## Step 3: Create your working directory

For running the plugin, open a **separate folder** — not the plugin repo:

1. Create a new folder: `mkdir ~/my-service-approval`
2. Optionally add custom input files:
   ```bash
   mkdir ~/my-service-approval/input
   cp /path/to/threat-model.xlsx ~/my-service-approval/input/
   cp /path/to/ccmv4-framework.json ~/my-service-approval/input/
   ```
3. Open this folder in VS Code: **File** → **Open Folder** → select `~/my-service-approval/`

If you don't add input files, the plugin uses built-in defaults (CCMv4 + MITRE ATT&CK).

> **Note:** The agent and MCP configs live in the plugin repo. If running from a
> different folder, copy `.vscode/mcp.json` and `.github/` from the plugin repo
> into your working directory, or open the plugin repo as a workspace alongside
> your working folder.

## Step 4: Open Copilot Chat in Agent mode

1. Open Copilot Chat: **Ctrl+Shift+I** (Windows/Linux) or **Cmd+Shift+I** (macOS)
2. Switch to **Agent mode** (click the mode selector at the top of the chat panel — it should say "Agent", not "Ask" or "Edit")

## Step 5: Run the plugin

Type in Copilot Chat:

```
@service-approval ./input --service=s3
```

Or without input files:
```
@service-approval --service=bedrock-agentcore
```

With additional flags:
```
@service-approval ./input --service=kms --framework=ccmv4
@service-approval --service=lambda --dry-run
@service-approval ./input --service=s3 --env=delegated-admin
```

## Step 6: Approve MCP connections

On first run, Copilot may prompt you to approve MCP server connections:
- `aws-documentation` — AWS docs lookup
- `awsknowledge` — AWS knowledge base
- `awsiac` — AWS IaC reference
- `terraform` — Terraform provider docs
- `mitre-attack` — MITRE ATT&CK techniques

Click **Allow** for each. These are read-only research tools.

## Step 7: Follow the pipeline

The plugin runs 9 phases:

1. **Intake** — collects service name, framework choice, testing preferences
2. **Assess** — security posture assessment against 5 CAF domains
3. **Research** — discovers service capabilities, API surface, attack surface
4. **Validate** — verifies research findings via MCP
5. **Map** — maps capabilities to control framework objectives
6. **Generate** — produces all security control artifacts and IaC templates
7. **Test** — deploys and validates (if `--env` provided)
8. **Summarize** — produces APPROVAL-REPORT.md with verdict
9. **Evidence** — runs CLI probes for attestation (if Test passed)

Progress appears in the Copilot Chat panel. The agent may ask clarifying
questions during Intake if service name or framework is ambiguous.

## Step 8: Review output

Output lands in `.service-approval/<service-slug>/` in your working directory:

```
.service-approval/s3/
  00-intake/          ← intake manifest
  01-assess/          ← SAR facts, assessment summary
  02-research/        ← research.json
  03-validate/        ← validated.json
  04-map/             ← mapping-results.json, controls-catalog.md
  05-generate/        ← all generated artifacts (85+ files)
  07-summarize/       ← APPROVAL-REPORT.md (final verdict)
```

The key deliverable is `07-summarize/APPROVAL-REPORT.md` — contains the approval
verdict, coverage matrix, and artifact inventory. Open it directly in VS Code to review.

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

**Copilot doesn't see the agent (`@service-approval` not recognized)**
1. Confirm Copilot Chat is in **Agent mode** (not Ask or Edit mode)
2. Restart VS Code after opening the repo
3. Verify `.github/agents/service-approval.agent.md` exists in the workspace

**MCP servers not connecting**
1. Check `.vscode/mcp.json` exists in the workspace
2. Verify `uv` is on PATH: open VS Code terminal and run `which uv`
3. Verify Docker is running for the Terraform MCP

**Agent runs but produces no output files**
Make sure you're in the correct working directory. Output goes to
`.service-approval/` relative to the folder VS Code has open.

**"I don't have access to that tool" errors**
Copilot may need MCP tool approval. Check the Copilot output panel
(**View** → **Output** → select "GitHub Copilot") for connection errors.

---

## Updating

```bash
cd /path/to/service-onboarding
git pull
```

Copilot re-reads `.github/` files on every session. No reinstall needed.
