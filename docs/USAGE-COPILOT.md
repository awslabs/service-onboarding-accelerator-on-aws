# Usage Guide — GitHub Copilot (VS Code)

Step-by-step guide to install and run the Service Approval Plugin with GitHub Copilot in VS Code.

---

## Prerequisites

- [VS Code](https://code.visualstudio.com/) with [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) extension installed
- GitHub Copilot subscription (Individual, Business, or Enterprise)
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH (for MCP servers)
- Python 3.9+ (for kb-search MCP and validators)

---

## Step 1: Get the repo

**Option A — clone (recommended):**

```bash
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
```

**Option B — from a repo zip.** If you were handed a `.zip` of the repo instead of
git access, unzip it and use the extracted folder in place of the cloned repo —
everything Copilot needs (`.github/`, `.vscode/mcp.json`, `skills/`, `rules/`,
`tools/`) ships inside the zip, so no clone is required:

```bash
unzip service-onboarding-accelerator-on-aws.zip -d ~/
# → creates ~/service-onboarding-accelerator-on-aws/ (folder name may vary)
```

Then treat the extracted folder exactly as the cloned repo for every step below.
Two things to check after unzipping:

- **Restore the `.github/skills` symlink if the zip flattened it.** Some zip tools
  don't preserve symlinks. Confirm it resolves:
  ```bash
  cd ~/service-onboarding-accelerator-on-aws
  ls .github/skills/summarize/SKILL.md   # should print the path, not error
  # if it errors, recreate the symlink:
  rm -f .github/skills && ln -s ../skills .github/skills
  ```
- **Unblock the files on macOS/Windows if they came from a download** (quarantine
  attribute can block VS Code from reading them): macOS `xattr -dr com.apple.quarantine ~/service-onboarding-accelerator-on-aws`;
  Windows → right-click the zip → **Properties** → **Unblock** before extracting.

## Step 2: Open the repo in VS Code

```bash
code service-onboarding-accelerator-on-aws
```

Or: **File** → **Open Folder** → select `service-onboarding-accelerator-on-aws/`.

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
@service-approval ./input --service=s3 --clean
```

## Step 6: Approve MCP connections

On first run, Copilot may prompt you to approve MCP server connections:
- `aws-documentation` — AWS docs lookup
- `awsknowledge` — AWS knowledge base
- `mitre-attack` — MITRE ATT&CK techniques

Click **Allow** for each. These are read-only research tools. Two additional
servers (`kb-search`, `iam`) are optional and used only when configured.

> **Running without MCP:** the pipeline can also run with no MCP servers at all,
> using web access instead. See [Running without MCP](#running-without-mcp) below.

## Step 7: Follow the pipeline

The plugin runs an Intake precursor plus 6 numbered phases:

1. **Intake** *(precursor)* — collects service name and framework choice
2. **Assess** — security posture assessment against 5 CAF domains
3. **Research** — discovers service capabilities, API surface, attack surface
4. **Validate** — verifies research findings via MCP
5. **Map** — maps capabilities to control framework objectives
6. **Recommended Guidance** — produces all security control artifacts (preventive, proactive, detective, responsive)
7. **Summarize** — produces SUMMARY-REPORT.md

The pipeline recommends controls that you deploy yourself; it does not deploy,
test, or attest against a live account.

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
  05-recommended-guidance/        ← all generated artifacts
  06-summarize/       ← SUMMARY-REPORT.md (Summary Report)
```

The key deliverable is `06-summarize/SUMMARY-REPORT.md` — a brief, service-first
overview that links out to the companion docs (`framework-mapping.md`,
`controls-catalog.md`) and includes a coverage summary, a per-domain coverage
rollup, and MITRE ATT&CK threat coverage. Open it directly in VS Code to review.

---

## Available flags

| Flag | Description | Default |
|------|-------------|---------|
| `--service=<name>` | AWS service ID (e.g., `s3`, `kms`, `bedrock-agentcore`) | Required |
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect |
| `--include-unverified` | Include unverified findings in generation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--clean` | Delete existing state before run | false |
| `--no-mcp` | Run without MCP — verify facts over the web (see "Running without MCP") | false |

---

## Running without MCP

MCP servers are the **default** and recommended path. The pipeline can also run
with no MCP servers at all — it verifies the same facts over the web instead,
using Copilot's `WebFetch`/`WebSearch` against an allowlist of AWS documentation
domains. Use this when MCP servers can't be installed (e.g. no `uv`/`uvx`, a
locked-down environment, or an air-gapped run relying on bundled snapshots).

To run in no-MCP mode, add the **`--no-mcp` flag** to your invocation:

```
@service-approval ./input --service=<name> --no-mcp
```

The flag is recorded in the intake manifest as `pipeline_flags.no_mcp` and puts
every phase into its **No-MCP mode** fallback — no config changes, no need to
remove `.vscode/mcp.json`. (You can also set `options.no_mcp: true` in an intake
YAML.) Keep the `fetch` tool enabled for the agent (it is in the agent's tool
list) so `WebFetch`/`WebSearch` are available.

In no-MCP mode:
- Each skill's **No-MCP mode** subsection maps its MCP calls to allowlisted
  `WebFetch`/`WebSearch` lookups — see [`rules/web-access.md`](../rules/web-access.md)
  for the domain allowlist, per-source URL patterns, and logging format.
- MITRE ATT&CK data comes from `attack.mitre.org` (or the bundled
  `data/attack-cloud-matrix.json` snapshot if unreachable), so
  threat-surface analysis still works offline.
- The pipeline-integrity check counts `web:*` lookups toward the same
  minimum-lookup floor that MCP calls satisfy in the default mode, so the run
  still passes its integrity gate.

Everything else — phases, flags, output tree, and the fact-verification
requirement — is identical to the default MCP run.

---

## Troubleshooting

**Copilot doesn't see the agent (`@service-approval` not recognized)**
1. Confirm Copilot Chat is in **Agent mode** (not Ask or Edit mode)
2. Restart VS Code after opening the repo
3. Verify `.github/agents/service-approval.agent.md` exists in the workspace

**MCP servers not connecting**
1. Check `.vscode/mcp.json` exists in the workspace
2. Verify `uv` is on PATH: open VS Code terminal and run `which uv`

**Agent runs but produces no output files**
Make sure you're in the correct working directory. Output goes to
`.service-approval/` relative to the folder VS Code has open.

**"I don't have access to that tool" errors**
Copilot may need MCP tool approval. Check the Copilot output panel
(**View** → **Output** → select "GitHub Copilot") for connection errors.

---

## Updating

```bash
cd /path/to/service-onboarding-accelerator-on-aws
git pull
```

Copilot re-reads `.github/` files on every session. No reinstall needed.
