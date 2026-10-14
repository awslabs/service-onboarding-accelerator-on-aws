# Usage Guide — GitHub Copilot (VS Code)

Step-by-step guide to install and run the Service Approval Plugin with GitHub Copilot in VS Code.

---

## Prerequisites

- [VS Code](https://code.visualstudio.com/) with [GitHub Copilot](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot) extension installed
- GitHub Copilot subscription (Individual, Business, or Enterprise)
- [`git`](https://git-scm.com/downloads) — to clone this repository (skip if you were handed a zip)
- [Python](https://www.python.org/downloads/) 3.9+ (`python3 --version`) — validators and hooks
- The Python packages in [`requirements.txt`](../requirements.txt) — installed in Step 1 below
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH — only for default MCP mode; skip if you always use `--no-mcp`

No AWS account or credentials are required to generate controls.

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

**Install the Python packages** (either option). From the repo folder:

```bash
cd service-onboarding-accelerator-on-aws
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

> On Windows PowerShell, use `py -m venv .venv ; .\.venv\Scripts\pip install -r requirements.txt`.

Confirm everything the pipeline needs is present (each line prints `PASS` or
`MISSING`; a `MISSING` for `uv` is fine if you only use `--no-mcp`):

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
2. Optionally add a framework or supporting documents:
   ```bash
   mkdir ~/my-service-approval/input
   cp /path/to/ccmv4-framework.json ~/my-service-approval/input/
   ```
3. Open this folder in VS Code: **File** → **Open Folder** → select `~/my-service-approval/`

Intake retrieves the latest matching model from the public AWS Threat Models
repository. Missing services and retrieval failures stop the pipeline; local
exports cannot bypass it. Resume checks upstream again. See
[Threat Models](THREAT-MODELS.md) for provenance, citations, and migration.

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
@service-approval ./input --service=lambda
```

A run without optional supporting documents:
```
@service-approval --service=dsql
```

With additional flags:
```
@service-approval ./input --service=kms --framework=ccmv4
@service-approval --service=lambda --dry-run
@service-approval ./input --service=lambda --clean
```

## Step 6: Approve MCP connections

On first run, Copilot may prompt you to approve MCP server connections:
- `aws-documentation` — AWS docs lookup
- `awsknowledge` — AWS knowledge base
- Optional `mitre-attack` — appears only if you [enable it](MCP.md); otherwise the bundled ATT&CK snapshot is used.

Click **Allow** for each. These are read-only research tools.

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
| `--framework-specification="<text>"` | Free-text notes on a custom framework's structure (control/sub-control ID format, columns, grouping); with a custom framework, intake also offers to ask | None |
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

In no-MCP mode, each phase replaces its MCP calls with web access using an
**open discovery → allowlisted fetch → narrow cite** loop: an open `WebSearch`
finds the right AWS page, an allowlisted `WebFetch` reads it, and citations stay
on `docs.aws.amazon.com`. MITRE ATT&CK data comes from `attack.mitre.org` (or the
bundled `data/attack-cloud-matrix.json` snapshot if unreachable). The
pipeline-integrity check counts `web:*` lookups toward the same minimum-lookup
floor that MCP calls satisfy in the default mode.

**See [How no-MCP mode works](NO-MCP.md)** for the full walkthrough — which
domains it searches and reads, how it maps to the MCPs, the `web:*` logging and
P1 floor, and the offline-snapshot fallbacks — and
[`rules/web-access.md`](../rules/web-access.md) for the policy itself.

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
