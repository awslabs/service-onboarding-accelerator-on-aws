# Usage Guide — Kiro IDE

Step-by-step guide to install and run the Service Approval Plugin with Kiro IDE.

---

## Prerequisites

- [Kiro IDE](https://kiro.dev) installed
- [`git`](https://git-scm.com/downloads) — to clone this repository
- [Python](https://www.python.org/downloads/) 3.9+ (`python3 --version`) — validators and hooks
- The Python packages in [`requirements.txt`](../requirements.txt) — installed in Step 1 below
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

## Step 2: Install the Power via Kiro IDE

1. Open **Kiro** IDE
2. Open the **Powers** panel (left sidebar)
3. Click **Add power from local path**
4. Navigate to and select the `powers/service-approval/` folder from the cloned repo

The Power is now registered in Kiro. It reads directly from the repo path, so
`git pull` updates it automatically.

## Step 3: Create your working directory

Open a **new folder** in Kiro for your service approval work — not the plugin repo itself:

1. **File** → **Open Folder**
2. Create or select an empty folder (e.g., `~/my-service-approval/`)

Optionally add a framework or supporting documents:
```bash
mkdir ~/my-service-approval/input
cp /path/to/ccmv4-framework.json ~/my-service-approval/input/
```

Intake retrieves the latest matching model from the public AWS Threat Models
repository. Missing services and retrieval failures stop the pipeline; local
exports cannot bypass it. Resume checks upstream again. See
[Threat Models](THREAT-MODELS.md) for provenance, citations, and migration.

## Step 4: Start the plugin

In Kiro's chat, trigger the Power using keyword matching. Any of these work:

- "run service approval for s3"
- "I need service approval for bedrock-agentcore"
- "generate security controls for kms"

Or explicitly ask Kiro to use the Power:
- "use the service-approval power for lambda"

## Step 5: Answer the Intake prompts

The Intake phase will ask you:

1. **Service name** — which AWS service (e.g., `s3`, `kms`, `lambda`)
2. **Framework** — defaults to CCMv4 (always-on MITRE ATT&CK enrichment). NIST 800-53, CIS, ISO 27001 stay available behind `--framework=<type>` for advanced operators.
3. **Input files** — whether to seed from bundled CCMv4 or use your own

If you placed files in `./input/`, Kiro detects them automatically.

## Step 6: Follow the pipeline

The plugin runs an Intake precursor plus 6 numbered phases:

1. **Intake** — collects service name and framework choice
2. **Assess** — security posture assessment against 5 CAF domains
3. **Research** — discovers service capabilities, API surface, attack surface
4. **Validate** — verifies research findings via MCP
5. **Map** — maps capabilities to control framework objectives
6. **Recommended Guidance** — produces all security control artifacts
7. **Summarize** — produces SUMMARY-REPORT.md

The pipeline recommends controls that you deploy yourself; it does not deploy,
test, or attest against a live account.

Kiro runs phases sequentially. You may see MCP connection prompts — approve them
to allow the plugin to query AWS documentation and knowledge bases.

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

## Running without MCP

MCP servers are the **default** and recommended path. The pipeline can also run
with no MCP servers at all — it verifies the same facts over the web instead. Ask
Kiro to run in no-MCP mode (e.g. "run service approval for s3 without MCP") or
set `options.no_mcp: true` in an intake YAML; either records
`pipeline_flags.no_mcp` in the intake manifest and puts every phase into its
**No-MCP mode** fallback.

No-MCP mode uses an **open discovery → allowlisted fetch → narrow cite** loop: an
open `WebSearch` finds the right AWS page, an allowlisted `WebFetch` reads it, and
citations stay on `docs.aws.amazon.com`. Threat data comes from
`attack.mitre.org` or the bundled `data/attack-cloud-matrix.json` snapshot, so
the pipeline works offline too.

See [How no-MCP mode works](NO-MCP.md) for the full walkthrough and
[`rules/web-access.md`](../rules/web-access.md) for the policy.

---

## Troubleshooting

**Power doesn't appear in the Powers panel**
Re-add: Powers panel → Add power from local path → select `powers/service-approval/`.

**Kiro doesn't activate the Power**
The Power is keyword-triggered. Make sure your message includes "service approval"
or the specific AWS service name. Alternatively, explicitly ask: "use the
service-approval power."

**MCP connection errors (`fetch failed`, `Connection closed`)**
- Check `uv` is on PATH: open terminal in Kiro and run `which uv`
- See [`docs/TESTING-KIRO.md`](TESTING-KIRO.md) for detailed MCP troubleshooting

**`workspaceRoot not approved` warning**
This is a Kiro security feature. Accept the workspace trust prompt when opening
your working directory for the first time.

---

## Updating

```bash
cd /path/to/service-onboarding-accelerator-on-aws
git pull
```

Since the Power references the repo path directly, updates take effect on the
next Kiro session. No reinstall needed.

---

## Uninstall

1. Open **Kiro** IDE → **Powers** panel
2. Select **service-approval**
3. Click **Remove**
