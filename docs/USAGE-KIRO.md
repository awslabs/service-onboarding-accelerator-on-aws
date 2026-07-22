# Usage Guide — Kiro IDE

Step-by-step guide to install and run the Service Approval Plugin with Kiro IDE.

---

## Prerequisites

- [Kiro IDE](https://kiro.dev) installed
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH (for MCP servers)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) running (for Terraform MCP)
- Python 3.9+ (for kb-search MCP and validators)

---

## Step 1: Clone the repo

```bash
git clone https://github.com/awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
```

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

Optionally add custom input files:
```bash
mkdir ~/my-service-approval/input
cp /path/to/threat-model.xlsx ~/my-service-approval/input/
cp /path/to/ccmv4-framework.json ~/my-service-approval/input/
```

If you don't add input files, the plugin uses built-in defaults (CCMv4 + MITRE ATT&CK).

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
6. **Recommended Guidance** — produces all security control artifacts and IaC templates
7. **Summarize** — produces SUMMARY-REPORT.md

The pipeline recommends controls + compliant IaC that you deploy yourself; it
does not deploy, test, or attest against a live account.

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
  05-recommended-guidance/        ← all generated artifacts (85+ files)
  06-summarize/       ← SUMMARY-REPORT.md (Summary Report)
```

The key deliverable is `06-summarize/SUMMARY-REPORT.md` — contains the coverage matrix, mitigation traceability, and artifact inventory.

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
- Check Docker is running for Terraform MCP
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
