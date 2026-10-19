# Service Approval

Generate AWS security controls for services with a published **AWS Threat Model**.
Provide the service and optionally a control framework; the pipeline retrieves
the latest model from AWS and researches the service
against authoritative AWS sources, maps every capability to a control framework,
and produces a full set of **recommended** preventive, proactive, detective, and
responsive controls. It recommends the controls — **you deploy them yourself**;
the tool never touches a live account.

It runs as [Agent Skills](https://agentskills.io), so the same skills work in
Claude Code, Kiro, and GitHub Copilot.

---

## Prerequisites

You do **not** need to be an AWS user or have AWS credentials to generate
controls — every fact comes from public AWS documentation and knowledge sources.
You do need a few common developer tools.

| You need | When | Why |
|----------|------|-----|
| A published [AWS Threat Model](https://github.com/aws/threat-models-for-aws-services) and network access to GitHub | always | retrieved automatically from the latest release; unpublished services or retrieval failures stop the pipeline |
| One of: Claude Code, Kiro IDE, or VS Code + GitHub Copilot | always | the client that runs the skills |
| [`git`](https://git-scm.com/downloads) | always | to clone this repository |
| [Python](https://www.python.org/downloads/) 3.9 or newer | always | the validators and hooks that gate the pipeline |
| The Python packages in [`requirements.txt`](requirements.txt) | always | `pyyaml`, `jsonschema`, `pytest`, and helpers the tooling imports |
| [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on your PATH | default mode only | the `aws-documentation` MCP server runs via `uvx awslabs.*@latest`; **not** needed with `--no-mcp` |
| An AWS CLI profile | optional | only for Tier 2 policy validation (Access Analyzer); the pipeline never deploys |

### Set up from zero

If you are starting with none of the above, work through these once:

1. **Install a client** — [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview),
   [Kiro](https://kiro.dev/), or VS Code with the
   [GitHub Copilot](https://code.visualstudio.com/docs/copilot/overview) extension.
2. **Install git** — [git-scm.com/downloads](https://git-scm.com/downloads); check with `git --version`.
3. **Install Python 3.9+** — [python.org/downloads](https://www.python.org/downloads/);
   check with `python3 --version`.
4. **Clone the repo and install the Python packages** into a virtual environment:

   ```bash
   git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
   cd service-onboarding-accelerator-on-aws
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt      # macOS / Linux
   # Windows PowerShell:  py -m venv .venv ; .\.venv\Scripts\pip install -r requirements.txt
   ```

5. **Install `uv`** (default MCP mode only) —
   [astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/);
   check with `uv --version`. Skip if you will always run with `--no-mcp`.

Then run the [prerequisite check](#verify-your-setup) below to confirm everything
is in place, and continue to [Install](#install).

**Running without MCP:** MCP servers are the default, but the whole pipeline can
also run with no MCP servers at all — pass the `--no-mcp` flag and every fact is
verified over the web via an open-discovery search that reads and cites only
authoritative AWS sources. See [How no-MCP mode works](docs/NO-MCP.md) for the
full walkthrough and [`rules/web-access.md`](rules/web-access.md) for the policy.

### Verify your setup

Run the block for your shell from inside the cloned repo. Each line prints
`PASS` or `MISSING` so you can see what still needs installing. (`uv` is only
required for default MCP mode; a `MISSING` there is fine if you use `--no-mcp`.)

**macOS / Linux (bash):**

```bash
# Run from the repository root, after creating .venv (see step 4 above).
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS     $1"; else echo "MISSING  $1"; fi; }
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
check "git"                 "command -v git"
check "python3 (>=3.9)"     "$PY -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,9) else 1)'"
check "python venv (.venv)" "test -x .venv/bin/python"
check "pyyaml"              "$PY -c 'import yaml'"
check "jsonschema"          "$PY -c 'import jsonschema'"
check "pytest"              "$PY -c 'import pytest'"
check "uv (MCP mode only)"  "command -v uv"
```

**Windows (PowerShell):**

```powershell
# Run from the repository root, after creating .venv (see step 4 above).
function Check($name, $ok) { if ($ok) { "PASS     $name" } else { "MISSING  $name" } }
$py = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" } else { "python" }
Check "git"                 ([bool](Get-Command git -ErrorAction SilentlyContinue))
Check "python (>=3.9)"      ((& $py -c "import sys; print(1 if sys.version_info[:2] >= (3,9) else 0)") -eq "1")
Check "python venv (.venv)" (Test-Path .\.venv\Scripts\python.exe)
Check "pyyaml"              ((& $py -c "import yaml; print(1)" 2>$null) -eq "1")
Check "jsonschema"          ((& $py -c "import jsonschema; print(1)" 2>$null) -eq "1")
Check "pytest"              ((& $py -c "import pytest; print(1)" 2>$null) -eq "1")
Check "uv (MCP mode only)"  ([bool](Get-Command uv -ErrorAction SilentlyContinue))
```

---

## Install

Clone once, then pick the path that matches your client.

**Claude Code (fastest — uses `manifest.yaml` directly, skips multi-client detection):**

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install-claude.sh
```

**All clients (Claude Code + Kiro + Copilot — auto-detects what's installed):**

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install.sh          # macOS / Linux
# or Windows PowerShell:
.\install.ps1
```

Update any time with `git pull` (re-run the install script for Claude Code so the
marketplace symlink refreshes). To auto-sync on every pull:

```bash
make enable-auto-sync
```

Per-client details, marketplace registration, and uninstall live in the usage
guides:

| Client | Guide |
|--------|-------|
| Claude Code | [`docs/USAGE-CLAUDE-CODE.md`](docs/USAGE-CLAUDE-CODE.md) |
| Kiro IDE | [`docs/USAGE-KIRO.md`](docs/USAGE-KIRO.md) |
| GitHub Copilot | [`docs/USAGE-COPILOT.md`](docs/USAGE-COPILOT.md) |
| All clients + troubleshooting | [`docs/INSTALL.md`](docs/INSTALL.md) |
| Running without MCP | [`docs/NO-MCP.md`](docs/NO-MCP.md) |

> Windows needs Developer Mode ON for the symlink install (one-time toggle).

---

## MCP configuration

`awsknowledge` and `aws-documentation` are required in the default MCP mode.
`mitre-attack` is optional and disabled by default; ATT&CK mapping uses the bundled
snapshot unless you enable it. See [MCP configuration](docs/MCP.md).

## How to run

The pipeline retrieves the latest matching model from the public
[AWS Threat Models repository](https://github.com/aws/threat-models-for-aws-services).
You do not need a local JSON export. Optional frameworks and supporting documents
can still go in `./input/`; the folder itself is optional. User-added input content
is ignored recursively, except the two shipped examples. Custom `inputs/`,
`input-*/`, `input_*/`, and `runs/` folders are also ignored; use external paths for
arbitrarily named folders. Do not overwrite shipped samples with customer data.

Services and artifact paths are discovered through AWS's release manifest. Newly
published services and model updates need no tooling change. If AWS has not
published a matching model, the pipeline stops. Retrieval failures also stop the
run; local files, cached models, and flags cannot bypass the requirement.

Intake records a hash-verified snapshot and its commit. Every phase and resume
uses that same snapshot offline. Only an explicit new run fetches latest. Source
link and readable-report defects are reported as advisories without stopping a
run that has usable JSON. Downloaded
models and derived state stay under ignored `.service-approval/` paths and must
not be committed. Tests use synthetic fixtures. See [retrieval, migration, and
citation details](docs/THREAT-MODELS.md).

Invoke the pipeline and answer the short intake prompts. The intake step asks for
the service name and control framework; if you pass them as flags, it skips the
corresponding prompt.

**Claude Code** — slash command:

```
/service-approval ./input --service=lambda
```

**Kiro** — keyword or explicit invocation:

```
run service approval for lambda
```

**GitHub Copilot** — `@`-mention in Agent mode:

```
@service-approval ./input --service=lambda
```

### Framework selection

The default framework is **CCMv4** (with always-on MITRE ATT&CK threat mapping).
NIST 800-53, CIS Benchmarks, and ISO 27001 are available with `--framework=<type>`;
a custom framework is mapped directly to source-backed controls, using AWS Threat
Models as the primary evidence and CCMv4 guidance as an optional aid. If a framework
file is present in your input folder it is auto-detected; otherwise the intake step
asks (or you pass `--framework=`).

### A concrete example

```text
/service-approval --service=dsql --framework=ccmv4
```

This retrieves the latest published Aurora DSQL model, reads optional supporting
files, researches DSQL, and writes output under `.service-approval/dsql/`.
The generated control catalog and framework mapping link source aliases directly
to the readable AWS report at the fetched commit.

---

## What you get

Output lands in `.service-approval/<service-slug>/` in your working directory, one
directory per phase:

```
.service-approval/<service-slug>/
  00-intake/               ← intake manifest
  01-assess/               ← SAR facts, checkpoints, assessment summary
  02-research/             ← research.json (merged from 4 sub-skills)
  03-validate/             ← validated.json
  04-map/                  ← mapping-results.json, controls-catalog.md, framework-mapping.md
  05-recommended-guidance/ ← all generated control artifacts (preventive, proactive, detective, responsive)
  06-summarize/            ← SUMMARY-REPORT.md, ARTIFACT-FLOW-MATRIX.md
  mcp-calls.log            ← MCP call audit log
```

The key deliverable is **`06-summarize/SUMMARY-REPORT.md`** — the framework
coverage matrix, mitigation traceability, control inventory, and a preventive
coverage accounting.

The `05-recommended-guidance/` tree holds the artifacts. Exact counts vary by
service surface area; the ranges below reflect observed output across validated
services:

| Category | Files | Key artifacts |
|----------|-------|---------------|
| Preventive | 9–12 | SCPs (split), resource policies, KMS key policy, permission boundary, VPC endpoint, RCP, tag policies |
| Proactive | 12–15 | CFN Guard rules, OPA policies (per resource type), Checkov config + custom policies, CFN hooks |
| Detective | 34–47 | Config rules + Lambda handlers, EventBridge rules, CloudWatch alarms, Access Analyzer, compensating controls |
| Responsive | Varies | References to pre-authored AWS SSM Automation runbooks and how-to-use guides |


---

## The pipeline

The tool runs an Intake precursor plus six numbered phases. Each phase consumes the
previous phase's output — a strict DAG — and writes to its own directory.

![Pipeline flow](docs/pipeline-flow.drawio.png)

- **Intake** — collects the service and framework, verifies the current published
  AWS Threat Model, and saves a sealed snapshot → `intake-manifest.json`.
- **Assess** — 5-domain CAF security posture assessment.
- **Research** — discovers capabilities, API surface, and MITRE ATT&CK attack
  surface (4 parallel sub-skills, then merged) → `research.json`.
- **Validate** — cross-references every research claim via MCP → `validated.json`.
- **Map** — parses the framework, generates controls, maps them to objectives, and
  assembles → `mapping-results.json` + reports.
- **Recommended Guidance** — produces the control artifacts across all
  categories (preventive is a gated sub-pipeline).
- **Summarize** — the coverage matrix and control inventory → `SUMMARY-REPORT.md`.

The same model snapshot is used throughout the run and on offline resume.
Custom frameworks map directly to AWS Threat Model evidence; CCMv4 similarity
is supporting guidance. See [source verification and workspace upgrades](docs/THREAT-MODELS.md).

### Upgrading a workspace with old runs

Old completed runs may predate the current model-verification and reporting
requirements. Preserve their reports and retire them from the active sweep:

```bash
# Run from the customer workspace, using the installed repository's script path.
python3 /path/to/service-onboarding/tools/archive_run.py --slug dsql --reason upgrade
```

This moves the selected run under ignored `.service-approval/_archive/`, without
changing its reports or shared source snapshots. Then run `/service-approval`
normally. An archive is a historical record, not approval under the new checks.
See the [upgrade procedure](docs/THREAT-MODELS.md#upgrade-existing-workspaces).

---

## Flags

If you provide no framework flag or file, the tool defaults to CCMv4 with MITRE
ATT&CK threat mapping.

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Optional framework and supporting files | `./input/` |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`, `s3`, `kms`) | Required if no folder |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` (asked at intake; flag bypasses the prompt) |
| `--framework-file=<path>` | Explicit path to a framework file | Auto-detect from input |
| `--framework-specification="<text>"` | Free-text notes on a custom framework's structure (control/sub-control ID format, columns, grouping); if you supply a custom framework and omit this, intake offers to ask | None |
| `--from-intake=<file>` | Read an intake YAML instead of prompting | None |
| `--interactive` | Force the interactive intake form | false |
| `--include-unverified` | Include unverified findings in generation | false |
| `--dry-run` | Lint artifacts only, no deployment | false |
| `--clean` | Clear the selected service’s phase output after successful retrieval; preserve source snapshots | false |
| `--no-mcp` | Run without MCP servers — verify facts over the web (see "Running without MCP" above) | false (MCP is the default) |
| Plugin works in the repo but not elsewhere (Claude Code) | The marketplace registration didn't take — `claude plugin marketplace add .` then `claude plugin install service-approval@service-approval --scope user`. |
| A phase reports too few MCP calls / integrity failure | The Stop hook enforces pipeline integrity (P1–P7); read `06-summarize/SUMMARY-REPORT.md` and `pipeline.log` for which check failed, then re-run from the failing phase. |

---

## Validation

The **published AWS Threat Model gate** retrieves current upstream data before
assessment/research for new runs and rechecks the original snapshot locally on resume. Intake records
`inputs.threat_model_file` and `inputs.threat_model_source`. Pre-write hooks,
phase preconditions, and pipeline integrity enforce the model's shape, service
identity, the authenticated intake seal, and snapshot hash. Only online intake
checks AWS publication; offline resume verifies the prior intake and unchanged
snapshot. AWS capability claims still
require Research/Validate verification.

Two complementary layers keep the output trustworthy.

The **review gates and correctness checks** that run *during* the pipeline — two
review gates, the root-cause critic, reference-anchor enforcement, the
AWS Threat Model-factual check, and conflict detection — are described in
[`docs/DESIGN.md`](docs/DESIGN.md).

The **artifact correctness checks** below confirm the generated control
artifacts are syntactically valid and policy-sound, and run automatically at
session end:

**Tier 1 — Static (no credentials)**
- JSON/YAML parse, Python handler compilation
- cfn-lint, CFN Guard syntax, OPA check

**Tier 2 — AWS API (credentials required)**
- IAM Access Analyzer `validate-policy` for SCPs, identity policies, resource policies

---

## How it works / accuracy model


The pipeline is built around a deterministic, citation-gated mapping layer and
reference-anchored preventive controls: every confident mapping cites its evidence,
and every preventive policy is adapted from a published AWS sample rather than
invented. The full accuracy model — the applicability screen, AWS Threat Model traceability
and citation verification, per-domain coverage ceilings, the source-priority order,
and the validation layers — is documented in **[`docs/DESIGN.md`](docs/DESIGN.md)**.

The skills that make up the pipeline live under [`skills/`](skills/); each is a
standalone Agent Skills folder with its own `SKILL.md`, so the same skills work
across every supported client.

---

## Security

For information about contributing and reporting security issues, see
[`CONTRIBUTING`](CONTRIBUTING.md).

## License

This project is licensed under the Apache License, Version 2.0 (`Apache-2.0`).
See [`LICENSE`](LICENSE) for the full terms and [`DISCLAIMER`](DISCLAIMER.md)
for guidance on evaluating and using the project's outputs.
