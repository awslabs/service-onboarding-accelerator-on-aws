# Service Approval Plugin

Generates AWS security control mappings and compliance assessments for any AWS service. Orchestrates a 6-phase pipeline (Intake → Assess → Research → Validate → Map → Summarize) and maps everything to CCMv4. Other frameworks (NIST 800-53, CIS, ISO 27001) remain available behind the `--framework=<type>` CLI flag for advanced operators; the interactive intake narrows to CCMv4.

## What it produces

- **Control mapping** - Maps threats and controls to security and compliance frameworks (e.g CCMv4, MITRE)
- **Approval report** - Summarizes the overall service onboarding assessment


Output lands in `.service-approval/<service-slug>/` (per-service layout) in your working directory:
```
.service-approval/<service-slug>/
  00-intake/              ← intake manifest
  01-assess/              ← SAR facts, checkpoints, assessment summary
  02-research/            ← research.json (merged from 4 sub-skills)
  03-validate/            ← validated.json
  04-map/                 ← mapping-results.json, controls-catalog.md, framework-mapping.md
  05-summarize/           ← APPROVAL-REPORT.md
  mcp-calls.log           ← MCP call audit log
```

---


### Key Features

The pipeline runs as 14 discrete skills under [`skills/`](skills/). Each one is a standalone [Agent Skills](https://agentskills.io) folder with its own `SKILL.md` — so the same skills work across Claude Code, Kiro, GitHub Copilot, and any other agentskills.io-compatible client.


### Artifact flow

Each phase consumes the previous phase's output — the pipeline is a strict DAG:

```
Input Files ──► Assess ──► Research ──► Validate ──► Map ──► Summarize
                  │           │            │          │          │
              sar-facts   research.json  validated  mapping   approval-
              checkpoints  (merged from  .json      results   report.md
              assessment    4 sub-skills)           .json
```

**Phase 1 (Research)** runs 4 parallel sub-skills — mitigations, capabilities, API surface,
and ATT&CK attack surface — then merges into `research.json` (schema v3.0).

**Phase 3 (Map)** produces the richest state — `mapping-results.json` contains:
- 60 controls organized by Category×Scope matrix (PRV:27, PRO:5, DET:22, COR:6)
- Threat-mitigation-control traceability (37 mitigations → controls → framework objectives)
- CCMv4 framework mapping (71 mapped / 126 N/A out of 197 objectives)
- ATT&CK technique coverage (17/21 techniques covered)
- Coverage gap analysis

---

## Installation

Pick the install path that matches your client.

**Claude Code only (recommended for Claude Code users)** — uses `manifest.yaml` as the source of truth, skips the multi-client detection, fastest:

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install-claude.sh
```

**All clients (Claude Code + Kiro + Copilot)** — auto-detects what's installed, wires up everything:

```bash
git clone git@github.com:awslabs/service-onboarding-accelerator-on-aws.git
cd service-onboarding-accelerator-on-aws
./install.sh        # macOS / Linux
# or Windows PowerShell:
.\install.ps1
```

Update with `git pull`. To make every `git pull` auto-sync .kiro/ and regenerate per-client manifests, run once:

```bash
make enable-auto-sync
```

See [`docs/INSTALL.md`](docs/INSTALL.md) for per-client notes. Windows needs Developer Mode ON for symlink installs (one-time toggle).

### Prerequisites per client

| Client | Prerequisite | Why |
|--------|--------------|-----|
| Claude Code / Copilot | none beyond the client itself | auto-discover from repo files |
| Kiro IDE | Kiro.app | manual Power install via the IDE Powers panel |
| Any client using `aws-documentation` / `awsiac` MCP | [`uv`](https://docs.astral.sh/uv/getting-started/installation/) on PATH | MCP servers run via `uvx awslabs.*@latest` |
| Any client using `terraform` MCP | Docker Desktop running | stdio MCP runs in a container |

## Usage guidelines

| Guide | |
|-------|-|
| [Claude Code](docs/USAGE-CLAUDE-CODE.md) | Scripted install, marketplace registration, slash command |
| [Kiro IDE](docs/USAGE-KIRO.md) | Power install via IDE, keyword invocation |
| [GitHub Copilot](docs/USAGE-COPILOT.md) | Zero-install auto-discovery, Agent mode |
| [Install reference](docs/INSTALL.md) | All clients, troubleshooting, uninstall |

---

## Flags

Note: if you do not provide any values, or custom threat models / frameworks in the input folder, the tool will default to CCMv4 and MITRE for the frameworks. 

| Flag | Description | Default |
|------|-------------|---------|
| `./input-folder` | Folder with input files (`.md`, `.json`, `.xlsx`, `.pdf`, `.docx`) | None |
| `--service=<name>` | AWS service ID (e.g., `bedrock-agentcore`, `s3`, `kms`) | Required if no folder |
| `--framework=<type>` | Control framework (`ccmv4`, `nist`, `cis`, `iso`) | `ccmv4` (asked at intake; flag bypasses the prompt) |
| `--framework-file=<path>` | Explicit path to framework file | Auto-detect from input |
| `--clean` | Delete existing `.service-approval/` state before run | false |

---

## Security
For information about contributing and reporting security issues, see [`CONTRIBUTING`](CONTRIBUTING.md).

---

## License
This project is licensed under the Apache-2.0 License.