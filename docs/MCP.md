# MCP configuration

The default configuration registers two required research servers:

- `aws-documentation` — AWS documentation via `uvx`.
- `awsknowledge` — the AWS Knowledge HTTP endpoint.

`mitre-attack` is optional and omitted from default configs and installer approval
lists. Without it, ATT&CK research uses `data/attack-cloud-matrix.json` and records
that source/version. If an enabled server fails, research falls back to that same
snapshot. A missing optional server is not a preflight failure, and agents must
not install it automatically.

## Enable MITRE MCP

Print the current pinned configuration for your client:

```bash
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client claude-code
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client copilot
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client kiro
```

Run only the command for your client. These commands print a configuration
fragment; they do not edit any files. Merge the printed server entry into your
client's **user MCP configuration** using its MCP settings interface. Preserve
existing entries. For Kiro the user config is `~/.kiro/settings/mcp.json`; in VS
Code use the user MCP configuration opened by **MCP: Open User Configuration**.
Claude Code users can register the printed `uvx` command/arguments through
`claude mcp add --scope user`.

Keep this personal opt-in out of the repository's generated configs. Running the
normal sync command regenerates the required-only defaults. The manifest remains
the source of the optional server's pinned package version.

The Copilot agent's tool allowlist includes the optional server so its tools can
be used when connected; this does not register, install, or enable that server.
For headless runs with MITRE explicitly enabled, add `mitre-attack` to your client's
trusted-tool list alongside the two required servers.

## Run without MCP

The separate `--no-mcp` mode verifies AWS facts through web access. It does not
require any MCP servers. See [NO-MCP.md](NO-MCP.md); published threat-model retrieval
still requires network access as described in [THREAT-MODELS.md](THREAT-MODELS.md).
