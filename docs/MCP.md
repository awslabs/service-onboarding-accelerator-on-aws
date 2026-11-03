# MCP configuration

The default configuration registers two required research servers:

- `aws-documentation` — AWS documentation via `uvx`.
- `awsknowledge` — the AWS Knowledge HTTP endpoint.

`mitre-attack` is optional and omitted from default configs and installer approval
lists. Without it, ATT&CK research uses `data/attack-cloud-matrix.json` and records
that source/version. If an enabled server fails, research falls back to that same
snapshot. A missing optional server is not a preflight failure, and agents must
not install it automatically.

## Codex

`install.sh` / `install.ps1` generate the two required servers in
[`.codex/config.toml`](../.codex/config.toml) from [`manifest.yaml`](../manifest.yaml),
alongside [validation hooks](../.codex/hooks.json). `--sync` / `-Sync` refresh them
after updates. No user-level configuration is modified.

The generated MCP block is owned by the installer. Put unrelated settings outside
its markers; the sync preserves them and other hook handlers. If required server
names already exist outside the managed block, setup stops before writing either
file so you can reconcile the duplicate project entries. Do not duplicate
connections supplied by an already-installed plugin.

Restart or reconnect the servers after changing the configuration. Verify both
servers with a documentation search and page read in the active Codex session;
a configured entry alone does not prove connectivity. See
[OpenAI's MCP documentation](https://developers.openai.com/codex/mcp/) for
configuration details and [Codex usage](USAGE-CODEX.md) for the complete workflow.
Codex loads project configuration only for trusted projects; hooks also require
review and trust. If `uvx` is unavailable, fix Codex's PATH before using the server.

The optional MITRE server is not needed for the documented setup. Codex can use
the bundled ATT&CK snapshot under the same rules as the other clients.

## Enable MITRE MCP

Print the current pinned configuration for your client:

```bash
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client claude-code
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client copilot
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client kiro
python3 tools/sync-ide-configs.py --optional-mcp-config mitre-attack --client codex
```

Run only the command for your client. These commands print a configuration
fragment; they do not edit any files. Merge the printed server entry into your
client's **user MCP configuration** using its MCP settings interface. Preserve
existing entries. For Kiro the user config is `~/.kiro/settings/mcp.json`; in VS
Code use the user MCP configuration opened by **MCP: Open User Configuration**.
Claude Code users can register the printed `uvx` command/arguments through
`claude mcp add --scope user`.
The Codex command prints TOML for its user `~/.codex/config.toml`.

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
