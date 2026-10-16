"""Optional MCP opt-in must not register a server or alter default configs."""
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SYNC = REPO / "tools/sync-ide-configs.py"
CONFIGS = {
    "claude-code": (".mcp.json", "mcpServers"),
    "copilot": (".vscode/mcp.json", "servers"),
    "kiro": ("powers/service-approval/mcp.json", "mcpServers"),
}


@pytest.mark.parametrize("client", CONFIGS)
def test_default_registration_and_explicit_opt_in_are_separate(client):
    config_path, key = CONFIGS[client]
    saved = {name: (REPO / name).read_bytes() for name, _ in CONFIGS.values()}
    assert set(json.loads(saved[config_path])[key]) == {"aws-documentation", "awsknowledge"}
    result = subprocess.run(
        [sys.executable, str(SYNC), "--optional-mcp-config", "mitre-attack", "--client", client],
        cwd=REPO, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    servers = json.loads(result.stdout)[key]
    assert set(servers) == {"mitre-attack"}
    registry = yaml.safe_load((REPO / "manifest.yaml").read_text())["mcp_servers"]
    assert servers["mitre-attack"]["args"] == registry["mitre-attack"]["args"]
    assert servers["mitre-attack"]["command"] == "uvx"
    assert "optional" not in servers["mitre-attack"]  # registry metadata is not client protocol
    assert {name: (REPO / name).read_bytes() for name in saved} == saved


@pytest.mark.parametrize("args", [
    ["--optional-mcp-config", "mitre-attack"],
    ["--optional-mcp-config", "mitre-attack", "--client", "kiro", "--check"],
    ["--optional-mcp-config", "aws-documentation", "--client", "claude-code"],
    ["--optional-mcp-config", "unknown-server", "--client", "copilot"],
])
def test_invalid_optional_config_requests_fail_without_writes(args):
    saved = {name: (REPO / name).read_bytes() for name, _ in CONFIGS.values()}
    result = subprocess.run([sys.executable, str(SYNC), *args], cwd=REPO, capture_output=True)
    assert result.returncode == 2
    assert {name: (REPO / name).read_bytes() for name in saved} == saved
