"""Codex project configuration shared by the installer and manifest sync."""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import sys

try:
    import tomllib
except ImportError:  # Python 3.9/3.10
    import tomli as tomllib

START = "# BEGIN service-approval MCP (generated from manifest.yaml)"
END = "# END service-approval MCP"
LABEL = "Service Approval:"


def render_mcp(servers: dict) -> str:
    """Render only MCP transport fields; do not set permissions or hook trust."""
    lines = []
    for name, spec in servers.items():
        if spec.get("optional"):
            continue
        table = f"mcp_servers.{json.dumps(name)}"
        lines.append(f"[{table}]")
        for field in ("url", "command", "args"):
            if field in spec:
                lines.append(f"{field} = {json.dumps(spec[field])}")
        if spec.get("env"):
            lines.append(f"\n[{table}.env]")
            lines.extend(f"{json.dumps(k)} = {json.dumps(v)}" for k, v in spec["env"].items())
        lines.append("")
    return "\n".join(lines)


def merge_mcp(existing: str, servers: dict) -> str:
    # Validate both before and after editing; preserve unrelated TOML verbatim.
    tomllib.loads(existing)
    if START in existing or END in existing:
        if existing.count(START) != 1 or existing.count(END) != 1:
            raise ValueError("Invalid Service Approval MCP block markers")
        before, remainder = existing.split(START, 1)
        managed, after = remainder.split(END, 1)
        # Only our server tables may live in the replaceable block.
        parsed = tomllib.loads(managed)
        if set(parsed) - {"mcp_servers"} or set(parsed.get("mcp_servers", {})) - set(servers):
            raise ValueError("Move unrelated settings outside the Service Approval MCP block")
        outside = before + after
    else:
        before, after, outside = existing.rstrip() + ("\n\n" if existing.strip() else ""), "", existing
    duplicates = set(tomllib.loads(outside).get("mcp_servers", {})) & {
        name for name, spec in servers.items() if not spec.get("optional")
    }
    if duplicates:
        raise ValueError("Existing MCP entries outside the managed block: " + ", ".join(sorted(duplicates))
                         + ". Reconcile these project entries before installing; user config is untouched.")
    result = before + START + "\n" + render_mcp(servers) + END + after
    result = result.rstrip() + "\n"
    tomllib.loads(result)
    return result


def hook_groups(repo: Path | None = None) -> dict:
    # Checked-in commands resolve from Git. External workspaces get absolute
    # commands at setup time; these local paths are never generated into Git.
    if repo is None:
        command = 'python3 "$(git rev-parse --show-toplevel)/tools/validate/hook_codex.py"'
        windows = (
            "& { $saRoot = git rev-parse --show-toplevel; "
            "$saPython = Join-Path $saRoot '.venv/Scripts/python.exe'; "
            "if (-not (Test-Path $saPython)) { $saPython = 'python' }; "
            "& $saPython (Join-Path $saRoot 'tools/validate/hook_codex.py'); "
            "exit $LASTEXITCODE }"
        )
    else:
        command = shlex.join([sys.executable, str(repo / "tools/validate/hook_codex.py")])
        windows = "& " + " ".join("'" + v.replace("'", "''") + "'" for v in
                                 [sys.executable, str(repo / "tools/validate/hook_codex.py")])
        windows += "; exit $LASTEXITCODE"
    groups = {}
    for event, timeout in (("PreToolUse", 30), ("PostToolUse", 180), ("Stop", 180)):
        group = {"hooks": [{"type": "command", "command": command,
                            "commandWindows": windows, "timeout": timeout,
                            "statusMessage": f"{LABEL} {event} validation"}]}
        if event != "Stop":
            group["matcher"] = "Bash|apply_patch|Write|Edit|fs_write"
        groups[event] = [group]
    return groups


def merge_hooks(existing: dict, repo: Path | None = None) -> dict:
    if not isinstance(existing, dict) or not isinstance(existing.get("hooks", {}), dict):
        raise ValueError("Codex hooks.json must contain an object of hook events")
    result = dict(existing)
    events = {}
    for event, groups in existing.get("hooks", {}).items():
        if not isinstance(groups, list):
            raise ValueError(f"Hook event {event} must contain a list of matcher groups")
        kept = []
        for group in groups:
            handlers = [h for h in group["hooks"]
                        if not (h.get("statusMessage") or "").startswith(LABEL)]
            if handlers:
                kept.append({**group, "hooks": handlers})
        events[event] = kept
    for event, groups in hook_groups(repo).items():
        events.setdefault(event, []).extend(groups)
    result["hooks"] = events
    return result


def configure(workspace: Path, servers: dict, *, repo: Path | None = None,
              check: bool = False) -> bool:
    """Return drift; --check validates and reports without creating any files."""
    directory = workspace / ".codex"
    config = directory / "config.toml"
    hooks = directory / "hooks.json"
    # Compute both first: a conflict must not result in a partial update.
    expected = {
        config: merge_mcp(config.read_text() if config.exists() else "", servers),
        hooks: json.dumps(merge_hooks(json.loads(hooks.read_text()) if hooks.exists() else {}, repo),
                          indent=2) + "\n",
    }
    drift = False
    for path, content in expected.items():
        if path.exists() and path.read_text() == content:
            continue
        drift = True
        print(f"{'DRIFT' if check else 'wrote'}  {path.relative_to(workspace)}")
        if not check:
            directory.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    return drift


def link_instructions(workspace: Path, repo: Path, *, check: bool = False) -> None:
    links = {workspace / ".agents/skills": repo / "skills",
             workspace / "AGENTS.md": repo / "AGENTS.md"}
    for path, target in links.items():
        if path.exists() or path.is_symlink():
            if path.resolve() != target.resolve():
                raise ValueError(f"Existing {path} does not point to {target}; refusing to replace it")
    for path, target in links.items():
        if path.is_symlink():
            continue
        print(f"{'would link' if check else 'linked'}  {path} -> {target}")
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target, target_is_directory=target.is_dir())
