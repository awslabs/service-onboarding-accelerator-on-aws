"""Codex transport, config preservation, and installer regressions.

All model/run material is synthetic and scoped to pytest's temporary directory.
No tests change Codex's native project/hook trust or the user's configuration.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

import hook_codex
from test_threat_model_integrity import run as synthetic_run, write

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("codex_config", REPO / "tools/codex_config.py")
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
SERVERS = yaml.safe_load((REPO / "manifest.yaml").read_text())["mcp_servers"]


def call_hook(root, event):
    return subprocess.run(
        [sys.executable, str(REPO / "tools/validate/hook_codex.py")],
        input=json.dumps({"cwd": str(root), "session_id": "test", "tool_use_id": "call", **event}),
        cwd=root, text=True, capture_output=True,
    )


def test_default_and_optional_mcp_configs():
    default = config.tomllib.loads(config.render_mcp(SERVERS))
    assert set(default) == {"mcp_servers"}
    assert set(default["mcp_servers"]) == {"aws-documentation", "awsknowledge"}
    result = subprocess.run(
        [sys.executable, str(REPO / "tools/sync-ide-configs.py"), "--client", "codex",
         "--optional-mcp-config", "mitre-attack"], capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert set(config.tomllib.loads(result.stdout)["mcp_servers"]) == {"mitre-attack"}


def test_mcp_updates_preserve_unrelated_text_and_are_idempotent():
    before = '# keep this comment\nmodel = "example"\n[mcp_servers.personal]\ncommand = "example"\n'
    installed = config.merge_mcp(before, SERVERS)
    assert before in installed
    assert config.merge_mcp(installed, SERVERS) == installed
    updated = {**SERVERS, "aws-documentation": {**SERVERS["aws-documentation"], "args": ["new-pin"]}}
    changed = config.merge_mcp(installed, updated)
    assert config.tomllib.loads(changed)["mcp_servers"]["aws-documentation"]["args"] == ["new-pin"]
    assert before in changed


@pytest.mark.parametrize("existing", [
    '[mcp_servers.awsknowledge]\nurl="https://example.test"\n',
    config.START + "\n[personal]\nx=1\n" + config.END,
    config.START,
    "not valid TOML",
])
def test_conflicts_do_not_partially_write_config(tmp_path, existing):
    directory = tmp_path / ".codex"; directory.mkdir()
    target = directory / "config.toml"; target.write_text(existing)
    with pytest.raises(ValueError):
        config.configure(tmp_path, SERVERS)
    assert target.read_text() == existing
    assert not (directory / "hooks.json").exists()


def test_hook_merging_keeps_other_handlers_and_does_not_grant_trust():
    personal = {"type": "command", "command": "personal", "timeout": 2}
    old = {"description": "mine", "hooks": {"Stop": [{"hooks": [personal]}]}}
    merged = config.merge_hooks(old)
    assert merged["description"] == "mine"
    assert merged["hooks"]["Stop"][0]["hooks"] == [personal]
    assert config.merge_hooks(merged) == merged
    assert not any(s in json.dumps(merged) for s in ("trust_level", "bypass", "approval_policy"))


def test_external_setup_checks_then_installs_idempotently(tmp_path):
    root = tmp_path / "customer workspace"
    command = [sys.executable, str(REPO / "tools/setup-codex.py"), "--workspace", str(root)]
    checked = subprocess.run([*command, "--check"], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert not root.exists()
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (root / ".agents/skills").resolve() == REPO / "skills"
    assert (root / "AGENTS.md").resolve() == REPO / "AGENTS.md"
    first = {p.name: p.read_bytes() for p in (root / ".codex").iterdir()}
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert {p.name: p.read_bytes() for p in (root / ".codex").iterdir()} == first
    hook = json.loads(first["hooks.json"])["hooks"]["Stop"][0]["hooks"][0]
    # Execute the actual generated command, with paths containing spaces.
    result = subprocess.run(hook["command"], shell=True, cwd=root,
                            input=json.dumps({"hook_event_name": "Stop", "cwd": str(root)}),
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_external_setup_preserves_existing_instructions(tmp_path):
    instructions = tmp_path / "AGENTS.md"; instructions.write_text("Personal instructions")
    result = subprocess.run(
        [sys.executable, str(REPO / "tools/setup-codex.py"), "--workspace", str(tmp_path)],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
    assert instructions.read_text() == "Personal instructions"
    assert not (tmp_path / ".codex").exists()


def test_patch_multi_file_move_is_gated_before_execution(tmp_path):
    patch = ("*** Begin Patch\n*** Update File: README.md\n@@\n-x\n+y\n"
             "*** Add File: .service-approval/lambda/02-research/research.json\n+{}\n"
             "*** Update File: draft.json\n"
             "*** Move to: .service-approval/lambda/03-validate/validated.json\n@@\n-{}\n+{}\n"
             "*** End Patch")
    event = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "tool_input": {"command": patch}}
    result = call_hook(tmp_path, event)
    assert result.returncode == 2
    assert "AWS THREAT MODEL REQUIRED" in result.stderr
    assert len(hook_codex.patch_paths({**event, "cwd": str(tmp_path)})) == 4


def test_unrelated_patch_does_not_require_a_pipeline(tmp_path):
    result = call_hook(tmp_path, {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                                 "tool_input": {"command": "*** Begin Patch\n*** Add File: README.md\n+hi\n*** End Patch"}})
    assert result.returncode == 0, result.stderr


def test_delete_does_not_require_missing_source_but_replacement_does(tmp_path):
    path = ".service-approval/lambda/02-research/broken.json"
    delete = f"*** Begin Patch\n*** Delete File: {path}\n*** End Patch"
    event = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
             "tool_input": {"command": delete}}
    assert call_hook(tmp_path, event).returncode == 0
    event["tool_input"]["command"] = delete.replace("*** End Patch",
        f"*** Add File: {path}\n+{{}}\n*** End Patch")
    assert call_hook(tmp_path, event).returncode == 2


def test_valid_source_allows_patch_then_invalid_state_is_rejected(tmp_path):
    root, _ = synthetic_run(tmp_path)
    path = root / "02-research/extra.json"
    event = {"tool_name": "apply_patch", "tool_input": {
        "command": f"*** Begin Patch\n*** Add File: {path}\n+{{bad\n*** End Patch"}}
    assert call_hook(tmp_path, {**event, "hook_event_name": "PreToolUse"}).returncode == 0
    path.parent.mkdir(); path.write_text("{bad")
    result = call_hook(tmp_path, {**event, "hook_event_name": "PostToolUse"})
    assert result.returncode == 2 and "JSON syntax error" in result.stderr
    path.write_text("{}")
    assert call_hook(tmp_path, {**event, "hook_event_name": "PostToolUse"}).returncode == 0


def test_shell_edits_checked_by_content_even_if_mtime_and_size_are_preserved(tmp_path):
    root, _ = synthetic_run(tmp_path)
    path = write(root / "02-research/extra.json", {})
    stat = path.stat()
    event = {"tool_name": "Bash", "tool_input": {"command": "some shell edit"}}
    assert call_hook(tmp_path, {**event, "hook_event_name": "PreToolUse"}).returncode == 0
    path.write_text("{x")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    result = call_hook(tmp_path, {**event, "hook_event_name": "PostToolUse"})
    assert result.returncode == 2 and "JSON syntax error" in result.stderr
    assert not list((tmp_path / ".service-approval/.codex-hooks").glob("*.json"))


def test_shell_without_pre_snapshot_still_checks_artifacts(tmp_path):
    root, _ = synthetic_run(tmp_path)
    path = root / "02-research/extra.json"; path.parent.mkdir(); path.write_text("{bad")
    result = call_hook(tmp_path, {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                 "tool_input": {"command": "edit"}})
    assert result.returncode == 2 and "JSON syntax error" in result.stderr


def test_staging_intake_is_checked_after_shell_write(tmp_path):
    path = tmp_path / ".service-approval/_staging/2026-01-01T00-00-00Z/00-intake/intake-manifest.json"
    path.parent.mkdir(parents=True); path.write_text("{bad")
    result = call_hook(tmp_path, {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                                 "tool_input": {"command": "write intake"}})
    assert result.returncode == 2 and "JSON syntax error" in result.stderr


def test_concurrent_shell_calls_have_separate_snapshots(tmp_path):
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "edit"}}
    assert call_hook(tmp_path, {**event, "tool_use_id": "first"}).returncode == 0
    assert call_hook(tmp_path, {**event, "tool_use_id": "second"}).returncode == 0
    assert len(list((tmp_path / ".service-approval/.codex-hooks").glob("*.json"))) == 2
    assert call_hook(tmp_path, {**event, "tool_use_id": "first", "hook_event_name": "PostToolUse"}).returncode == 0
    assert len(list((tmp_path / ".service-approval/.codex-hooks").glob("*.json"))) == 1


def test_stop_catches_unobserved_write_and_runs_shared_integrity(tmp_path):
    root, _ = synthetic_run(tmp_path)
    path = root / "05-recommended-guidance/preventive/extra.json"
    path.parent.mkdir(parents=True); path.write_text("{bad")
    result = call_hook(tmp_path, {"hook_event_name": "Stop"})
    assert result.returncode == 2
    assert "json_syntax" in result.stderr
    assert "PIPELINE INTEGRITY FAILED" in result.stderr


def test_workspace_resolution_uses_tool_workdir_and_project_parent(tmp_path):
    root = tmp_path / "run"; (root / ".codex").mkdir(parents=True)
    child = root / "nested"; child.mkdir()
    assert hook_codex.workspace({"cwd": str(tmp_path), "tool_input": {"workdir": str(child)}}) == root


def test_stop_file_scan_does_not_log_false_progress(tmp_path):
    root, _ = synthetic_run(tmp_path)
    write(root / "02-research/extra.json", {})
    assert hook_codex.validate_paths(hook_codex.phase_files(tmp_path), log=False) == []
    assert not (root / "pipeline.log").exists()


@pytest.fixture
def install_checkout(tmp_path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for name in ("tools", "powers", ".claude-plugin", ".github", ".vscode", ".agents"):
        shutil.copytree(REPO / name, checkout / name, symlinks=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # The shared skill link needs only the actual entry-point file for detection.
    entry = checkout / "skills/service-approval"; entry.mkdir(parents=True)
    shutil.copy(REPO / "skills/service-approval/SKILL.md", entry / "SKILL.md")
    for name in ("manifest.yaml", "install.sh"):
        shutil.copy(REPO / name, checkout / name)
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
    return checkout, env


@pytest.mark.parametrize("mode", [[], ["--sync"], ["--quiet"]])
def test_installer_generates_codex_and_second_check_does_not_write(install_checkout, mode):
    root, env = install_checkout
    result = subprocess.run(["bash", "install.sh", *mode], cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    if mode == ["--quiet"]:
        assert result.stdout == ""
    assert (root / ".codex/config.toml").is_file()
    assert (root / ".codex/hooks.json").is_file()
    saved = {p: p.stat().st_mtime_ns for p in (root / ".codex").iterdir()}
    result = subprocess.run(["bash", "install.sh", "--check"], cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert {p: p.stat().st_mtime_ns for p in saved} == saved


def test_installer_reports_sync_failure(install_checkout):
    root, env = install_checkout
    (root / ".codex").mkdir()
    (root / ".codex/config.toml").write_text("[mcp_servers.awsknowledge]\nurl='custom'\n")
    result = subprocess.run(["bash", "install.sh"], cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "configuration failed" in result.stderr


def test_portable_hook_command_runs_from_nested_git_directory(install_checkout):
    root, env = install_checkout
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    result = subprocess.run(["bash", "install.sh"], cwd=root, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    nested = root / "nested"; nested.mkdir()
    hook = json.loads((root / ".codex/hooks.json").read_text())["hooks"]["Stop"][0]["hooks"][0]
    result = subprocess.run(hook["command"], shell=True, cwd=nested, env=env,
                            input=json.dumps({"cwd": str(nested), "hook_event_name": "Stop"}),
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
