#!/usr/bin/env python3
"""Adapt Codex patch/shell events to the shared validators.

PreToolUse gates explicit patch/write destinations. For shell commands, record
content hashes before execution and validate changed artifacts afterward.
Stop scans all phase files, including edits not observed by tool hooks, before
running the shared cross-artifact/integrity hook. No hook-trust settings are read
or written here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from paths import is_phase_dir_name  # noqa: E402


def workspace(event: dict) -> Path:
    """Locate runtime relative to the tool/session cwd, including subdirectories."""
    tool_input = event.get("tool_input", {})
    cwd = tool_input.get("workdir") or tool_input.get("cwd") or event.get("cwd") or os.getcwd()
    root = Path(cwd).resolve()
    for parent in (root, *root.parents):
        if parent.name == ".service-approval":
            return parent.parent
        if (parent / ".codex").is_dir() or (parent / "manifest.yaml").is_file():
            return parent
    return root


def patch_paths(event: dict, *, include_deletions: bool = True) -> list[Path]:
    args = event.get("tool_input", {})
    raw = []
    if event.get("tool_name") == "apply_patch":
        command = args.get("command", "")
        if not isinstance(command, str):
            raise ValueError("apply_patch hook input must provide tool_input.command")
        operations = "Add File|Update File|Move to"
        if include_deletions:
            operations += "|Delete File"
        raw.extend(re.findall(rf"^\*\*\* (?:{operations}): (.+)$", command, re.MULTILINE))
    else:
        path = args.get("file_path") or args.get("path")
        if isinstance(path, str):
            raw.append(path)
    cwd = Path(event.get("cwd") or os.getcwd())
    return list(dict.fromkeys((cwd / path).resolve() for path in raw))


def phase_files(root: Path) -> list[Path]:
    files = []
    base = root / ".service-approval"
    if not base.is_dir():
        return files
    runs = []
    for service in base.iterdir():
        if service.is_symlink() or not service.is_dir():
            continue
        if service.name == "_staging":
            runs.extend(p for p in service.iterdir() if p.is_dir() and not p.is_symlink())
        elif not service.name.startswith((".", "_")) and service.name != "plans":
            runs.append(service)
    for service in runs:
        for phase in service.iterdir():
            if phase.is_dir() and not phase.is_symlink() and is_phase_dir_name(phase.name):
                for current, dirs, names in os.walk(phase, followlinks=False):
                    dirs[:] = [d for d in dirs if not d.startswith(".")
                               and d not in ("__pycache__", "node_modules")]
                    files.extend(Path(current) / n for n in names
                                 if not n.startswith(".") and Path(n).suffix in
                                 (".json", ".yaml", ".yml", ".rego", ".guard", ".py", ".md")
                                 and not (Path(current) / n).is_symlink())
    return sorted(files)


def hashes(root: Path) -> dict[str, str]:
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in phase_files(root)}


def snapshot_path(root: Path, event: dict) -> Path:
    # Never use untrusted raw tool/session IDs as filesystem components.
    key = json.dumps([event.get("session_id"), event.get("tool_use_id")])
    name = hashlib.sha256(key.encode()).hexdigest()
    return root / ".service-approval/.codex-hooks" / f"{name}.json"


def invoke(script: str, root: Path, event: dict | None = None) -> tuple[int, str]:
    result = subprocess.run([sys.executable, str(Path(__file__).with_name(script))],
                            cwd=root, input=json.dumps(event) if event is not None else "",
                            text=True, capture_output=True)
    return result.returncode, result.stderr or result.stdout


def validate_paths(paths: list[Path], *, log: bool = True) -> list[str]:
    from validate_threat_model_input import check_artifact_prerequisite
    from validate_state import validate_state_file
    from validate_controls import validate_file
    from _hook_log import log_hook_fire
    errors = []
    for path in paths:
        if not path.is_file():
            continue  # Deletions are checked by phase completeness / Stop.
        parts = path.parts
        if ".service-approval" not in parts:
            continue
        index = len(parts) - 1 - list(reversed(parts)).index(".service-approval")
        rel = parts[index + 1:]
        phase_index = 2 if rel and rel[0] == "_staging" else 1
        if len(rel) <= phase_index + 1 or not is_phase_dir_name(rel[phase_index]):
            continue
        found = check_artifact_prerequisite(str(path))
        if not found:
            found = (validate_file(str(path)) if rel[phase_index] == "05-recommended-guidance"
                     else validate_state_file(str(path)))
        if log:
            log_hook_fire("post-tool-use", "fail" if found else "pass",
                          f"Codex validated {path.name}", file_path=str(path))
        errors.extend(found)
    return errors


def handle(event: dict) -> list[str]:
    root = workspace(event)
    kind = event.get("hook_event_name")
    paths = patch_paths(event, include_deletions=kind != "PreToolUse")
    shell = event.get("tool_name") == "Bash"
    if kind == "PreToolUse":
        errors = []
        for path in paths:
            code, message = invoke("hook_pre_tool_use.py", root,
                                   {"tool_name": "Write", "tool_input": {"file_path": str(path)}})
            if code:
                errors.append(message)
        if not errors and shell:
            snapshot = snapshot_path(root, event)
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_text(json.dumps(hashes(root)))
        return errors
    if kind == "PostToolUse":
        if shell:
            snapshot = snapshot_path(root, event)
            before = json.loads(snapshot.read_text()) if snapshot.exists() else {}
            after = hashes(root)
            paths.extend(Path(p) for p, digest in after.items() if before.get(p) != digest)
            snapshot.unlink(missing_ok=True)
        return validate_paths(list(dict.fromkeys(paths)))
    if kind == "Stop":
        # A repeated validation is not authoring progress. Do not reset the
        # shared Stop hook's identical-failure backstop by logging file checks.
        errors = validate_paths(phase_files(root), log=False)
        code, message = invoke("hook_stop.py", root)
        if code:
            errors.append(message)
        elif message.strip():
            # Shared hook warnings/snooze are surfaced as context, never parsed
            # as a Codex decision with an unsupported value.
            print(json.dumps({"systemMessage": message}))
        return errors
    return []


def main() -> int:
    # The documented install puts dependencies in the repo's virtualenv.
    # Re-exec before reading stdin so hooks work even with a minimal client PATH.
    venv = REPO / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv.is_file() and Path(sys.prefix).resolve() != (REPO / ".venv").resolve():
        os.execv(str(venv), [str(venv), str(Path(__file__).resolve())])
    try:
        event = json.load(sys.stdin)
        event.setdefault("cwd", os.getcwd())
        os.chdir(workspace(event))
        errors = handle(event)
    except Exception as exc:
        errors = [f"Service Approval hook could not validate: {exc}"]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
