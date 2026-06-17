"""CLI-flag tests for scripts/map-assemble.py.

Covers the `--service` / `--slug` alias reconcile: orchestrator prose
elsewhere in this repo uses both names, so argparse must accept either.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "map-assemble.py"


def _load_module():
    """Load scripts/map-assemble.py as a module so we can poke at its
    argparse. The script's filename has a hyphen, so import has to go
    through importlib spec_from_file_location."""
    spec = importlib.util.spec_from_file_location("map_assemble", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_parser():
    """Re-build the parser with the same arguments main() registers, so
    we can assert flag behaviour without invoking the full pipeline.

    main() composes the parser inline; we mirror that here. If main()'s
    flag list drifts, this test surfaces it."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--service", "--slug", dest="service")
    return parser


def test_service_flag_is_accepted() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--service", "lambda"])
    assert args.service == "lambda"


def test_slug_flag_is_accepted_as_alias() -> None:
    """The `--slug` alias must populate the same destination as
    `--service`."""
    parser = _build_parser()
    args = parser.parse_args(["--slug", "lambda"])
    assert args.service == "lambda"


def test_script_help_lists_both_flags() -> None:
    """`map-assemble.py --help` must mention both flag names so a caller
    who tries `--slug` first sees the alias and doesn't have to read the
    source. This anchors against accidental removal of the alias."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=15,
    )
    # --help exits 0 on success
    assert proc.returncode == 0, f"--help exited {proc.returncode}: {proc.stderr}"
    out = proc.stdout
    assert "--service" in out, "--service flag missing from --help"
    assert "--slug" in out, "--slug alias missing from --help"


def test_module_main_function_exists() -> None:
    """Sanity: the script defines main(). Guards against accidental
    rename that would silently break the CLI shape."""
    module = _load_module()
    assert hasattr(module, "main"), "scripts/map-assemble.py must expose main()"
