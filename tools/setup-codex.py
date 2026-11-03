#!/usr/bin/env python3
"""Install the same Codex configuration in an external runtime workspace."""
import argparse
from pathlib import Path
import sys

import yaml

from codex_config import configure, link_instructions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    workspace = args.workspace.expanduser().resolve()
    if workspace == repo or repo in workspace.parents:
        parser.error("Choose a workspace outside the source checkout; install.sh handles the checkout")
    servers = yaml.safe_load((repo / "manifest.yaml").read_text())["mcp_servers"]
    try:
        # Validate link conflicts and config conflicts before any writes.
        link_instructions(workspace, repo, check=True)
        configure(workspace, servers, repo=repo, check=True)
        if not args.check:
            configure(workspace, servers, repo=repo)
            link_instructions(workspace, repo)
    except (ValueError, OSError) as exc:
        print(f"Codex setup failed: {exc}", file=sys.stderr)
        return 2
    print("Open the workspace in Codex, trust the project, and review its hooks before running.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
