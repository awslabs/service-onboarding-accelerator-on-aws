#!/usr/bin/env python3
"""Retire a selected run without deleting its reports or certifying its validity."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tempfile


def archive_run(workspace: Path, slug: str, reason: str = "upgrade") -> Path:
    """Atomically move an explicitly selected run outside the active sweep.

    Completion markers grant no exemption. Archives are historical records, not
    current validation results, and cannot be resumed in place. Shared snapshot
    directories remain untouched, preserving other runs' source references.
    """
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", slug):
        raise ValueError("Invalid service slug")
    workspace = workspace.resolve()
    output = workspace / ".service-approval"
    run = output / slug
    archive = output / "_archive"
    if output.is_symlink() or run.is_symlink() or archive.is_symlink():
        raise ValueError("Refusing to archive through a symlink")
    if not run.is_dir() or not any(
        child.is_dir() and re.fullmatch(r"0[0-6]-[a-z-]+", child.name)
        for child in run.iterdir()
    ):
        raise ValueError(f"No active pipeline run found at {run}")
    inventory = {}
    for item in sorted(run.rglob("*")):
        if item.is_symlink():
            raise ValueError(f"Run contains a symlink; archive it manually outside the workspace: {item}")
        if item.is_file():
            inventory[str(item.relative_to(run))] = hashlib.sha256(item.read_bytes()).hexdigest()
    archive.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    destination = Path(tempfile.mkdtemp(prefix=f"{slug}-{now:%Y%m%dT%H%M%SZ}-", dir=archive))
    receipt = destination / "archive.json"
    try:
        receipt.write_text(json.dumps({
            "version": 1,
            "service_slug": slug,
            "archived_at": now.isoformat(),
            "reason": reason,
            "original_path": str(run),
            "status": "historical archive; not validated by the current pipeline",
            "files_sha256": inventory,
        }, indent=2) + "\n")
        run.rename(destination / "run")
    except Exception:
        # A failed move must leave the original run active and intact.
        receipt.unlink(missing_ok=True)
        destination.rmdir()
        raise
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True, help="Exact active service directory to retire")
    parser.add_argument("--reason", default="upgrade", help="Reason recorded in archive.json")
    args = parser.parse_args()
    try:
        destination = archive_run(Path.cwd(), args.slug, args.reason)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Run was not archived: {exc}\n")
    print(f"Archived historical run: {destination}\n"
          "Reports are preserved; this is not current validation or approval. "
          "Start a fresh /service-approval run to use the current pipeline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
