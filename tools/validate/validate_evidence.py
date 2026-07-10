"""Decommissioned no-op validator (retained for reversibility).

The pipeline recommends controls + IaC that the customer deploys themselves;
it no longer runs a live evidence/attestation phase. The check functions
below are retained as no-ops so any residual import resolves and never
blocks — each returns an empty error list, and `main()` always exits 0.

The file is kept on disk (not deleted) so the evidence flow can be
re-enabled without recovering it from history.
"""
from __future__ import annotations

import sys
from pathlib import Path


def check_cli_commands(data: dict) -> list[str]:
    """No-op — always returns no errors."""
    return []


def check_attestation_results(
    data: dict,
    evidence_dir: Path | None = None,
) -> list[str]:
    """No-op — always returns no errors."""
    return []


def check_deployed_resources(data: dict) -> list[str]:
    """No-op — always returns no errors."""
    return []


def main() -> None:
    """Always exits 0 — this validator no longer gates the pipeline."""
    sys.exit(0)


if __name__ == "__main__":
    main()
