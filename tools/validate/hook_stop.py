#!/usr/bin/env python3
"""
Stop hook: pipeline integrity validation.

Runs the pipeline integrity validator against `.service-approval/<slug>/`
when the agent signals completion:

  - `validate_pipeline_integrity` (P1, P2, P5, P6, P7) — strict-by-default;
    integrity errors always block (exit 2).

Only fires if a service directory with phase subdirs exists.

Exit codes:
    0 — pass, or warnings reported (non-blocking)
    2 — strict mode: validation failed (errors on stderr).

Self-suppression backstop: if the previous N consecutive hook:stop events for
a service are all `fail` with byte-identical `first_integrity` strings AND
nothing else changed in `pipeline.log` between them, exit 0 with a single
`hook:stop:snoozed` event instead of looping forever. This prevents the
17-hour identical-failure loop pathology where the harness re-fires Stop on
an idle agent turn that has no path to remediation. Reset triggers any time
real progress (any non-`hook:stop:fail` event) lands in pipeline.log.
"""

import json
import os
import re
import sys

# Allow sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _hook_log import log_hook_fire  # noqa: E402

# Number of consecutive identical hook:stop:fail entries before snoozing.
# 3 = ~3-5 minutes of repeats (cadence is roughly 1 fire/minute when the
# harness is idle), short enough to act, long enough that a real
# in-progress fix-and-retry won't trip it.
_SNOOZE_THRESHOLD = 3
# Capture the JSON-encoded string value for first_integrity. The log writer
# emits each `extra` value through json.dumps, so the raw substring on the
# log line is itself a valid JSON string (quotes + escapes). Decode it before
# comparing to the in-memory current_first_integrity (which is a plain str).
_FIRST_INTEGRITY_RE = re.compile(r'first_integrity=("(?:[^"\\]|\\.)*")')


def _should_snooze(service_dir: str, current_first_integrity: str | None) -> bool:
    """Detect the N-identical-fires loop.

    Reads `pipeline.log` at `<service_dir>/pipeline.log`.

    Returns True iff:
      1. Last `_SNOOZE_THRESHOLD` hook:stop entries are all `fail`.
      2. Their `first_integrity` strings are byte-identical to one another
         AND to the current run's first_integrity.
      3. No other event types appear interleaved (real progress would
         emit skill/mcp/script events between hook fires).
    """
    if current_first_integrity is None:
        return False
    pipeline_log = os.path.join(service_dir, "pipeline.log")
    if not os.path.isfile(pipeline_log):
        return False
    try:
        with open(pipeline_log) as f:
            lines = f.readlines()
    except OSError:
        return False

    # Walk backward; collect tail until we have N hook:stop entries OR hit a
    # non-hook:stop event (which resets the snooze).
    #
    # Any non-`hook:stop:fail` event resets — including events that land AFTER
    # the most recent fail (i.e., the most recent log line is a skill:end or
    # mcp:call). Earlier behavior only reset on events between fails, which
    # silently snoozed `[fail, fail, fail, skill:test:start]` and contradicted
    # the docstring's plain reading. Now matches the docstring.
    tail_fails: list[str] = []
    for ln in reversed(lines):
        if "[hook:stop:" in ln:
            if "[hook:stop:fail]" not in ln:
                # A pass/warn/snoozed entry resets — abort snooze check.
                return False
            tail_fails.append(ln)
            if len(tail_fails) >= _SNOOZE_THRESHOLD:
                break
        else:
            # Non-hook:stop event — real progress; reset regardless of
            # whether any fails have been collected yet.
            return False

    if len(tail_fails) < _SNOOZE_THRESHOLD:
        return False

    # All N tail entries must carry the same first_integrity as this run.
    # Log values pass through json.dumps, so decode each match before compare.
    for ln in tail_fails:
        m = _FIRST_INTEGRITY_RE.search(ln)
        if not m:
            return False
        try:
            decoded = json.loads(m.group(1))
        except json.JSONDecodeError:
            return False
        if decoded != current_first_integrity:
            return False
    return True


def main():
    cwd = os.getcwd()
    output_dir = os.path.join(cwd, ".service-approval")
    if not os.path.isdir(output_dir):
        sys.exit(0)

    # Find all service directories with phase subdirs
    service_dirs = []
    for item in os.listdir(output_dir):
        if item.startswith("_") or item == "plans":
            continue
        service_path = os.path.join(output_dir, item)
        if not os.path.isdir(service_path):
            continue
        # Check for any numbered phase directory
        has_phases = any(
            os.path.isdir(os.path.join(service_path, sub))
            for sub in os.listdir(service_path)
            if os.path.isdir(os.path.join(service_path, sub))
            and len(sub) > 3 and sub[:2].isdigit() and sub[2] == "-"
        )
        if has_phases:
            service_dirs.append(service_path)

    if not service_dirs:
        sys.exit(0)

    # --- Run validations for each service ---
    from validate_pipeline_integrity import validate_pipeline
    from pathlib import Path

    # Pipeline integrity validation (runs once per repo, iterates services internally)
    integrity_errors = validate_pipeline(Path(cwd))

    if not integrity_errors:
        for service_dir in service_dirs:
            log_hook_fire(
                "stop",
                "pass",
                "all integrity checks passed",
                file_path=service_dir,
            )
        sys.exit(0)

    # Self-suppression check: if the previous N consecutive hook:stop
    # entries for any service in scope are all identical-failure with
    # this run's first_integrity, snooze instead of re-blocking.
    current_first_integrity = integrity_errors[0][:200]
    snooze_dirs = [
        d for d in service_dirs
        if _should_snooze(d, current_first_integrity)
    ]
    if snooze_dirs and len(snooze_dirs) == len(service_dirs):
        for service_dir in service_dirs:
            log_hook_fire(
                "stop",
                "snoozed",
                f"suppressing identical failure (threshold={_SNOOZE_THRESHOLD}); "
                f"emit any non-hook:stop event in pipeline.log to reset",
                file_path=service_dir,
                extra={
                    "first_integrity": current_first_integrity,
                },
            )
        print(
            f"hook:stop snoozed — {_SNOOZE_THRESHOLD} consecutive identical "
            f"failures with no progress between. Emit any other pipeline.log "
            f"event to re-arm.",
            file=sys.stderr,
        )
        sys.exit(0)

    # Block: send errors to stderr so Claude can auto-fix
    print(f"PIPELINE INTEGRITY FAILED ({len(integrity_errors)} errors):", file=sys.stderr)
    for e in integrity_errors:
        print(f"  {e}", file=sys.stderr)
    for service_dir in service_dirs:
        log_hook_fire(
            "stop",
            "fail",
            f"integrity={len(integrity_errors)}",
            file_path=service_dir,
            extra={
                "first_integrity": current_first_integrity,
            },
        )
    sys.exit(2)


if __name__ == "__main__":
    main()
