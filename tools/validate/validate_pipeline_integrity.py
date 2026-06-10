#!/usr/bin/env python3
"""
Pipeline integrity validator.

Detects agents that skip the 6-phase pipeline (Intake → Assess → Research →
Validate → Map → Summarize) and emit hardcoded artifacts instead of running
real MCP-driven research/validation.

Fires from the Stop hook. Exits 2 on failure so Claude Code auto-retries.

Failure signals:
    P1 — pipeline.log / mcp-calls.log missing or too few MCP calls
         (exempted when pipeline.log carries the
         `[pipeline:complete:<VERDICT>]` terminal sentinel — finalized
         runs are immutable, retroactive remediation impossible)
    P2 — validated.json has templated or empty verification notes
    P5 — framework coverage below threshold with no per-objective rationale
    P6 — verdict mismatch (APPROVED emitted despite integrity failures)
    P7 — phase-output completeness: every phase dir on disk must contain
         its declared outputs (mapping-results.json, controls-catalog.md,
         framework-mapping.md, etc.) at min-size thresholds
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


MIN_MCP_CALLS = 10
MIN_FRAMEWORK_COVERAGE_PCT = 15


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


_MCP_CALL_TOKEN_RE = re.compile(r"\[mcp:[^\]]+:call\]")
# Terminal-state sentinel emitted by summarize/evidence at end of pipeline.
# Anchor at the source-tag column (3rd bracketed token of a pipeline.log
# line) so a message body containing the literal text can't satisfy the
# gate. Line shape: `<iso8601> [<phase>] [<source>:<verdict>]  <message>`.
# Verdict allowlist is closed: APPROVED | APPROVED_WITH_EXCEPTIONS |
# REQUIRES_REMEDIATION. Anything else does NOT close out the run.
_PIPELINE_COMPLETE_RE = re.compile(
    r"^\S+\s+\[\S+\]\s+\[pipeline:complete:"
    r"(APPROVED|APPROVED_WITH_EXCEPTIONS|REQUIRES_REMEDIATION)\]",
    re.MULTILINE,
)


def check_mcp_log(service_root: Path) -> list[str]:
    """Check MCP call count from the consolidated pipeline.log.

    Counts lines whose source matches the canonical `[mcp:<server>:call]`
    token in pipeline.log. Anchored regex so a message field that happens
    to contain the literal text `[mcp:` or `:call]` cannot inflate the
    count (e.g., a `skill:research:start` event whose message describes
    "starting [mcp:awsknowledge:call] phase" would substring-match but not
    regex-match).

    Falls back to the legacy mcp-calls.log shadow file. Legacy lines start
    with literal "MCP CALL"; we anchor with `startswith` so a message
    containing "MCP CALL" mid-line doesn't inflate the count either.

    Terminal-state exemption: if pipeline.log carries a
    `[pipeline:complete:<verdict>]` sentinel, the run is finalized and the
    file is frozen. P1 cannot be remediated retroactively, so the check
    returns no error for sentinel-bearing files. Mid-flight runs (no
    sentinel) still get the strict count.
    """
    errors: list[str] = []
    pipeline_log = service_root / "pipeline.log"
    mcp_shadow = service_root / "mcp-calls.log"

    if pipeline_log.exists():
        content = pipeline_log.read_text()
        if _PIPELINE_COMPLETE_RE.search(content):
            return []
    else:
        content = ""

    call_lines: list[str] = []

    if pipeline_log.exists():
        call_lines.extend(
            ln for ln in content.splitlines()
            if _MCP_CALL_TOKEN_RE.search(ln)
        )

    # Either source — pipeline.log uses the new format; mcp-calls.log may
    # still receive raw "MCP CALL" lines from older skills/scripts.
    if mcp_shadow.exists() and not call_lines:
        content = mcp_shadow.read_text()
        call_lines = [
            ln for ln in content.splitlines()
            if ln.startswith("MCP CALL") or ln.startswith("MCP call")
            or _MCP_CALL_TOKEN_RE.search(ln)
        ]

    if not pipeline_log.exists() and not mcp_shadow.exists():
        return [
            "P1 neither pipeline.log nor mcp-calls.log exists at service "
            "root — pipeline must log every MCP call to pipeline.log"
        ]

    if len(call_lines) < MIN_MCP_CALLS:
        errors.append(
            f"P1 pipeline.log has {len(call_lines)} logged MCP calls "
            f"(minimum {MIN_MCP_CALLS}). Validate and Research phases must "
            f"call MCP for every capability, API parameter, and condition key."
        )
    return errors


def check_validated_notes(validate_dir: Path) -> list[str]:
    """Check validated.json in 03-validate/ phase dir.

    P2 gate: a missing or unreadable validated.json is a hard fail —
    Phase 2 (Validate) is mandatory and its absence means the pipeline
    skipped a required phase. Previously this function returned `[]`
    silently, letting the gate pass open.
    """
    errors: list[str] = []
    validated_path = validate_dir / "validated.json"
    validated = _load_json(validated_path)
    if validated is None:
        if validated_path.exists():
            errors.append(
                f"P2 FAIL: {validated_path} exists but failed to parse as JSON. "
                "Phase 2 (Validate) must produce a well-formed validated.json."
            )
        else:
            errors.append(
                f"P2 FAIL: {validated_path} is missing. Phase 2 (Validate) is "
                "mandatory — every pipeline run must produce validated.json with "
                "verification notes for each capability claim."
            )
        return errors
    if not validated:
        # Empty dict — file exists, parses, but contains nothing meaningful.
        errors.append(
            f"P2 FAIL: {validated_path} is empty. Phase 2 (Validate) must "
            "produce content — at minimum, capabilities and verification notes."
        )
        return errors

    notes: list[str] = []

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("verification_note", "feasibility_note") and isinstance(v, str):
                    notes.append(v.strip())
                else:
                    walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(validated)

    if not notes:
        errors.append(
            "P2 validated.json has zero verification_note fields. "
            "Every capability, API parameter, and condition key must have a "
            "specific per-item verification note."
        )
        return errors

    unique_ratio = len(set(notes)) / len(notes)
    if unique_ratio < 0.5:
        errors.append(
            f"P2 validated.json verification notes are {int((1 - unique_ratio) * 100)}% "
            f"duplicated ({len(notes)} total, {len(set(notes))} unique). "
            f"Notes must be specific to each item, not templated."
        )

    summary = validated.get("verification", {}).get("summary", "")
    if summary and len(summary) < 40:
        errors.append(
            f"P2 validated.json verification.summary is too short "
            f"({len(summary)} chars) — looks templated: {summary!r}"
        )

    return errors




def check_framework_coverage(map_dir: Path) -> list[str]:
    """Check framework coverage from 04-map/ phase dir.

    Fails closed when 04-map/ exists but neither mapping-results.json nor
    map-framework-mapped.json is loadable, OR when the loaded JSON lacks
    a non-empty `framework_mapping` key. P7's size threshold is
    content-blind (>=1024 bytes); a 1024-byte JSON without the
    framework_mapping key would clear P7 and silently clear P5 too.
    Same fail-closed pattern as check_validated_notes (P2) and
    check_verdict_consistency (P6).
    """
    errors: list[str] = []
    mapping_path = map_dir / "mapping-results.json"
    fallback_path = map_dir / "map-framework-mapped.json"
    mapping = _load_json(mapping_path)
    if not mapping:
        mapping = _load_json(fallback_path)
    if not mapping:
        # Both files missing or unparseable. P7 catches fully-missing/<1024
        # cases; this branch fires when a file exists but failed to parse,
        # or when neither is present (defense in depth).
        errors.append(
            f"P5 FAIL: neither {mapping_path} nor {fallback_path} loaded "
            "as valid JSON. Phase 3 (Map) is mandatory when 04-map/ exists "
            "— framework coverage cannot be verified."
        )
        return errors

    fm = mapping.get("framework_mapping", [])
    if not fm:
        errors.append(
            f"P5 FAIL: {mapping_path} missing or empty `framework_mapping` "
            "key. Phase 3 (Map) must produce per-objective mapping rows; "
            "fail-closed against silent template/output drift."
        )
        return errors

    total = len(fm)
    mapped = sum(1 for f in fm if f.get("status") == "MAPPED")
    na = [f for f in fm if f.get("status") == "N/A"]

    pct = (mapped / total * 100) if total else 0
    if pct < MIN_FRAMEWORK_COVERAGE_PCT:
        missing_rationale = sum(
            1 for f in na
            if not f.get("rationale") or len(f.get("rationale", "")) < 30
        )
        if missing_rationale:
            errors.append(
                f"P5 framework coverage {pct:.0f}% ({mapped}/{total}) below "
                f"{MIN_FRAMEWORK_COVERAGE_PCT}% threshold, and {missing_rationale} "
                f"N/A objectives lack a specific rationale (>=30 chars). "
                f"Low coverage requires per-objective justification."
            )
    return errors


# ----------------------------------------------------------------------
# P7: per-phase output completeness
# ----------------------------------------------------------------------
# For each phase directory that exists on disk, the documented outputs
# of that phase MUST exist with at least the stated minimum size. A
# phase dir's existence means the agent claimed to run that phase —
# missing outputs mean the run was incomplete and downstream consumers
# will silently break.
#
# Phase dir absence is OK (the phase didn't run — Intake's testing.mode
# == "skip" legitimately skips Phase 5 + Phase 7, for instance).
#
# Min sizes are calibrated for the typical Lambda/S3-scale service:
#   * JSON state files: 1024 bytes (~30 keys, schema-required)
#   * markdown reports: 3072 bytes (controls-catalog) / 5120 bytes
#     (framework-mapping — has 1 row per framework objective, ~197 rows
#     for CCMv4)
#   * single-record files: 256 bytes (intake-manifest, sar-facts head)
PHASE_REQUIRED_OUTPUTS: dict[str, list[tuple[str, int]]] = {
    "00-intake": [
        ("intake-manifest.json", 256),
    ],
    "01-assess": [
        ("sar-facts.json", 256),
        ("checkpoint-results.json", 256),
        ("assessment-summary.md", 1024),
        ("iac-support.json", 256),
    ],
    "02-research": [
        ("research.json", 1024),
        # research-mitigations/capabilities/api-surface are merged into
        # research.json by the merge sub-skill; they may be cleaned up,
        # so don't gate them. research-attack-surface.json is mandatory —
        # MITRE ATT&CK is always-on (manifest.yaml dropped `optional: true`
        # for sa-research-attack-surface; skills/research/SKILL.md raises
        # FileNotFoundError on missing artifact; map-assemble raises
        # ValueError on missing attack_surface). P7 closes the
        # defense-in-depth loop.
        ("research-attack-surface.json", 1024),
    ],
    "03-validate": [
        ("validated.json", 1024),
    ],
    "04-map": [
        ("map-framework-parsed.json", 1024),
        ("map-controls-generated.json", 1024),
        ("map-framework-mapped.json", 1024),
        ("mapping-results.json", 1024),
        ("controls-catalog.md", 3072),
        ("framework-mapping.md", 5120),
    ],
    "05-summarize": [
        ("APPROVAL-REPORT.md", 2048),
    ],
}


def check_phase_outputs(service_root: Path) -> list[str]:
    """P7: every phase dir that exists must contain its documented outputs.

    Walks each phase dir under service_root and asserts that every required
    output exists and meets its minimum size threshold. A phase dir not
    present is considered "phase did not run" and skipped silently.
    """
    errors: list[str] = []

    for phase_name, required in PHASE_REQUIRED_OUTPUTS.items():
        phase_dir = service_root / phase_name
        if not phase_dir.exists():
            continue  # phase did not run — OK

        for filename, min_size in required:
            artifact = phase_dir / filename
            if not artifact.exists():
                errors.append(
                    f"P7 {service_root.name}/{phase_name}/{filename}: MISSING. "
                    f"Phase {phase_name} ran (dir exists) but did not produce "
                    f"{filename}. Downstream consumers depend on this artifact; "
                    f"re-run the {phase_name.split('-', 1)[1]} skill."
                )
                continue
            actual_size = artifact.stat().st_size
            if actual_size < min_size:
                errors.append(
                    f"P7 {service_root.name}/{phase_name}/{filename}: "
                    f"{actual_size} bytes (< {min_size} min). File exists but "
                    f"is too small to contain valid content. Likely a stub or "
                    f"truncated write. Re-run the {phase_name.split('-', 1)[1]} skill."
                )

    return errors


def check_verdict_consistency(summarize_dir: Path, integrity_errors_count: int) -> list[str]:
    """Check verdict consistency from 05-summarize/ phase dir.

    Fails closed when APPROVAL-REPORT.md exists but the `## Verdict` H2
    header is missing (e.g., template drift to H3, or report truncated).
    Same pattern as `check_validated_notes` for P2 — silently returning
    `[]` would let an APPROVED-with-integrity-failures run sneak past
    when a future template change breaks the contract.
    """
    errors: list[str] = []
    report = summarize_dir / "APPROVAL-REPORT.md"
    if not report.exists():
        return errors
    content = report.read_text()
    # Anchor on H2 only — `(?<!#)##(?!#)` enforces exactly two `#`s. Without
    # the lookarounds, `##\s*Verdict` matches `### Verdict` as a substring,
    # silently accepting H3 (the very drift the introducer note in
    # skills/summarize/SKILL.md flags as broken).
    match = re.search(r"(?<!#)##(?!#)\s*Verdict\s*\n+([^\n]+)", content)
    if not match:
        errors.append(
            f"P6 FAIL: {report} exists but no `## Verdict` H2 header found. "
            "skills/summarize/SKILL.md template requires the section at H2; "
            "verdict cannot be verified — fail-closed against silent template drift."
        )
        return errors
    verdict = match.group(1).strip().upper()
    if integrity_errors_count > 0 and "APPROVED" in verdict and "EXCEPTION" not in verdict:
        errors.append(
            f"P6 APPROVAL-REPORT.md verdict '{verdict}' but {integrity_errors_count} "
            f"integrity failures were detected. Change verdict to "
            f"REQUIRES REMEDIATION."
        )
    return errors


# Validator contract: every check_*() must fail-closed when the artifact it
# reads exists but is missing/malformed. Pass-7 audit (2026-05-19) confirmed:
#   - P1, P2, P5, P6, P7 fail-closed with explicit `P{N}`-prefixed errors.
#     P2/P5/P6 use the `P{N} FAIL: ...` shape on missing-artifact branches
#     (the canonical pattern). P1 and P7 ALSO have missing-artifact branches
#     (P1 line ~146 emits `P1 neither pipeline.log nor mcp-calls.log exists`;
#     P7 emits `P7 ... MISSING` when a required output is absent) but use
#     the older bare `P{N} ...` shape — `P{N} FAIL:` is the going-forward
#     canonical pattern for new checks.
#   - P3, P4 have `if not <dir>.exists(): return []` defensive branches that
#     are unreachable in practice — `validate_pipeline()` below gates each
#     call on `.exists()` before invocation.
# When adding a new check_*(): match the P2/P5/P6 pattern (append a
# `P{N} FAIL: ...` error and `return errors` rather than `return errors`
# silently). Probe 33 (missing-artifact silently passes gate) was the source
# of three earlier defects in this file; don't re-introduce.
def validate_pipeline(root: Path) -> list[str]:
    """Validate pipeline integrity for all services in .service-approval/.

    Iterates over all service subdirectories (.service-approval/<slug>/)
    and runs integrity checks on each one. Skips _staging/ and plans/.
    """
    output_dir = root / ".service-approval"
    if not output_dir.exists():
        return []

    errors: list[str] = []

    # Find all service directories (skip _staging/ and plans/).
    # Phase-dir detection is regex-anchored via tools.paths.is_phase_dir_name
    # so unrelated "0-something" or "00-private" dirs aren't mistaken for
    # service roots.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from paths import is_phase_dir_name  # type: ignore

    service_dirs = []
    for item in output_dir.iterdir():
        if not item.is_dir():
            continue
        if item.name.startswith("_") or item.name == "plans":
            continue
        # Check if this looks like a service dir (has phase subdirs)
        has_phases = any(
            child.is_dir() and is_phase_dir_name(child.name)
            for child in item.iterdir()
        )
        if has_phases:
            service_dirs.append(item)

    if not service_dirs:
        return []

    # Validate each service
    for service_root in service_dirs:
        # Check MCP log at service root
        errors.extend(check_mcp_log(service_root))

        # P7: phase-output completeness — every phase dir that exists must
        # contain its declared outputs (safety net; the per-skill
        # check_phase_complete CLI catches this earlier in the run).
        errors.extend(check_phase_outputs(service_root))

        # Check validated.json in 03-validate/
        validate_dir = service_root / "03-validate"
        if validate_dir.exists():
            errors.extend(check_validated_notes(validate_dir))

        # Check framework coverage in 04-map/
        map_dir = service_root / "04-map"
        if map_dir.exists():
            errors.extend(check_framework_coverage(map_dir))

        # Check verdict consistency in 05-summarize/
        summarize_dir = service_root / "05-summarize"
        if summarize_dir.exists():
            errors.extend(check_verdict_consistency(summarize_dir, len(errors)))

    return errors


def main() -> None:
    root = Path(os.getcwd())
    errors = validate_pipeline(root)
    if not errors:
        sys.exit(0)
    print(f"PIPELINE INTEGRITY FAILED ({len(errors)} errors):", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
