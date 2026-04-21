#!/usr/bin/env python3
"""
Pipeline integrity validator.

Detects agents that skip the 5-phase pipeline and emit hardcoded artifacts
instead of running real MCP-driven research/validation/generation.

Fires from the Stop hook. Exits 2 on failure so Claude Code auto-retries.

Failure signals:
    P1 — mcp-calls.log missing or too few calls
    P2 — validated.json has templated or empty verification notes
    P3 — IAM policy logic errors (inverted SCP, permissive boundaries)
    P4 — IaC templates contain placeholder account IDs / ARNs
    P5 — framework coverage below threshold with no per-objective rationale
    P6 — verdict mismatch (APPROVED emitted despite integrity failures)
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


MIN_MCP_CALLS = 10
MIN_FRAMEWORK_COVERAGE_PCT = 15
PLACEHOLDER_ACCOUNTS = {"123456789012", "000000000000", "111111111111"}
PLACEHOLDER_ARN_FRAGMENTS = (
    "arn:aws:kms:us-east-1:123456789012:key/example",
    "arn:aws:iam::123456789012:role/lambda-exec",
)

# Base positive/negative IAM condition operator pairs.
# Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
# AWS has not added a new base pair in years; if they do, extend this list.
_BASE_CONDITION_OPERATOR_PAIRS = (
    ("StringEquals", "StringNotEquals"),
    ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"),
    ("StringLike", "StringNotLike"),
    ("NumericEquals", "NumericNotEquals"),
    ("DateEquals", "DateNotEquals"),
    ("ArnEquals", "ArnNotEquals"),
    ("ArnLike", "ArnNotLike"),
    ("IpAddress", "NotIpAddress"),
)

# IAM allows ForAllValues: / ForAnyValue: prefixes (set operators) and an
# IfExists suffix. Every base pair is valid under each combination, so we
# expand the cartesian product up front.
_SET_PREFIXES = ("", "ForAllValues:", "ForAnyValue:")
_EXISTS_SUFFIXES = ("", "IfExists")


def _expand_operator_pairs() -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for pos, neg in _BASE_CONDITION_OPERATOR_PAIRS:
        for prefix in _SET_PREFIXES:
            for suffix in _EXISTS_SUFFIXES:
                pairs.append((f"{prefix}{pos}{suffix}", f"{prefix}{neg}{suffix}"))
    return tuple(pairs)


CONDITION_OPERATOR_PAIRS = _expand_operator_pairs()


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def check_mcp_log(state_dir: Path) -> list[str]:
    errors: list[str] = []
    log = state_dir / "mcp-calls.log"
    if not log.exists():
        return ["P1 mcp-calls.log missing — pipeline must log every MCP call"]
    content = log.read_text()
    call_lines = [
        ln for ln in content.splitlines()
        if "MCP CALL" in ln or "MCP call" in ln
    ]
    if len(call_lines) < MIN_MCP_CALLS:
        errors.append(
            f"P1 mcp-calls.log has {len(call_lines)} logged calls "
            f"(minimum {MIN_MCP_CALLS}). Validate and Research phases must "
            f"call MCP for every capability, API parameter, and condition key."
        )
    return errors


def check_validated_notes(state_dir: Path) -> list[str]:
    errors: list[str] = []
    validated = _load_json(state_dir / "validated.json")
    if not validated:
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


def _iter_json_files(root: Path):
    if not root.exists():
        return
    for p in root.rglob("*.json"):
        data = _load_json(p)
        if isinstance(data, dict):
            yield p, data


def check_iam_policies(controls_dir: Path) -> list[str]:
    errors: list[str] = []
    if not controls_dir.exists():
        return errors

    for policy_file, data in _iter_json_files(controls_dir):
        if "Statement" not in data:
            continue
        statements = data["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        rel = policy_file.relative_to(controls_dir)
        for i, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                continue

            condition = stmt.get("Condition") or {}
            for pos_op, neg_op in CONDITION_OPERATOR_PAIRS:
                pos_keys = set((condition.get(pos_op) or {}).keys())
                neg_keys = set((condition.get(neg_op) or {}).keys())
                if pos_keys and neg_keys and not (pos_keys & neg_keys):
                    errors.append(
                        f"P3 {rel} Statement[{i}]: {pos_op} and {neg_op} target "
                        f"different keys ({sorted(pos_keys)} vs {sorted(neg_keys)}). "
                        f"Conditions AND together — this statement cannot fire correctly."
                    )

            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]
                broad_actions = [a for a in actions if "*" in a or a.startswith("logs:")]
                if broad_actions and resources == ["*"] and not condition:
                    errors.append(
                        f"P3 {rel} Statement[{i}]: Allow {broad_actions} on "
                        f"Resource '*' with no Condition — exfiltration path."
                    )

        if "scp" in policy_file.name.lower() and not any(
            (s.get("Effect") == "Deny") for s in statements if isinstance(s, dict)
        ):
            errors.append(
                f"P3 {rel}: SCP has no Deny statement — per safety rules, "
                f"SCPs must include at least one Deny."
            )

    return errors


def check_iac_placeholders(iac_dir: Path) -> list[str]:
    errors: list[str] = []
    if not iac_dir.exists():
        return errors
    for path in iac_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            content = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(iac_dir)
        for acct in PLACEHOLDER_ACCOUNTS:
            if acct in content:
                errors.append(
                    f"P4 {rel}: contains placeholder account ID {acct}. "
                    f"Use parameters or Sub references, not hardcoded accounts."
                )
        for fragment in PLACEHOLDER_ARN_FRAGMENTS:
            if fragment in content:
                errors.append(
                    f"P4 {rel}: contains placeholder ARN '{fragment}'. "
                    f"IaC must be parameterized."
                )
    return errors


def check_framework_coverage(state_dir: Path) -> list[str]:
    errors: list[str] = []
    mapping = _load_json(state_dir / "mapping-results.json")
    if not mapping:
        mapping = _load_json(state_dir / "map-framework-mapped.json")
    if not mapping:
        return errors

    fm = mapping.get("framework_mapping", [])
    if not fm:
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


def check_verdict_consistency(output_dir: Path, integrity_errors_count: int) -> list[str]:
    errors: list[str] = []
    report = output_dir / "APPROVAL-REPORT.md"
    if not report.exists():
        return errors
    content = report.read_text()
    match = re.search(r"##\s*Verdict\s*\n+([^\n]+)", content)
    if not match:
        return errors
    verdict = match.group(1).strip().upper()
    if integrity_errors_count > 0 and "APPROVED" in verdict and "EXCEPTION" not in verdict:
        errors.append(
            f"P6 APPROVAL-REPORT.md verdict '{verdict}' but {integrity_errors_count} "
            f"integrity failures were detected. Change verdict to "
            f"REQUIRES REMEDIATION."
        )
    return errors


def validate_pipeline(root: Path) -> list[str]:
    output_dir = root / ".service-approval"
    state_dir = output_dir / "state"
    controls_dir = output_dir / "controls"
    iac_dir = controls_dir / "iac"

    if not state_dir.exists():
        return []

    errors: list[str] = []
    errors.extend(check_mcp_log(state_dir))
    errors.extend(check_validated_notes(state_dir))
    errors.extend(check_iam_policies(controls_dir))
    errors.extend(check_iac_placeholders(iac_dir))
    errors.extend(check_framework_coverage(state_dir))
    errors.extend(check_verdict_consistency(output_dir, len(errors)))
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
