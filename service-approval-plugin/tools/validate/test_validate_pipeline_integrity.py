"""Unit tests for validate_pipeline_integrity checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from validate_pipeline_integrity import (
    CONDITION_OPERATOR_PAIRS,
    MIN_FRAMEWORK_COVERAGE_PCT,
    MIN_MCP_CALLS,
    check_framework_coverage,
    check_iac_placeholders,
    check_iam_policies,
    check_mcp_log,
    check_validated_notes,
    check_verdict_consistency,
    validate_pipeline,
)


# ---------- P1: mcp-calls.log ----------


def test_mcp_log_missing_fails(tmp_path: Path) -> None:
    errors = check_mcp_log(tmp_path)
    assert len(errors) == 1
    assert errors[0].startswith("P1") and "missing" in errors[0]


def test_mcp_log_below_minimum_fails(tmp_path: Path) -> None:
    (tmp_path / "mcp-calls.log").write_text("MCP CALL 1\nMCP CALL 2\n")
    errors = check_mcp_log(tmp_path)
    assert len(errors) == 1
    assert "P1" in errors[0] and f"minimum {MIN_MCP_CALLS}" in errors[0]


def test_mcp_log_at_minimum_passes(tmp_path: Path) -> None:
    (tmp_path / "mcp-calls.log").write_text(
        "\n".join(f"MCP CALL {i}" for i in range(MIN_MCP_CALLS))
    )
    assert check_mcp_log(tmp_path) == []


def test_mcp_log_case_insensitive_call_marker(tmp_path: Path) -> None:
    # Both "MCP CALL" and "MCP call" are recognised per the implementation.
    lines = ["MCP CALL foo"] * 5 + ["MCP call bar"] * 5
    (tmp_path / "mcp-calls.log").write_text("\n".join(lines))
    assert check_mcp_log(tmp_path) == []


# ---------- P2: validated.json verification notes ----------


def test_validated_notes_missing_file_is_noop(tmp_path: Path) -> None:
    assert check_validated_notes(tmp_path) == []


def test_validated_notes_no_notes_fails(tmp_path: Path) -> None:
    (tmp_path / "validated.json").write_text(json.dumps({"capabilities": {}}))
    errors = check_validated_notes(tmp_path)
    assert len(errors) == 1
    assert "P2" in errors[0] and "zero verification_note" in errors[0]


def test_validated_notes_unique_notes_pass(tmp_path: Path) -> None:
    data = {
        "items": [
            {"verification_note": f"Verified via MCP call for item {i} — details {i}"}
            for i in range(6)
        ]
    }
    (tmp_path / "validated.json").write_text(json.dumps(data))
    assert check_validated_notes(tmp_path) == []


def test_validated_notes_heavily_duplicated_fails(tmp_path: Path) -> None:
    data = {"items": [{"verification_note": "TODO"} for _ in range(8)]}
    (tmp_path / "validated.json").write_text(json.dumps(data))
    errors = check_validated_notes(tmp_path)
    assert any("P2" in e and "duplicated" in e for e in errors)


def test_validated_notes_feasibility_note_also_counted(tmp_path: Path) -> None:
    # feasibility_note is also scanned — reusing the same string across both
    # field names should still trip the duplication rule.
    data = {
        "items": [
            {"verification_note": "same"} for _ in range(4)
        ] + [
            {"feasibility_note": "same"} for _ in range(4)
        ]
    }
    (tmp_path / "validated.json").write_text(json.dumps(data))
    errors = check_validated_notes(tmp_path)
    assert any("P2" in e and "duplicated" in e for e in errors)


def test_validated_notes_short_summary_fails(tmp_path: Path) -> None:
    data = {
        "items": [{"verification_note": f"unique note {i} with enough length"} for i in range(4)],
        "verification": {"summary": "ok"},
    }
    (tmp_path / "validated.json").write_text(json.dumps(data))
    errors = check_validated_notes(tmp_path)
    assert any("P2" in e and "summary is too short" in e for e in errors)


# ---------- P3: IAM policy logic ----------


def _write_policy(tmp_path: Path, name: str, policy: dict) -> None:
    (tmp_path / name).write_text(json.dumps(policy))


def test_iam_inverted_string_equals_fails(tmp_path: Path) -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": "o-abc"},
                    "StringNotEquals": {"aws:ResourceTag/Env": "prod"},
                },
            }
        ]
    }
    _write_policy(tmp_path, "policy.json", policy)
    errors = check_iam_policies(tmp_path)
    assert any("P3" in e and "StringEquals" in e and "cannot fire" in e for e in errors)


def test_iam_overlapping_keys_pass(tmp_path: Path) -> None:
    # Same key in both StringEquals and StringNotEquals is a legitimate pattern
    # (allow one value but exclude a subset), so the inverted-key check must not trip.
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/Env": "prod"},
                    "StringNotEquals": {"aws:ResourceTag/Env": "prod-readonly"},
                },
            }
        ]
    }
    _write_policy(tmp_path, "policy.json", policy)
    # The check may still flag exfil-path issues, but never an inverted-keys P3.
    errors = check_iam_policies(tmp_path)
    assert not any("cannot fire correctly" in e for e in errors)


@pytest.mark.parametrize("pos_op,neg_op", CONDITION_OPERATOR_PAIRS)
def test_iam_inverted_logic_detected_for_all_operator_pairs(
    tmp_path: Path, pos_op: str, neg_op: str
) -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {
                    pos_op: {"aws:PrincipalOrgID": "o-abc"},
                    neg_op: {"aws:ResourceTag/Env": "prod"},
                },
            }
        ]
    }
    _write_policy(tmp_path, "policy.json", policy)
    errors = check_iam_policies(tmp_path)
    assert any(
        "P3" in e and pos_op in e and neg_op in e and "cannot fire" in e for e in errors
    ), f"expected inverted-logic finding for {pos_op} vs {neg_op}, got: {errors}"


def test_iam_allow_star_without_condition_fails(tmp_path: Path) -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "logs:*",
                "Resource": "*",
            }
        ]
    }
    _write_policy(tmp_path, "policy.json", policy)
    errors = check_iam_policies(tmp_path)
    assert any("P3" in e and "exfiltration path" in e for e in errors)


def test_iam_allow_star_with_condition_passes(tmp_path: Path) -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "logs:*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
            }
        ]
    }
    _write_policy(tmp_path, "policy.json", policy)
    errors = check_iam_policies(tmp_path)
    assert not any("exfiltration path" in e for e in errors)


def test_scp_without_deny_fails(tmp_path: Path) -> None:
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    _write_policy(tmp_path, "scp-baseline.json", policy)
    errors = check_iam_policies(tmp_path)
    assert any("P3" in e and "SCP has no Deny" in e for e in errors)


def test_scp_with_deny_passes(tmp_path: Path) -> None:
    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}
        ]
    }
    _write_policy(tmp_path, "scp-guardrail.json", policy)
    errors = check_iam_policies(tmp_path)
    assert not any("SCP has no Deny" in e for e in errors)


def test_non_scp_without_deny_passes(tmp_path: Path) -> None:
    # The SCP Deny requirement should only apply to files named like SCPs.
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
        ]
    }
    _write_policy(tmp_path, "resource-policy.json", policy)
    errors = check_iam_policies(tmp_path)
    assert not any("SCP has no Deny" in e for e in errors)


# ---------- P4: IaC placeholders ----------


def test_iac_placeholder_account_fails(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  Role:\n    Arn: arn:aws:iam::123456789012:role/foo\n"
    )
    errors = check_iac_placeholders(tmp_path)
    assert any("P4" in e and "123456789012" in e for e in errors)


def test_iac_placeholder_arn_fragment_fails(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(
        'const kmsArn = "arn:aws:kms:us-east-1:123456789012:key/example";\n'
    )
    errors = check_iac_placeholders(tmp_path)
    # Both the account ID and the ARN fragment should trigger; at least one P4 required.
    assert any("P4" in e for e in errors)


def test_iac_parameterized_passes(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Parameters:\n  AccountId:\n    Type: String\nResources:\n"
        '  Role:\n    Arn: !Sub "arn:aws:iam::${AccountId}:role/foo"\n'
    )
    assert check_iac_placeholders(tmp_path) == []


# ---------- P5: framework coverage ----------


def test_framework_coverage_missing_file_is_noop(tmp_path: Path) -> None:
    assert check_framework_coverage(tmp_path) == []


def test_framework_coverage_high_passes(tmp_path: Path) -> None:
    data = {
        "framework_mapping": [{"status": "MAPPED"} for _ in range(8)] + [
            {"status": "N/A", "rationale": "x" * 40}
        ]
    }
    (tmp_path / "mapping-results.json").write_text(json.dumps(data))
    assert check_framework_coverage(tmp_path) == []


def test_framework_coverage_low_without_rationale_fails(tmp_path: Path) -> None:
    data = {
        "framework_mapping": (
            [{"status": "MAPPED"}]
            + [{"status": "N/A", "rationale": "short"} for _ in range(20)]
        )
    }
    (tmp_path / "mapping-results.json").write_text(json.dumps(data))
    errors = check_framework_coverage(tmp_path)
    assert any("P5" in e and "below" in e and str(MIN_FRAMEWORK_COVERAGE_PCT) in e for e in errors)


def test_framework_coverage_low_with_rationale_passes(tmp_path: Path) -> None:
    data = {
        "framework_mapping": (
            [{"status": "MAPPED"}]
            + [{"status": "N/A", "rationale": "r" * 50} for _ in range(20)]
        )
    }
    (tmp_path / "mapping-results.json").write_text(json.dumps(data))
    assert check_framework_coverage(tmp_path) == []


def test_framework_coverage_falls_back_to_mapped_file(tmp_path: Path) -> None:
    # Implementation tries mapping-results.json first, then map-framework-mapped.json.
    data = {"framework_mapping": [{"status": "MAPPED"} for _ in range(10)]}
    (tmp_path / "map-framework-mapped.json").write_text(json.dumps(data))
    assert check_framework_coverage(tmp_path) == []


# ---------- P6: verdict consistency ----------


def test_verdict_missing_report_is_noop(tmp_path: Path) -> None:
    assert check_verdict_consistency(tmp_path, integrity_errors_count=5) == []


def test_verdict_approved_with_errors_fails(tmp_path: Path) -> None:
    (tmp_path / "APPROVAL-REPORT.md").write_text("# Report\n\n## Verdict\nAPPROVED\n")
    errors = check_verdict_consistency(tmp_path, integrity_errors_count=3)
    assert any("P6" in e and "APPROVED" in e for e in errors)


def test_verdict_approved_with_exception_passes(tmp_path: Path) -> None:
    (tmp_path / "APPROVAL-REPORT.md").write_text(
        "# Report\n\n## Verdict\nAPPROVED WITH EXCEPTION\n"
    )
    assert check_verdict_consistency(tmp_path, integrity_errors_count=3) == []


def test_verdict_requires_remediation_passes(tmp_path: Path) -> None:
    (tmp_path / "APPROVAL-REPORT.md").write_text(
        "# Report\n\n## Verdict\nREQUIRES REMEDIATION\n"
    )
    assert check_verdict_consistency(tmp_path, integrity_errors_count=3) == []


def test_verdict_no_errors_approved_passes(tmp_path: Path) -> None:
    (tmp_path / "APPROVAL-REPORT.md").write_text("# Report\n\n## Verdict\nAPPROVED\n")
    assert check_verdict_consistency(tmp_path, integrity_errors_count=0) == []


# ---------- validate_pipeline integration ----------


def test_validate_pipeline_no_state_dir_returns_empty(tmp_path: Path) -> None:
    # No .service-approval/state/ → nothing to validate (pre-pipeline run).
    assert validate_pipeline(tmp_path) == []


def test_validate_pipeline_aggregates_errors(tmp_path: Path) -> None:
    out = tmp_path / ".service-approval"
    state = out / "state"
    controls = out / "controls"
    state.mkdir(parents=True)
    controls.mkdir(parents=True)
    # Trigger P1 (missing mcp-calls.log) and P3 (inverted SCP without Deny).
    _write_policy(
        controls,
        "scp-baseline.json",
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    )
    errors = validate_pipeline(tmp_path)
    assert any("P1" in e for e in errors)
    assert any("P3" in e and "SCP has no Deny" in e for e in errors)
