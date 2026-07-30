"""Unit tests for validate_pipeline_integrity checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from validate_pipeline_integrity import (
    CONDITION_OPERATOR_PAIRS,
    MIN_FRAMEWORK_COVERAGE_PCT,
    MIN_MCP_CALLS,
    _arn_delimiter_errors,
    _is_management_action,
    _resource_type_delimiters,
    check_arn_shapes,
    check_boundary_minimality,
    check_citation_coverage,
    check_framework_coverage,
    check_iam_policies,
    check_mcp_log,
    check_phase_outputs,
    check_validated_notes,
    is_finalized,
    validate_pipeline,
)


# Authoritative Lambda SAR ARN patterns (subset) — the data the delimiter map is
# derived from. `function` uses a colon; `layer` uses a colon; the slash variant
# is the defect.
_LAMBDA_SAR_FACTS = {
    "service_prefix": "lambda",
    "resource_types": [
        {"name": "function",
         "arn_pattern": "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}"},
        {"name": "code signing config",
         "arn_pattern": "arn:${Partition}:lambda:${Region}:${Account}:code-signing-config:${CodeSigningConfigId}"},
        {"name": "layer",
         "arn_pattern": "arn:${Partition}:lambda:${Region}:${Account}:layer:${LayerName}"},
        {"name": "eventSourceMapping",
         "arn_pattern": "arn:${Partition}:lambda:${Region}:${Account}:event-source-mapping:${UUID}"},
    ],
}


# ---------- P1: mcp-calls.log ----------


def test_mcp_log_missing_fails(tmp_path: Path) -> None:
    """Neither pipeline.log nor mcp-calls.log exists → P1 fails."""
    errors = check_mcp_log(tmp_path)
    assert len(errors) == 1
    assert errors[0].startswith("P1")
    # Either log file name appears in the error message
    assert "pipeline.log" in errors[0] or "mcp-calls.log" in errors[0]


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


def test_pipeline_log_mcp_calls_counted(tmp_path: Path) -> None:
    """P1 reads MCP call count from the consolidated pipeline.log.

    The consolidated logger writes lines like:
      <ts> [01-assess] [mcp:awsknowledge:call]  <message>
    P1 must recognize these and count them — same threshold as legacy.
    """
    pipeline_lines = [
        f"2026-05-14T18:32:0{i}Z [01-assess] [mcp:awsknowledge:call]  search_documentation: query{i}"
        for i in range(MIN_MCP_CALLS)
    ]
    (tmp_path / "pipeline.log").write_text("\n".join(pipeline_lines))
    assert check_mcp_log(tmp_path) == []


def test_pipeline_log_below_minimum_fails(tmp_path: Path) -> None:
    """pipeline.log present but with too few MCP calls fails P1."""
    pipeline_lines = [
        f"2026-05-14T18:32:0{i}Z [01-assess] [mcp:awsknowledge:call]  q{i}"
        for i in range(2)
    ]
    (tmp_path / "pipeline.log").write_text("\n".join(pipeline_lines))
    errors = check_mcp_log(tmp_path)
    assert len(errors) == 1
    assert "P1" in errors[0]


# ---------- P2: validated.json verification notes ----------


def test_validated_notes_missing_file_is_p2_failure(tmp_path: Path) -> None:
    """A missing validated.json must be a P2 failure, not a silent pass.

    Previously the gate returned [] when the file was absent — letting a
    pipeline that skipped Phase 2 entirely sneak through. Now the gate
    reports a hard fail.
    """
    errors = check_validated_notes(tmp_path)
    assert len(errors) == 1
    assert "P2 FAIL" in errors[0] and "missing" in errors[0]


def test_validated_notes_unparseable_file_is_p2_failure(tmp_path: Path) -> None:
    """A validated.json that exists but doesn't parse must also be a P2 failure."""
    (tmp_path / "validated.json").write_text("{not valid json")
    errors = check_validated_notes(tmp_path)
    assert len(errors) == 1
    assert "P2 FAIL" in errors[0] and "failed to parse" in errors[0]


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


# ---------- P7: phase-output completeness ----------


def test_phase_outputs_missing_required_artifact_fails(tmp_path: Path) -> None:
    """A phase dir that ran but lacks its required artifacts is a P7 error."""
    (tmp_path / "06-summarize").mkdir()
    errors = check_phase_outputs(tmp_path)
    assert any("P7" in e and "SUMMARY-REPORT.md" in e for e in errors)


# ---------- P9: ARN resource-delimiter validation ----------


def test_resource_type_delimiters_parsed_from_sar_patterns() -> None:
    """The delimiter map is derived from SAR arn_pattern fields — `function`
    and `layer` use a colon, multi-word types keep their hyphenated token."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    assert delims["function"] == ":"
    assert delims["layer"] == ":"
    assert delims["code-signing-config"] == ":"
    assert delims["event-source-mapping"] == ":"


def test_arn_delimiter_wrong_delimiter_flagged() -> None:
    """A function ARN with a slash where SAR mandates a colon is the no-op
    defect — flagged."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    err = _arn_delimiter_errors("arn:aws:lambda:*:*:function/*", "lambda", delims)
    assert err is not None
    assert "function" in err and "silent no-op" in err


def test_arn_delimiter_correct_and_wildcard_pass() -> None:
    """The colon form, a fully-qualified colon ARN, and a bare `*` all pass."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    assert _arn_delimiter_errors("arn:aws:lambda:*:*:function:*", "lambda", delims) is None
    assert _arn_delimiter_errors(
        "arn:aws:lambda:*:123456789012:function:*", "lambda", delims
    ) is None
    assert _arn_delimiter_errors("*", "lambda", delims) is None


def test_arn_delimiter_other_service_and_unknown_token_pass() -> None:
    """Cross-service ARNs (format not loaded) and unknown type tokens are not
    judged — the check stays quiet rather than false-positive."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    # Different service — its ARN format was not loaded.
    assert _arn_delimiter_errors("arn:aws:s3:::my-bucket/*", "lambda", delims) is None
    # Unknown resource-type token for this service.
    assert _arn_delimiter_errors(
        "arn:aws:lambda:*:*:newthing/abc", "lambda", delims
    ) is None


def test_arn_delimiter_malformed_too_few_fields_flagged() -> None:
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    err = _arn_delimiter_errors("arn:aws:lambda:function", "lambda", delims)
    assert err is not None and "6 colon-delimited" in err


def test_arn_delimiter_wrong_case_resource_type_flagged() -> None:
    """IAM resource matching is case-sensitive — a capitalized resource type
    (Function/ instead of function:) matches nothing and is flagged."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    err = _arn_delimiter_errors("arn:aws:lambda:*:*:Function/*", "lambda", delims)
    assert err is not None and "case" in err.lower()


def test_arn_delimiter_uppercase_scheme_still_checked() -> None:
    """A wrong-case ARN scheme/service (ARN:AWS:LAMBDA:…) is still parsed and its
    malformed resource delimiter flagged (not silently skipped)."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    err = _arn_delimiter_errors("ARN:AWS:LAMBDA:*:*:FUNCTION/*", "lambda", delims)
    assert err is not None


def test_arn_delimiter_missing_delimiter_flagged() -> None:
    """A known resource type with NO delimiter (function* instead of function:*)
    is a malformed ARN."""
    delims = _resource_type_delimiters(_LAMBDA_SAR_FACTS)
    err = _arn_delimiter_errors("arn:aws:lambda:*:*:function*", "lambda", delims)
    assert err is not None and "without its delimiter" in err


def _write_preventive_artifact(root: Path, name: str, statements: list) -> None:
    prev = root / "05-recommended-guidance" / "preventive"
    prev.mkdir(parents=True, exist_ok=True)
    (prev / name).write_text(json.dumps({"Version": "2012-10-17", "Statement": statements}))


def _write_sar_facts(root: Path) -> None:
    assess = root / "01-assess"
    assess.mkdir(parents=True, exist_ok=True)
    (assess / "sar-facts.json").write_text(json.dumps(_LAMBDA_SAR_FACTS))


def test_check_arn_shapes_flags_slash_function(tmp_path: Path) -> None:
    """End-to-end: a preventive artifact with `function/*` fails P9; the colon
    sibling in the same file passes."""
    _write_sar_facts(tmp_path)
    _write_preventive_artifact(
        tmp_path,
        "scp-policy.json",
        [
            {"Sid": "Bad", "Effect": "Deny", "Action": "lambda:CreateFunction",
             "Resource": "arn:aws:lambda:*:*:function/*"},
            {"Sid": "Good", "Effect": "Deny", "Action": "lambda:CreateFunction",
             "Resource": "arn:aws:lambda:*:*:function:*"},
        ],
    )
    errors = check_arn_shapes(tmp_path)
    assert len(errors) == 1
    assert "P9" in errors[0] and "scp-policy.json" in errors[0] and "Statement[0]" in errors[0]


def test_check_arn_shapes_clean_artifact_passes(tmp_path: Path) -> None:
    """An artifact whose ARNs all use the correct delimiter yields no P9 error."""
    _write_sar_facts(tmp_path)
    _write_preventive_artifact(
        tmp_path,
        "permission-boundary.json",
        [
            {"Sid": "Ok", "Effect": "Deny", "Action": "lambda:CreateFunction",
             "Resource": ["arn:aws:lambda:*:*:function:*", "*"]},
        ],
    )
    assert check_arn_shapes(tmp_path) == []


_FINALIZED_LINE = (
    "2026-06-18T01:19:00Z [06-summarize] [pipeline:complete:FINALIZED]  done\n"
)


def test_arn_shapes_exempts_finalized_run(tmp_path: Path) -> None:
    """A finalized run is frozen — newly-added P9 must not retroactively fail it
    (it would brick every subsequent Stop hook for an immutable run)."""
    _write_sar_facts(tmp_path)
    _write_preventive_artifact(
        tmp_path, "scp-policy.json",
        [{"Sid": "Bad", "Effect": "Deny", "Action": "lambda:CreateFunction",
          "Resource": "arn:aws:lambda:*:*:function/*"}],
    )
    # mid-flight (no sentinel) → flagged
    assert len(check_arn_shapes(tmp_path)) == 1
    # finalized (sentinel present) → exempt
    (tmp_path / "pipeline.log").write_text(_FINALIZED_LINE)
    assert check_arn_shapes(tmp_path) == []


def test_boundary_minimality_exempts_finalized_run(tmp_path: Path) -> None:
    _write_preventive_artifact(
        tmp_path, "permission-boundary.json",
        [{"Sid": "AllowMgmt", "Effect": "Allow",
          "Action": ["lambda:CreateFunction"], "Resource": "*"}],
    )
    assert len(check_boundary_minimality(tmp_path)) == 1  # mid-flight
    (tmp_path / "pipeline.log").write_text(_FINALIZED_LINE)
    assert check_boundary_minimality(tmp_path) == []  # finalized


def test_citation_coverage_exempts_finalized_run(tmp_path: Path) -> None:
    """P12 is a newly-added check — a run that finalized before it existed had
    no chance to satisfy it and is frozen, so the Stop-hook path must exempt it
    (mirrors P9/P10/P11). Mid-flight runs still get the strict check."""
    guidance = tmp_path / "05-recommended-guidance" / "detective"
    guidance.mkdir(parents=True)
    # An authored detective artifact with no citation → flagged mid-flight.
    (guidance / "config-rules.json").write_text(
        json.dumps({"_metadata": {"posture": "reactive-detective"}, "rules": []})
    )
    assert len(check_citation_coverage(tmp_path)) >= 1  # mid-flight (no sentinel)
    (tmp_path / "pipeline.log").write_text(_FINALIZED_LINE)
    assert check_citation_coverage(tmp_path) == []  # finalized → exempt


def test_is_finalized_detection(tmp_path: Path) -> None:
    assert is_finalized(tmp_path) is False  # no pipeline.log
    (tmp_path / "pipeline.log").write_text("2026-01-01T00:00:00Z [04-map] [skill:x:end]  hi\n")
    assert is_finalized(tmp_path) is False  # no sentinel
    (tmp_path / "pipeline.log").write_text(_FINALIZED_LINE)
    assert is_finalized(tmp_path) is True
    # the sentinel must sit at the source-tag column, not in a message body
    (tmp_path / "pipeline.log").write_text(
        "2026-01-01T00:00:00Z [04-map] [skill:x:end]  mentions [pipeline:complete:FINALIZED]\n"
    )
    assert is_finalized(tmp_path) is False


def test_check_arn_shapes_no_sar_facts_is_silent(tmp_path: Path) -> None:
    """Without sar-facts.json there is no authoritative format — the check must
    not fire (it cannot judge correctness)."""
    _write_preventive_artifact(
        tmp_path,
        "scp-policy.json",
        [{"Sid": "X", "Effect": "Deny", "Action": "lambda:CreateFunction",
          "Resource": "arn:aws:lambda:*:*:function/*"}],
    )
    assert check_arn_shapes(tmp_path) == []


# ---------- P10: permission-boundary minimality ----------


def test_is_management_action_classification() -> None:
    # Explicit write verbs are management.
    assert _is_management_action("lambda:CreateFunction")
    assert _is_management_action("lambda:UpdateFunctionConfiguration")
    assert _is_management_action("lambda:PutFunctionCodeSigningConfig")
    assert _is_management_action("lambda:DeleteFunction")
    assert _is_management_action("lambda:TagResource")
    # FAIL-CLOSED: escalation actions whose verb is not a known read verb are
    # management even though their verb is not an obvious Create/Update/Put.
    assert _is_management_action("ec2:RunInstances")
    assert _is_management_action("sts:AssumeRole")
    assert _is_management_action("kms:ScheduleKeyDeletion")
    assert _is_management_action("s3:RestoreObject")
    assert _is_management_action("dynamodb:ExportTableToPointInTime")
    # invoke is a privileged data-plane action a boundary should constrain.
    assert _is_management_action("lambda:InvokeFunction")
    # read verbs are not management.
    assert not _is_management_action("lambda:GetFunction")
    assert not _is_management_action("lambda:ListFunctions")
    assert not _is_management_action("s3:DescribeJob")
    # wildcard globs: a write/ambiguous stem is management; a read stem is not.
    assert _is_management_action("lambda:Create*")
    assert _is_management_action("lambda:*")
    assert _is_management_action("*")
    assert not _is_management_action("lambda:Get*")
    assert not _is_management_action("lambda:List*")


def test_boundary_allow_with_management_actions_flagged(tmp_path: Path) -> None:
    """A permission-boundary Allow enumerating CreateFunction/UpdateX fails P10."""
    _write_preventive_artifact(
        tmp_path,
        "permission-boundary.json",
        [
            {"Sid": "AllowScopedMgmt", "Effect": "Allow",
             "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration",
                        "lambda:InvokeFunction"],
             "Resource": "arn:aws:lambda:*:*:function:*"},
            {"Sid": "DenyUrl", "Effect": "Deny",
             "Action": "lambda:CreateFunctionUrlConfig", "Resource": "*",
             "Condition": {"StringNotEquals": {"lambda:FunctionUrlAuthType": "AWS_IAM"}}},
        ],
    )
    errors = check_boundary_minimality(tmp_path)
    assert len(errors) == 1
    assert "P10" in errors[0] and "AllowScopedMgmt" in errors[0]
    assert "lambda:CreateFunction" in errors[0]


def test_boundary_minimal_allow_passes(tmp_path: Path) -> None:
    """A boundary whose Allow is a minimal READ floor — control intent in the
    Deny — passes P10. (Reads only; invoke/management belong in the Deny + keys.)"""
    _write_preventive_artifact(
        tmp_path,
        "permission-boundary.json",
        [
            {"Sid": "AllowReadFloor", "Effect": "Allow",
             "Action": ["lambda:GetFunction", "lambda:ListFunctions",
                        "lambda:GetAccountSettings"],
             "Resource": "*"},
            {"Sid": "DenyPassRole", "Effect": "Deny", "Action": "iam:PassRole",
             "Resource": "*",
             "Condition": {"StringNotEqualsIfExists": {"iam:PassedToService": "lambda.amazonaws.com"}}},
        ],
    )
    assert check_boundary_minimality(tmp_path) == []


def test_boundary_escalation_action_flagged(tmp_path: Path) -> None:
    """FAIL-CLOSED regression: a boundary Allow listing escalation actions whose
    verbs are not in any write-verb list (RunInstances, AssumeRole, …) must still
    be flagged — the check treats unknown verbs as management."""
    _write_preventive_artifact(
        tmp_path,
        "permission-boundary.json",
        [
            {"Sid": "AllowEscalation", "Effect": "Allow",
             "Action": ["ec2:RunInstances", "sts:AssumeRole",
                        "kms:ScheduleKeyDeletion"],
             "Resource": "*"},
        ],
    )
    errors = check_boundary_minimality(tmp_path)
    assert len(errors) == 1 and "AllowEscalation" in errors[0]


def test_boundary_detected_by_metadata_not_just_filename(tmp_path: Path) -> None:
    """A boundary artifact under a non-obvious filename is still checked when its
    _metadata marks it a permission boundary."""
    prev = tmp_path / "05-recommended-guidance" / "preventive"
    prev.mkdir(parents=True)
    (prev / "pb.json").write_text(json.dumps({
        "_metadata": {"mechanism": "IAM Permission Boundary", "layer": "preventive"},
        "Version": "2012-10-17",
        "Statement": [{"Sid": "AllowMgmt", "Effect": "Allow",
                       "Action": ["lambda:CreateFunction"], "Resource": "*"}],
    }))
    errors = check_boundary_minimality(tmp_path)
    assert len(errors) == 1 and "AllowMgmt" in errors[0]


def test_boundary_minimality_only_checks_boundary_files(tmp_path: Path) -> None:
    """An SCP that enumerates management actions in an Allow is NOT a P10 concern
    (P10 is specific to permission-boundary artifacts)."""
    _write_preventive_artifact(
        tmp_path,
        "scp-policy.json",
        [{"Sid": "AllowMgmt", "Effect": "Allow",
          "Action": ["lambda:CreateFunction"], "Resource": "*"}],
    )
    assert check_boundary_minimality(tmp_path) == []


# ---------- P5: framework coverage ----------


def test_framework_coverage_both_files_missing_fails_closed(tmp_path: Path) -> None:
    """04-map/ exists but neither mapping-results.json nor
    map-framework-mapped.json is present. Pre-fix this returned [] silently;
    same Probe 33 pattern X1 closed for P2 and X2 closed for P6."""
    errors = check_framework_coverage(tmp_path)
    assert errors and "P5 FAIL" in errors[0] and "neither" in errors[0]


def test_framework_coverage_corrupt_json_fails_closed(tmp_path: Path) -> None:
    """A 1024+ byte mapping-results.json that fails to parse must
    fail-closed (P7's size threshold is content-blind)."""
    (tmp_path / "mapping-results.json").write_text("{not valid json" + "x" * 2000)
    errors = check_framework_coverage(tmp_path)
    assert errors and "P5 FAIL" in errors[0]


def test_framework_coverage_no_mapping_key_fails_closed(tmp_path: Path) -> None:
    """A file that parses but lacks the `framework_mapping` key must
    fail-closed. P7 only enforces size, not content shape."""
    (tmp_path / "mapping-results.json").write_text(
        json.dumps({"controls": [{"id": "c1"}], "padding": "x" * 2000})
    )
    errors = check_framework_coverage(tmp_path)
    assert errors and "P5 FAIL" in errors[0] and "framework_mapping" in errors[0]


def test_framework_coverage_empty_mapping_list_fails_closed(tmp_path: Path) -> None:
    """`framework_mapping: []` is the same shape as missing — fail-closed."""
    (tmp_path / "mapping-results.json").write_text(
        json.dumps({"framework_mapping": [], "padding": "x" * 2000})
    )
    errors = check_framework_coverage(tmp_path)
    assert errors and "P5 FAIL" in errors[0] and "framework_mapping" in errors[0]


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


# ---------- validate_pipeline integration ----------


def test_validate_pipeline_no_state_dir_returns_empty(tmp_path: Path) -> None:
    # No .service-approval/ → nothing to validate (pre-pipeline run).
    assert validate_pipeline(tmp_path) == []


def test_validate_pipeline_aggregates_errors(tmp_path: Path) -> None:
    # New layout: .service-approval/<slug>/0N-phase/
    out = tmp_path / ".service-approval"
    service = out / "testservice"
    service.mkdir(parents=True)

    # Create phase directories
    (service / "03-validate").mkdir()
    (service / "05-recommended-guidance").mkdir()
    (service / "05-recommended-guidance" / "preventive").mkdir()

    # Trigger P1 (missing mcp-calls.log at service root)
    # No mcp-calls.log created → will fail P1

    # Trigger P3 (SCP without at least one Deny)
    _write_policy(
        service / "05-recommended-guidance",
        "scp-baseline.json",
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    )

    errors = validate_pipeline(tmp_path)
    assert any("P1" in e for e in errors)
    assert any("P3" in e and "SCP has no Deny" in e for e in errors)


# ---------- P1 sentinel anchoring ----------


def test_pipeline_complete_sentinel_in_message_does_not_close_p1(tmp_path: Path) -> None:
    """A pipeline.log line whose MESSAGE contains the literal sentinel text must
    NOT close out P1 — only a real `[pipeline:complete:FINALIZED]` source-tag
    counts. This protects against the validator getting tricked by skill prose
    that happens to quote the sentinel."""
    leaked = (
        "2026-05-14T18:32:01Z [06-summarize] [skill:summarize:end]  "
        "wrote `[pipeline:complete:FINALIZED]` reference to docs only\n"
    )
    (tmp_path / "pipeline.log").write_text(leaked)
    errors = check_mcp_log(tmp_path)
    # P1 should still fail (no real MCP calls AND no real sentinel).
    assert errors and "P1" in errors[0]


def test_pipeline_complete_sentinel_at_source_tag_closes_p1(tmp_path: Path) -> None:
    """The real sentinel format closes out P1 retroactively — finalized runs
    are exempt because the file is frozen at that point."""
    line = (
        "2026-05-14T18:32:01Z [06-summarize] [pipeline:complete:FINALIZED]  "
        "summarize finalized\n"
    )
    (tmp_path / "pipeline.log").write_text(line)
    assert check_mcp_log(tmp_path) == []


def test_pipeline_complete_sentinel_unknown_token_is_ignored(tmp_path: Path) -> None:
    """A sentinel with any token other than the fixed FINALIZED (e.g., a
    leftover verdict word or a typo) should NOT close P1 — only FINALIZED
    finalizes the run."""
    for token in ("APPROVED", "UNCLEAR", "DONE"):
        line = (
            f"2026-05-14T18:32:01Z [06-summarize] [pipeline:complete:{token}]  "
            f"weird state\n"
        )
        (tmp_path / "pipeline.log").write_text(line)
        errors = check_mcp_log(tmp_path)
        assert errors and "P1" in errors[0], f"token {token} must not close P1"


# ---------- P3 wildcard-only literal-only matching ----------


def test_action_matches_wildcard_only_literal_match() -> None:
    """A literal action present in the wildcard-only set is exempt."""
    from validate_pipeline_integrity import _action_matches_wildcard_only
    wildcard_only = {"datasync:DescribeAgent", "datasync:DescribeTask"}
    assert _action_matches_wildcard_only("datasync:DescribeAgent", wildcard_only)


def test_action_matches_wildcard_only_glob_no_longer_exempted() -> None:
    """Globs (`Describe*`) are NOT exempted — even if some matching actions
    are wildcard-only. SAR data is incomplete; literal-only matching keeps
    the carve-out tight."""
    from validate_pipeline_integrity import _action_matches_wildcard_only
    wildcard_only = {"datasync:DescribeAgent"}
    assert not _action_matches_wildcard_only("datasync:Describe*", wildcard_only)


def test_action_matches_wildcard_only_unknown_action_not_exempted() -> None:
    """An action not in the set is not exempted regardless of prefix overlap."""
    from validate_pipeline_integrity import _action_matches_wildcard_only
    wildcard_only = {"datasync:DescribeAgent"}
    assert not _action_matches_wildcard_only("datasync:CreateTask", wildcard_only)


# ---------- _load_wildcard_only_actions empty-prefix guard (F11) ----------


def test_wildcard_only_loader_skips_bare_actions_when_prefix_empty(tmp_path: Path) -> None:
    """When sar-facts.json omits service_prefix and an action has no prefix,
    the loader must NOT emit `:Action` (which silently matches nothing)."""
    from validate_pipeline_integrity import _load_wildcard_only_actions
    assess_dir = tmp_path / "01-assess"
    assess_dir.mkdir()
    (assess_dir / "sar-facts.json").write_text(json.dumps({
        "wildcard_only_actions": ["BareAction"],
        "actions": [{"name": "AnotherBare", "resource_types": []}],
    }))
    controls_dir = tmp_path / "05-recommended-guidance"
    controls_dir.mkdir()
    out = _load_wildcard_only_actions(controls_dir)
    # Cross-service entries are still present, but no malformed ":Action" entries.
    assert all(":" in a and not a.startswith(":") for a in out), out


def test_wildcard_only_loader_qualifies_with_prefix(tmp_path: Path) -> None:
    """When service_prefix is present, bare actions are qualified properly."""
    from validate_pipeline_integrity import _load_wildcard_only_actions
    assess_dir = tmp_path / "01-assess"
    assess_dir.mkdir()
    (assess_dir / "sar-facts.json").write_text(json.dumps({
        "service_prefix": "datasync",
        "wildcard_only_actions": ["DescribeAgent"],
    }))
    controls_dir = tmp_path / "05-recommended-guidance"
    controls_dir.mkdir()
    out = _load_wildcard_only_actions(controls_dir)
    assert "datasync:DescribeAgent" in out


# ---------- P11: no LLM confidence scoring ----------


def test_confidence_key_in_map_json_fails(tmp_path: Path) -> None:
    """A `confidence` key on a control under 04-map/ fails P11."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    map_dir = tmp_path / "04-map"
    map_dir.mkdir()
    (map_dir / "mapping-results.json").write_text(json.dumps({
        "framework_mapping": [
            {"objective_id": "X", "controls": [
                {"control_id": "C-1", "confidence": {"band": "HIGH", "score": 0.9}}
            ]}
        ]
    }))
    errors = check_no_confidence_scoring(tmp_path)
    assert any("P11" in e and "confidence" in e for e in errors), errors


def test_run_confidence_key_in_generate_json_fails(tmp_path: Path) -> None:
    """A `run_confidence` key under 05-recommended-guidance/ fails P11."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    gen_dir = tmp_path / "05-recommended-guidance" / "preventive"
    gen_dir.mkdir(parents=True)
    (gen_dir / "summary.json").write_text(json.dumps({"run_confidence": 0.7}))
    errors = check_no_confidence_scoring(tmp_path)
    assert any("P11" in e and "run_confidence" in e for e in errors), errors


def test_confidence_band_in_report_md_fails(tmp_path: Path) -> None:
    """A confidence band attached to 'confidence' in the report fails P11."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    sm_dir = tmp_path / "06-summarize"
    sm_dir.mkdir()
    (sm_dir / "SUMMARY-REPORT.md").write_text(
        "# Report\n\n| Control | Confidence |\n|--|--|\n"
        "| C-1 | HIGH confidence |\n"
    )
    errors = check_no_confidence_scoring(tmp_path)
    assert any("P11" in e and "band" in e for e in errors), errors


def test_confidence_word_without_band_passes(tmp_path: Path) -> None:
    """P11 targets a confidence BAND token, not the English word. The Summary
    Report's one-line 'Verification approach' pointer (and any prose that uses
    the word 'confidence' without a HIGH/MEDIUM/LOW band) must NOT trip P11. The
    generic 'Actions Taken to Increase Confidence' boilerplate no longer appears
    in reports — it lives once in the README — but even if the word 'confidence'
    shows up in prose, the band-token requirement keeps the check from firing."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    sm_dir = tmp_path / "06-summarize"
    sm_dir.mkdir()
    (sm_dir / "SUMMARY-REPORT.md").write_text(
        "# Report\n\n> The verification steps that build confidence are described "
        "in the project README.\n\n"
        "- Every capability was MCP-verified.\n"
        "- Reference anchors resolved for each preventive policy.\n"
    )
    assert check_no_confidence_scoring(tmp_path) == []


def test_coverage_level_does_not_trip_p11(tmp_path: Path) -> None:
    """coverage_level is the allowed deterministic ranked field — not confidence."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    map_dir = tmp_path / "04-map"
    map_dir.mkdir()
    (map_dir / "mapping-results.json").write_text(json.dumps({
        "framework_mapping": [
            {"objective_id": "X", "controls": [
                {"control_id": "C-1", "coverage_level": "Full Coverage"}
            ]}
        ]
    }))
    assert check_no_confidence_scoring(tmp_path) == []


def test_p11_exempts_finalized_run(tmp_path: Path) -> None:
    """A finalized run is frozen — P11 must not retroactively fail it."""
    from validate_pipeline_integrity import check_no_confidence_scoring
    map_dir = tmp_path / "04-map"
    map_dir.mkdir()
    (map_dir / "mapping-results.json").write_text(json.dumps({"confidence": 0.5}))
    assert len(check_no_confidence_scoring(tmp_path)) == 1  # mid-flight
    (tmp_path / "pipeline.log").write_text(_FINALIZED_LINE)
    assert check_no_confidence_scoring(tmp_path) == []  # finalized
