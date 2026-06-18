#!/usr/bin/env python3
"""
Pipeline integrity validator.

Detects agents that skip the 9-phase pipeline (Intake → Assess → Research →
Validate → Map → Generate → Test → Summarize → Evidence) and emit hardcoded
artifacts instead of running real MCP-driven research/validation/generation.

Fires from the Stop hook. Exits 2 on failure so Claude Code auto-retries.

Failure signals:
    P1 — pipeline.log / mcp-calls.log missing or too few MCP calls
         (exempted when pipeline.log carries the
         `[pipeline:complete:FINALIZED]` terminal sentinel — finalized
         runs are immutable, retroactive remediation impossible)
    P2 — validated.json has templated or empty verification notes
    P3 — IAM policy logic errors (mismatched StringEquals/StringNotEquals
         keys, broad Allow on Resource:* without Condition, SCP without Deny)
    P4 — IaC templates contain placeholder account IDs / ARNs
    P5 — framework coverage below threshold with no per-objective rationale
    P7 — phase-output completeness: every phase dir on disk must contain
         its declared outputs (mapping-results.json, controls-catalog.md,
         framework-mapping.md, etc.) at min-size thresholds
    P8 — reference-anchor enforcement: every preventive policy artifact under
         05-generate/preventive/ must carry a _metadata.reference resolving to
         a real entry in data/reference-repos/index.yaml (gap/skip stubs and
         documentation files exempt)
    P9 — ARN resource-delimiter validation: every Resource/NotResource ARN in a
         preventive policy artifact must use the delimiter the service's SAR ARN
         format mandates for that resource type (catches a function written
         `function/*` instead of `function:*` — a silent no-op deny)
    P10 — permission-boundary minimality: a boundary's Allow statement must not
         enumerate management actions (Create*/Update*/Put*/Delete*/Tag*/…). A
         boundary is the MAXIMUM a principal may do, not the role's grant policy;
         the control intent belongs in the Deny + condition keys
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


_MCP_CALL_TOKEN_RE = re.compile(r"\[mcp:[^\]]+:call\]")
# Terminal-state sentinel emitted by summarize/evidence at end of pipeline.
# Anchor at the source-tag column (3rd bracketed token of a pipeline.log
# line) so a message body containing the literal text can't satisfy the
# gate. Line shape: `<iso8601> [<phase>] [<source>:<status>]  <message>`.
# The sentinel is verdict-free: the fixed token FINALIZED marks a finalized
# run. Anything else does NOT close out the run.
_PIPELINE_COMPLETE_RE = re.compile(
    r"^\S+\s+\[\S+\]\s+\[pipeline:complete:FINALIZED\]",
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
    `[pipeline:complete:FINALIZED]` sentinel, the run is finalized and the
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


def _iter_json_files(root: Path):
    from validate_deployable import SKIP_DIRS

    if not root.exists():
        return
    for p in root.rglob("*.json"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        data = _load_json(p)
        if isinstance(data, dict):
            yield p, data


# Cross-service AWS-canonical wildcard-only actions. The validator only loads
# the target service's SAR data (sar-facts.json / validated.json), so cross-
# service actions like `logs:DescribeLogGroups` would otherwise always flag P3.
# Each entry below is wildcard-only per its service's SAR page (`Resource types`
# column empty in the Actions table). Keep this minimal — only add entries that
# are demonstrably wildcard-only per AWS docs, with a citation.
_CROSS_SERVICE_WILDCARD_ONLY = frozenset({
    # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatchlogs.html
    "logs:DescribeLogGroups",
    "logs:DescribeQueryDefinitions",
    "logs:DescribeAccountPolicies",
    # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html — Describe*
    # for cross-resource enumeration: ARN scoping is unsupported
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeVpcs",
    # https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html
    "secretsmanager:ListSecrets",
})


def _load_wildcard_only_actions(controls_dir: Path) -> set[str]:
    """Load the set of `<prefix>:<action>` strings AWS SAR marks wildcard-only.

    `controls_dir` is `<slug>/05-generate`. Two per-service state files are
    consulted in addition to the cross-service floor:
      1. `<slug>/01-assess/sar-facts.json` — `wildcard_only_actions[]` enumerates
         actions Phase 0 explicitly classified as wildcard-only (typically
         Create* for resources that don't exist yet).
      2. `<slug>/03-validate/validated.json` — `api_surface.operations[]` carries
         per-op `resource_types` post-validation. An op with `resource_types`
         empty or null is wildcard-only by AWS design (no ARN to scope to).

    Always unions in `_CROSS_SERVICE_WILDCARD_ONLY` (cross-service AWS-canonical
    actions — see the `_CROSS_SERVICE_WILDCARD_ONLY` constant defined above).
    When per-service files are missing or malformed, the per-service additions
    are skipped — the cross-service set is the floor, not an empty set. The
    validator stays conservative: actions only earn an exemption when an
    authoritative file positively says they are wildcard-only.
    """
    out: set[str] = set()

    def _qualified(name: str, fallback_prefix: str) -> str | None:
        """Return `prefix:Action`, or None if neither the action nor the
        fallback prefix is usable. Bare `Action` strings with an empty
        fallback would otherwise enter the set as `:Action` and silently
        match nothing.
        """
        if ":" in name:
            return name
        if not fallback_prefix:
            return None
        return f"{fallback_prefix}:{name}"

    sar_path = controls_dir.parent / "01-assess" / "sar-facts.json"
    facts = _load_json(sar_path) or {}
    prefix = facts.get("service_prefix") or ""
    for a in facts.get("wildcard_only_actions") or []:
        if isinstance(a, str):
            qualified = _qualified(a, prefix)
            if qualified:
                out.add(qualified)
    for a in facts.get("actions") or []:
        if isinstance(a, dict) and not (a.get("resource_types") or []):
            name = a.get("name") or a.get("action")
            if isinstance(name, str):
                qualified = _qualified(name, prefix)
                if qualified:
                    out.add(qualified)

    val_path = controls_dir.parent / "03-validate" / "validated.json"
    val = _load_json(val_path) or {}
    val_prefix = (val.get("capabilities", {}).get("iam", {}).get("service_prefix")
                  or val.get("service_prefix") or prefix)
    for op in (val.get("api_surface") or {}).get("operations", []) or []:
        if not isinstance(op, dict):
            continue
        rts = op.get("resource_types")
        if rts:  # populated list — action IS scoped, not wildcard-only
            continue
        op_name = op.get("operation") or op.get("action")
        if isinstance(op_name, str):
            qualified = _qualified(op_name, val_prefix)
            if qualified:
                out.add(qualified)

    out |= _CROSS_SERVICE_WILDCARD_ONLY
    return out


def _action_matches_wildcard_only(action: str, wildcard_only: set[str]) -> bool:
    """True when `action` is a literal entry in the wildcard-only set.

    Globs like `datasync:Describe*` are NOT exempted. Earlier glob-expansion
    matched any wildcard-only action under the prefix and exempted the whole
    glob, but SAR data is loaded from per-service state files and is often
    incomplete — actions outside the SAR snapshot but matched by the glob
    were silently allowed. Literal-only matching keeps the carve-out tight
    against missing data.
    """
    return action in wildcard_only


def check_iam_policies(controls_dir: Path) -> list[str]:
    errors: list[str] = []
    if not controls_dir.exists():
        return errors

    wildcard_only = _load_wildcard_only_actions(controls_dir)

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
                # KMS key-admin carve-out: `kms:*` on `*` to account-root is the
                # canonical AWS-recommended key-administrator statement. Resource `*`
                # in a KMS key policy scopes to the enclosing key, not all resources.
                # See https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
                principal = stmt.get("Principal") or {}
                is_kms_key_policy = "kms-key-policy" in policy_file.name.lower()
                is_root_admin = (
                    is_kms_key_policy
                    and broad_actions == ["kms:*"]
                    and isinstance(principal, dict)
                    and any(
                        v == "*" or (isinstance(v, str) and v.endswith(":root"))
                        or (isinstance(v, list) and all(
                            isinstance(x, str) and (x == "*" or x.endswith(":root"))
                            for x in v
                        ))
                        for v in principal.values()
                    )
                )
                # SAR wildcard-only carve-out: an action whose SAR `resource_types`
                # is empty (e.g., DataSync Describe*/List*, logs:DescribeLogGroups
                # in the target service's API surface) CANNOT be ARN-scoped — it
                # can only appear with `Resource: "*"`. Flagging it as
                # exfiltration produces a false positive. Only exempt when
                # EVERY broad action resolves to wildcard-only per SAR; if any
                # action could be scoped, the original check still fires.
                all_wildcard_only = bool(broad_actions) and all(
                    _action_matches_wildcard_only(a, wildcard_only)
                    for a in broad_actions
                )
                if (
                    broad_actions
                    and resources == ["*"]
                    and not condition
                    and not is_root_admin
                    and not all_wildcard_only
                ):
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


# --- P9: ARN resource-delimiter validation --------------------------------
# A resource ARN has 6 colon-delimited fields:
#   arn:partition:service:region:account:resource
# The 6th field is `resource` — usually `<resource-type><delim><resource-id>`
# where the delimiter is `:` or `/` depending on the resource type (and is
# fixed per type by AWS). A policy that uses the WRONG delimiter (e.g. a Lambda
# function as `function/*` instead of `function:*`) matches nothing — the Deny
# is a silent no-op. The correct delimiter for each resource type is taken from
# the service's own SAR ARN patterns (sar-facts.json.resource_types[].arn_pattern),
# so this check is service-agnostic, not hardcoded to any one service.


def _resource_type_delimiters(sar_facts: dict) -> dict[str, str]:
    """Map each SAR resource-type token → the delimiter that follows it.

    Parsed from `resource_types[].arn_pattern`. For
    `arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}` the
    6th field is `function:${FunctionName}`, so the type token is `function`
    and the delimiter is `:`. A pattern whose 6th field is just `${Resource}`
    (no literal type token) contributes nothing. When a type token appears with
    conflicting delimiters across patterns (it does not in practice), the colon
    form wins — a slash variant of a colon type is the defect we want to catch.
    """
    delims: dict[str, str] = {}
    for rt in sar_facts.get("resource_types", []) or []:
        pattern = rt.get("arn_pattern")
        if not isinstance(pattern, str):
            continue
        fields = pattern.split(":", 5)
        if len(fields) < 6:
            continue
        resource_field = fields[5]
        # Find the first delimiter (`:` or `/`) and the literal token before it.
        m = re.match(r"^([A-Za-z0-9\-]+)([:/])", resource_field)
        if not m:
            continue
        token, delim = m.group(1), m.group(2)
        # A token that starts with a template var (e.g. `${FunctionName}`) has no
        # literal type prefix — skip (handled by the `[A-Za-z0-9\-]+` anchor,
        # which won't match a leading `$`).
        if token in delims and delims[token] != delim:
            # Prefer ':' on conflict (the colon form is the canonical type).
            if delim == ":":
                delims[token] = delim
        else:
            delims.setdefault(token, delim)
    return delims


def _arn_delimiter_errors(
    arn: str, service_prefix: str, delims: dict[str, str]
) -> str | None:
    """Return an error string if `arn` is malformed for this service, else None.

    Only ARNs for `service_prefix` are checked (cross-service ARNs use other
    services' formats we did not load). `*` and non-ARN strings pass. The
    resource field's leading literal type token is matched against `delims`; a
    token present in the SAR map but used with the wrong delimiter is the defect.
    """
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None  # `*` or a non-ARN value — nothing to validate here
    fields = arn.split(":", 5)
    if len(fields) < 6:
        return f"malformed ARN (needs 6 colon-delimited fields): {arn!r}"
    service = fields[2]
    if service != service_prefix:
        return None  # different service — its format was not loaded
    resource_field = fields[5]
    m = re.match(r"^([A-Za-z0-9\-]+)([:/])", resource_field)
    if not m:
        return None  # bare id / wildcard resource (e.g. `*`, `${id}`) — no token
    token, used_delim = m.group(1), m.group(2)
    expected = delims.get(token)
    if expected is None:
        return None  # unknown token — can't authoritatively judge; stay quiet
    if used_delim != expected:
        return (
            f"resource type {token!r} uses delimiter {used_delim!r} but the "
            f"service ARN format requires {expected!r} "
            f"(expected {token}{expected}…, got {arn!r}); the Deny matches "
            f"nothing and is a silent no-op"
        )
    return None


def check_arn_shapes(service_root: Path) -> list[str]:
    """P9: every Resource ARN in a preventive policy artifact must use the
    delimiter the service's SAR ARN format mandates for that resource type.

    Catches the silent-no-op class where a function ARN is written `function/*`
    (slash) instead of `function:*` (colon). The authoritative per-type
    delimiters come from sar-facts.json, so the check works for any service.
    """
    errors: list[str] = []
    controls_dir = service_root / "05-generate"
    if not controls_dir.exists():
        return errors

    sar_facts = _load_json(service_root / "01-assess" / "sar-facts.json") or {}
    service_prefix = sar_facts.get("service_prefix") or ""
    delims = _resource_type_delimiters(sar_facts)
    if not (service_prefix and delims):
        return errors  # no authoritative format to validate against

    preventive_dir = controls_dir / "preventive"
    for policy_file, data in _iter_json_files(preventive_dir):
        if "Statement" not in data:
            continue
        statements = data["Statement"]
        if not isinstance(statements, list):
            statements = [statements]
        rel = policy_file.relative_to(controls_dir)
        for i, stmt in enumerate(statements):
            if not isinstance(stmt, dict):
                continue
            for field in ("Resource", "NotResource"):
                resources = stmt.get(field)
                if resources is None:
                    continue
                if isinstance(resources, str):
                    resources = [resources]
                for arn in resources:
                    err = _arn_delimiter_errors(arn, service_prefix, delims)
                    if err:
                        errors.append(f"P9 {rel} Statement[{i}] {field}: {err}")
    return errors


# --- P10: permission-boundary minimality -----------------------------------
# A permission boundary defines the MAXIMUM a principal may do; it is not the
# role's grant policy. Its Allow exists only to keep the boundary from being a
# deny-all — it should be a minimal floor (reads + the actions the enforcing
# Denys gate), NOT an enumerated allowlist of management actions. Enumerating
# Create*/Update*/Put*/Delete*/Tag*/… in the Allow re-creates the role policy
# inside the boundary (an observed defect) and means the control intent is not
# actually carried by the boundary's Deny + condition keys.

# Read-only action verbs. The boundary-minimality check is FAIL-CLOSED: an Allow
# action is management UNLESS its verb is one of these read-only verbs. An
# allowlist of write verbs would fail open — any escalation action whose verb the
# author didn't anticipate (RunInstances, AssumeRole, ScheduleKeyDeletion,
# RestoreObject, …) would slip through. Inverting to a read allowlist means an
# unknown verb is treated as management, which is the safe default for a boundary.
_BOUNDARY_READ_VERBS = (
    "Get", "List", "Describe", "Search", "Query", "Lookup", "View", "Read",
    "Batch", "Scan", "Head", "Check", "Test", "Validate", "Estimate",
    "Detect", "Discover", "Count", "Filter", "Select",
)


def _is_management_action(action: str) -> bool:
    """True if a boundary-Allow action mutates state (fail-closed).

    An action is management UNLESS its verb is a known read-only verb. So
    `lambda:CreateFunction`, `ec2:RunInstances`, `sts:AssumeRole`,
    `kms:ScheduleKeyDeletion` → True (management); `lambda:GetFunction`,
    `lambda:ListX`, `s3:DescribeJob` → False (read). A wildcard glob counts as
    management unless its stem is a read verb: `lambda:Create*` → True,
    `lambda:Get*` → False, and a bare `*` / `prefix:*` → True (it spans writes).
    `Invoke*` is intentionally treated as management on a boundary — invoke is a
    privileged data-plane action a boundary should constrain, not floor.
    """
    name = action.split(":", 1)[1] if ":" in action else action
    if not name:
        return False
    if name == "*":
        return True  # spans every action, including writes
    # Strip a trailing wildcard to test the verb stem (Create* → Create).
    stem = name[:-1] if name.endswith("*") else name
    # A glob whose stem is a read verb (Get*, List*) is read-only; otherwise a
    # glob is management (Create*, or an ambiguous stem like Cr* → management).
    return not any(stem.startswith(v) for v in _BOUNDARY_READ_VERBS)


def check_boundary_minimality(service_root: Path) -> list[str]:
    """P10: a permission-boundary Allow must not enumerate management actions.

    Only `permission-boundary*.json` artifacts are checked. Each Allow statement
    is scanned; if it enumerates one or more management actions
    (Create*/Update*/Put*/Delete*/Tag*/…), the boundary is re-creating the role's
    grant policy instead of carrying the control intent in its Deny + condition
    keys — flag it. Deny statements and read/list/invoke Allows are fine.
    """
    errors: list[str] = []
    preventive_dir = service_root / "05-generate" / "preventive"
    if not preventive_dir.exists():
        return errors

    for policy_file, data in _iter_json_files(preventive_dir):
        # Identify a boundary by filename OR by its metadata, so a renamed file
        # (pb.json, boundary.json) cannot dodge the check.
        meta = data.get("_metadata") or {}
        meta_blob = " ".join(
            str(meta.get(k, "")) for k in ("mechanism", "posture", "layer")
        ).lower()
        is_boundary = (
            "permission-boundary" in policy_file.name.lower()
            or "boundary" in policy_file.name.lower()
            or "permission boundary" in meta_blob
            or "permission-boundary" in meta_blob
        )
        if not is_boundary:
            continue
        if "Statement" not in data:
            continue
        statements = data["Statement"]
        if not isinstance(statements, list):
            statements = [statements]
        rel = policy_file.relative_to(service_root / "05-generate")
        for i, stmt in enumerate(statements):
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            mgmt = sorted({a for a in actions if _is_management_action(a)})
            if mgmt:
                errors.append(
                    f"P10 {rel} Statement[{i}] (Sid {stmt.get('Sid', '?')!r}): "
                    f"permission-boundary Allow enumerates management action(s) "
                    f"{mgmt} — a boundary is the MAXIMUM a principal may do, not "
                    f"the role's grant policy. Keep the Allow to a minimal floor "
                    f"(reads + the actions the enforcing Denys gate); carry the "
                    f"control intent in the Deny + condition keys."
                )
    return errors


def check_iac_placeholders(iac_dir: Path) -> list[str]:
    # Reuse the canonical exclude list from validate_deployable so adding a new
    # vendored-dep dir doesn't require touching two places.
    from validate_deployable import SKIP_DIRS

    errors: list[str] = []
    if not iac_dir.exists():
        return errors
    for path in iac_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
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


def check_framework_coverage(map_dir: Path) -> list[str]:
    """Check framework coverage from 04-map/ phase dir.

    Fails closed when 04-map/ exists but neither mapping-results.json nor
    map-framework-mapped.json is loadable, OR when the loaded JSON lacks
    a non-empty `framework_mapping` key. P7's size threshold is
    content-blind (>=1024 bytes); a 1024-byte JSON without the
    framework_mapping key would clear P7 and silently clear P5 too.
    Same fail-closed pattern as check_validated_notes (P2).
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
    "05-generate": [
        # 05-generate/ contains category subdirs, not single files.
        # Existence of at least one of {preventive, proactive, detective,
        # responsive, iac} signals the phase ran. Empty dir = incomplete.
    ],
    "06-test": [
        ("test-results.json", 256),
        # deployed-resources.json only required for full-deploy (where
        # Phase 7 will run); checked separately below.
    ],
    "07-summarize": [
        ("APPROVAL-REPORT.md", 2048),
    ],
    "08-evidence": [
        ("cli-commands.json", 256),
        ("attestation-results.json", 256),
        ("attestation-report.md", 1024),
    ],
}


def check_phase_outputs(service_root: Path) -> list[str]:
    """P7: every phase dir that exists must contain its documented outputs.

    Walks each phase dir under service_root and asserts that every required
    output exists and meets its minimum size threshold. A phase dir not
    present is considered "phase did not run" and skipped silently — the
    user may have set testing.mode=skip, --dry-run, etc. A phase dir that
    contains a `phase-skipped.json` sentinel is treated the same way: the
    phase deliberately skipped itself (e.g. Evidence skips when Test ran
    dry-run and deployed nothing), so its required outputs are not expected.

    The full-deploy → Phase 7 contract gets an extra check: if 06-test/
    exists with deployed-resources.json AND 08-evidence/ exists, the linkage
    is sound; if 06-test/test-results.json says full-deploy succeeded but
    deployed-resources.json is missing, Phase 7 cannot run.
    """
    errors: list[str] = []

    for phase_name, required in PHASE_REQUIRED_OUTPUTS.items():
        phase_dir = service_root / phase_name
        if not phase_dir.exists():
            continue  # phase did not run — OK
        if (phase_dir / "phase-skipped.json").exists():
            continue  # phase deliberately skipped itself — outputs not expected

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

    # 05-generate/: at least one category subdir must contain real files.
    # `any(cat_dir.rglob("*"))` would return True for an empty subdir tree
    # (any directory entry counts), letting an empty `preventive/empty/`
    # satisfy the gate. Require at least one actual file.
    generate_dir = service_root / "05-generate"
    if generate_dir.exists():
        categories = ["preventive", "proactive", "detective", "responsive", "iac"]
        any_populated = False
        for cat in categories:
            cat_dir = generate_dir / cat
            if cat_dir.exists() and any(p.is_file() for p in cat_dir.rglob("*")):
                any_populated = True
                break
        if not any_populated:
            errors.append(
                f"P7 {service_root.name}/05-generate/: phase ran but produced "
                f"NO files in any of {categories}. Re-run generate."
            )

    # full-deploy → Phase 7 contract: if 08-evidence/ exists, then
    # 06-test/deployed-resources.json must also exist (Phase 7 reads it).
    evidence_dir = service_root / "08-evidence"
    if evidence_dir.exists() and not (evidence_dir / "phase-skipped.json").exists():
        deployed_resources = service_root / "06-test" / "deployed-resources.json"
        if not deployed_resources.exists():
            errors.append(
                f"P7 {service_root.name}/06-test/deployed-resources.json: MISSING "
                f"but 08-evidence/ exists. Phase 7 needs deployed-resources.json "
                f"to know which stack/ARNs to probe; without it, every CLI verdict "
                f"will be ERROR. Re-run Phase 5 with full-deploy mode."
            )

    return errors


def check_reference_anchors(service_root: Path) -> list[str]:
    """P8: every preventive policy artifact must carry a resolvable anchor.

    Delegates to validate_reference_anchor.check_service. Imported lazily so a
    missing module degrades gracefully (returns []) rather than breaking the
    whole Stop hook — the dedicated PostToolUse path still surfaces anchor
    failures per-file in that case.
    """
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from validate_reference_anchor import check_service  # type: ignore
    except ImportError:
        return []
    return check_service(service_root)


# Validator contract: every check_*() must fail-closed when the artifact it
# reads exists but is missing/malformed. Pass-7 audit (2026-05-19) confirmed:
#   - P1, P2, P5, P7 fail-closed with explicit `P{N}`-prefixed errors.
#     P2/P5 use the `P{N} FAIL: ...` shape on missing-artifact branches
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

        # Check controls in 05-generate/
        controls_dir = service_root / "05-generate"
        if controls_dir.exists():
            errors.extend(check_iam_policies(controls_dir))
            iac_dir = controls_dir / "iac"
            if iac_dir.exists():
                errors.extend(check_iac_placeholders(iac_dir))
            # P8: every preventive policy artifact must anchor to a reference.
            errors.extend(check_reference_anchors(service_root))
            # P9: every Resource ARN must use the SAR-mandated delimiter for its
            # resource type (catches function/* vs function:* silent no-ops).
            errors.extend(check_arn_shapes(service_root))
            # P10: a permission-boundary Allow must not enumerate management
            # actions (the boundary is a maximum, not the role's grant policy).
            errors.extend(check_boundary_minimality(service_root))

        # Check framework coverage in 04-map/
        map_dir = service_root / "04-map"
        if map_dir.exists():
            errors.extend(check_framework_coverage(map_dir))

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
