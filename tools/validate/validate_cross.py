#!/usr/bin/env python3
"""
Cross-artifact consistency validator.

Runs after a generation phase completes to verify consistency across all
generated control artifacts in .service-approval/<slug>/05-recommended-guidance/.

Usage:
    python3 validate_cross.py <controls_dir>

Exit codes:
    0 — all checks pass
    2 — validation errors found (errors on stderr)
"""

import json
import os
import re
import sys

try:
    from .artifact_rules import iter_rules, resource_types
except ImportError:
    from artifact_rules import iter_rules, resource_types


# ================================================================
# Helpers
# ================================================================

def _load_json(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _find_state_dir(controls_dir: str) -> dict[str, str] | None:
    """Find sibling phase directories relative to controls dir.

    In the new layout, controls_dir is .service-approval/<slug>/05-recommended-guidance/
    and we need to find 04-map/ and 03-validate/ siblings.

    Returns:
        Dict with keys "map" and "validate" pointing to phase directories,
        or None if not found.
    """
    # controls_dir is typically .service-approval/<slug>/05-recommended-guidance/
    # Parent is the service root
    service_root = os.path.dirname(controls_dir.rstrip("/"))
    map_dir = os.path.join(service_root, "04-map")
    validate_dir = os.path.join(service_root, "03-validate")
    # Return dict if at least map dir exists (validate is optional for some checks)
    if os.path.isdir(map_dir):
        return {"map": map_dir, "validate": validate_dir}
    return None


def _extract_metadata(data: dict) -> dict | None:
    # Some artifacts have a top-level JSON array (e.g. CloudFormation parameter
    # files) rather than an object; those carry no _metadata. Guard the type so
    # walking them never raises.
    if not isinstance(data, dict):
        return None
    meta = data.get("_metadata")
    if not meta or not isinstance(meta, dict):
        return None
    return {k.lower(): v for k, v in meta.items()}


def _extract_controls_from_meta(meta: dict) -> set[str]:
    controls = meta.get("controls", "")
    if isinstance(controls, list):
        return {c.strip() for c in controls if c.strip()}
    if isinstance(controls, str):
        return {c.strip() for c in controls.split(",") if c.strip()}
    return set()


def _walk_json_files(controls_dir: str) -> list[str]:
    """Find all JSON files under controls_dir."""
    result = []
    for root, dirs, files in os.walk(controls_dir):
        dirs[:] = [d for d in dirs if d not in (".terraform", "node_modules", "__pycache__")]
        for f in files:
            if f.endswith(".json") and not f.startswith("."):
                result.append(os.path.join(root, f))
    return result


def _walk_all_files(controls_dir: str) -> list[str]:
    """Find all artifact files under controls_dir."""
    result = []
    for root, dirs, files in os.walk(controls_dir):
        dirs[:] = [d for d in dirs if d not in (".terraform", "node_modules", "__pycache__")]
        for f in files:
            if not f.startswith("."):
                result.append(os.path.join(root, f))
    return result


_CTRL_ID_PATTERN = re.compile(r"CTRL-[A-Z]+-[A-Z]+-\d+")


# ================================================================
# Check X1: Framework header consistency across all files
# ================================================================

def check_framework_header_consistency(controls_dir: str) -> list[str]:
    """Verify all artifacts have identical FRAMEWORK header strings."""
    errors = []
    headers: dict[str, list[str]] = {}  # framework_string -> [file_paths]

    for fpath in _walk_json_files(controls_dir):
        data = _load_json(fpath)
        if not data:
            continue
        meta = _extract_metadata(data)
        if not meta:
            continue
        fw = meta.get("framework", "")
        if fw:
            # Normalize: strip whitespace, sort objectives for comparison
            parts = fw.split("—")
            if len(parts) == 2:
                prefix = parts[0].strip()
                objs = sorted(o.strip() for o in parts[1].split(",") if o.strip())
                normalized = f"{prefix} — {', '.join(objs)}"
            else:
                objs = sorted(o.strip() for o in fw.split(",") if o.strip())
                normalized = ", ".join(objs)
            headers.setdefault(normalized, []).append(os.path.basename(fpath))

    if len(headers) > 1:
        for fw_str, files in headers.items():
            errors.append(
                f"CHECK-X1 framework_consistency: [{', '.join(files)}] "
                f"have framework header: '{fw_str[:80]}...'"
            )
        errors.insert(0,
            f"CHECK-X1 framework_consistency: {len(headers)} distinct framework "
            f"headers found — all artifacts must share the same full sorted union"
        )

    return errors


# ================================================================
# Check X2: Control coverage — every control ID referenced
# ================================================================

def check_control_coverage(controls_dir: str, mapping: dict) -> list[str]:
    """Verify every control in mapping-results is referenced by at least one artifact."""
    errors = []
    expected_ids = {c.get("id") for c in mapping.get("controls", []) if c.get("id")}
    if not expected_ids:
        return errors

    found_ids: set[str] = set()

    # Scan JSON _metadata and inline control_ids
    for fpath in _walk_json_files(controls_dir):
        data = _load_json(fpath)
        if not data or not isinstance(data, dict):
            continue
        meta = _extract_metadata(data)
        if meta:
            found_ids |= _extract_controls_from_meta(meta)

        for key, val in data.items():
            if key == "_metadata":
                continue
            if isinstance(val, dict):
                for cid in val.get("control_ids", []):
                    found_ids.add(cid)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        for cid in item.get("control_ids", []):
                            found_ids.add(cid)

    # Also scan comment headers in ALL non-JSON files (including IaC)
    for fpath in _walk_all_files(controls_dir):
        if fpath.endswith(".json"):
            continue
        try:
            with open(fpath) as f:
                for i, line in enumerate(f):
                    if i >= 30:
                        break
                    if "CONTROLS:" in line:
                        found_ids.update(_CTRL_ID_PATTERN.findall(line))
        except (OSError, UnicodeDecodeError):
            pass

    # Controls with mechanism "IaC Template" are implemented by the IaC files
    # themselves — they don't need explicit _metadata or CONTROLS: headers
    iac_ctrl_ids = {
        c.get("id") for c in mapping.get("controls", [])
        if c.get("mechanism", "").lower() in ("iac template", "iac")
    }

    # Controls the preventive recommender deliberately deferred are NOT orphans:
    # a REFER_TO_REFERENCE decision (no reference example anchors the objective)
    # or a ROUTE_DETECTIVE decision (not preventable at request time) is a
    # documented, intentional non-authoring outcome — the risk-averse path. The
    # decision is recorded in preventive-plan.json, so a deferred control counts
    # as covered as long as it carries an explicit plan decision. (A preventive
    # control that is simply MISSING from the plan is still flagged.)
    deferred_ctrl_ids = _deferred_preventive_controls(controls_dir)

    orphaned = expected_ids - found_ids - iac_ctrl_ids - deferred_ctrl_ids
    if orphaned:
        errors.append(
            f"CHECK-X2 control_coverage: {len(orphaned)} control(s) in mapping-results "
            f"not referenced by any artifact: {sorted(orphaned)}"
        )

    return errors


def _deferred_preventive_controls(controls_dir: str) -> set[str]:
    """Control IDs the recommender deferred via REFER_TO_REFERENCE / ROUTE_DETECTIVE.

    Read from preventive-plan.json (the recommender gate). These are intentional
    non-authoring decisions — the objective could not be anchored to a reference
    or is not preventable at request time — so the control legitimately has no
    preventive artifact. Returns the empty set when no plan exists (e.g. a run
    that predates the gated preventive sub-pipeline), preserving prior behavior.
    """
    plan_path = os.path.join(controls_dir, "preventive-plan.json")
    plan = _load_json(plan_path)
    if not plan:
        return set()
    deferred = set()
    for d in plan.get("decisions", []):
        if not isinstance(d, dict):
            continue
        if d.get("decision") in ("REFER_TO_REFERENCE", "ROUTE_DETECTIVE"):
            cid = d.get("control_id")
            if cid:
                deferred.add(cid)
    return deferred


# ================================================================
# Check X4: Permission-boundary org prerequisite
# ================================================================

# Mapping mechanism strings that resolve to an IAM permission boundary.
_BOUNDARY_MECHANISMS = {"iam permission boundary", "permission boundary"}

# Matches the finalized-run sentinel at the source-tag column of a pipeline.log
# line (mirrors validate_pipeline_integrity._PIPELINE_COMPLETE_RE).
_FINALIZED_RE = re.compile(
    r"^\S+\s+\[\S+\]\s+\[pipeline:complete:FINALIZED\]", re.MULTILINE
)


def _is_finalized_run(controls_dir: str) -> bool:
    """True if the run carries the `[pipeline:complete:FINALIZED]` sentinel.

    A finalized run is frozen and immutable — its plan/artifacts cannot be
    remediated. A check added after a run finalized must not retroactively fail
    it (it would brick every subsequent Stop hook for that frozen state). Honored
    the same way P1 in validate_pipeline_integrity is. `controls_dir` is
    `<service_root>/05-recommended-guidance`, so pipeline.log is one level up.
    """
    service_root = os.path.dirname(controls_dir.rstrip("/"))
    log_path = os.path.join(service_root, "pipeline.log")
    if not os.path.isfile(log_path):
        return False
    try:
        with open(log_path) as fh:
            return bool(_FINALIZED_RE.search(fh.read()))
    except OSError:
        return False


def _org_attaches_permission_boundaries(controls_dir: str) -> bool:
    """Whether the org recorded that it attaches permission boundaries.

    Read from intake-manifest.json at `org_context.permission_boundaries_attached`
    (default False when the block or field is absent). A permission boundary only
    takes effect if the org actually attaches one to its delegated-admin / role
    principals; absent that prerequisite, authoring a boundary is shelfware. So
    the recommender authors a boundary ONLY when this is explicitly true —
    otherwise it refers the customer to the reference example.
    """
    service_root = os.path.dirname(controls_dir.rstrip("/"))
    manifest = _load_json(os.path.join(service_root, "00-intake", "intake-manifest.json"))
    if not isinstance(manifest, dict):
        return False
    org = manifest.get("org_context")
    if not isinstance(org, dict):
        return False
    return org.get("permission_boundaries_attached") is True


def check_boundary_org_prerequisite(controls_dir: str) -> list[str]:
    """X4: a GENERATE_IAM boundary decision requires the org opt-in.

    A permission boundary is refer-by-default: the recommender must NOT author a
    boundary unless the run records that the org attaches boundaries to its
    principals (intake org_context.permission_boundaries_attached == true).
    Without the opt-in, the decision must be REFER_TO_REFERENCE, pointing at the
    reference boundary example. This keeps the boundary authoring surface out of
    the common case entirely.
    """
    errors: list[str] = []
    plan = _load_json(os.path.join(controls_dir, "preventive-plan.json"))
    if not plan:
        return errors
    if _is_finalized_run(controls_dir):
        return errors  # frozen run — the plan can't be remediated retroactively
    if _org_attaches_permission_boundaries(controls_dir):
        return errors  # opt-in recorded — authoring a boundary is permitted
    for d in plan.get("decisions", []):
        if not isinstance(d, dict):
            continue
        mechanism = (d.get("mechanism") or "").strip().lower()
        if d.get("decision") == "GENERATE_IAM" and mechanism in _BOUNDARY_MECHANISMS:
            errors.append(
                f"X4 {d.get('control_id', '?')}: decision GENERATE_IAM for a "
                f"permission boundary, but the run did not record "
                f"org_context.permission_boundaries_attached=true in "
                f"intake-manifest.json. Permission boundaries are refer-by-default "
                f"— set the decision to REFER_TO_REFERENCE (point to the reference "
                f"boundary example) unless the org explicitly attaches boundaries."
            )
    return errors


# ================================================================
# Check X3: Resource type consistency across Config and EventBridge
# ================================================================

def check_resource_type_consistency(controls_dir: str, validated: dict) -> list[str]:
    """Cross-check resource types used in Config rules vs EventBridge rules."""
    errors = []
    valid_types = {a.get("cfn_type") for a in validated.get("assets", []) if a.get("cfn_type")}

    config_types: set[str] = set()

    for fpath in _walk_json_files(controls_dir):
        basename = os.path.basename(fpath).lower()
        data = _load_json(fpath)
        if not data or not isinstance(data, dict):
            continue

        if basename in {"config-rules.json", "config-org-rules.json"}:
            for _, rule in iter_rules(data):
                config_types.update(resource_types(rule))

    # Check Config types against validated assets
    invalid_config = config_types - valid_types
    if invalid_config:
        errors.append(
            f"CHECK-X3 resource_type_consistency: Config rules reference "
            f"resource types not in validated.json: {sorted(invalid_config)}"
        )

    return errors


# ================================================================
# Check X4: No duplicate rule/alarm names
# ================================================================

def check_no_duplicate_names(controls_dir: str) -> list[str]:
    """Verify no two rules, alarms, or policies share the same name."""
    errors = []
    names: dict[str, list[str]] = {}  # name -> [source files]

    for fpath in _walk_json_files(controls_dir):
        data = _load_json(fpath)
        if not data or not isinstance(data, dict):
            continue
        basename = os.path.basename(fpath)

        # Check rule_name in list-of-rules format
        rules = data.get("rules", [])
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict):
                    name = rule.get("rule_name", "")
                    if name:
                        names.setdefault(name, []).append(basename)

        # Check rule_name in dict-of-rules format
        for key, val in data.items():
            if key == "_metadata" or not isinstance(val, dict):
                continue
            name = val.get("rule_name", "") or val.get("alarm_name", "")
            if name:
                names.setdefault(name, []).append(basename)

    for name, files in names.items():
        if len(files) > 1:
            errors.append(
                f"CHECK-X4 duplicate_name: '{name}' appears in "
                f"{', '.join(files)}"
            )

    return errors


# ================================================================
# Check X5: Condition key consistency across policy files
# ================================================================

def check_condition_key_consistency(controls_dir: str, validated: dict) -> list[str]:
    """Verify condition keys across all policy files are from validated.json."""
    errors = []
    service_keys = set()
    for ck in validated.get("capabilities", {}).get("iam", {}).get("condition_keys", []):
        # Support both object format ({"key": "lambda:VpcIds", ...}) and plain string format
        if isinstance(ck, dict):
            key = ck.get("key", "")
        elif isinstance(ck, str):
            key = ck
        else:
            sys.stderr.write(
                f"WARN check_condition_key_consistency: unexpected condition_key type "
                f"{type(ck).__name__} in validated.json — skipping entry: {ck!r}\n"
            )
            key = ""
        if key:
            service_keys.add(key)

    if not service_keys:
        return errors

    # Global keys that are always valid
    global_prefixes = ("aws:", "s3:", "ec2:", "kms:", "iam:", "sts:", "lambda:", "logs:")

    all_keys_used: dict[str, list[str]] = {}  # key -> [files]

    for fpath in _walk_json_files(controls_dir):
        norm = fpath.replace("\\", "/")
        if "/proactive/" in norm:
            continue
        data = _load_json(fpath)
        if not data:
            continue

        def _extract_keys(obj, path=""):
            if isinstance(obj, dict):
                if "Condition" in obj:
                    cond = obj["Condition"]
                    if isinstance(cond, dict):
                        for op, keys_dict in cond.items():
                            if isinstance(keys_dict, dict):
                                for k in keys_dict:
                                    all_keys_used.setdefault(k, []).append(
                                        os.path.basename(fpath)
                                    )
                for v in obj.values():
                    _extract_keys(v)
            elif isinstance(obj, list):
                for item in obj:
                    _extract_keys(item)

        _extract_keys(data)

    for key, files in all_keys_used.items():
        # Skip global AWS keys
        if any(key.startswith(p) for p in global_prefixes):
            continue
        # Skip tag keys
        if "Tag/" in key or "TagKeys" in key:
            continue
        # Check against service keys
        if key not in service_keys:
            unique_files = sorted(set(files))
            errors.append(
                f"CHECK-X5 condition_key_consistency: '{key}' used in "
                f"{', '.join(unique_files)} but not in validated.json condition_keys"
            )

    return errors


# ================================================================
# Check X8: Lambda handler completeness
# ================================================================

def check_lambda_handler_completeness(controls_dir: str) -> list[str]:
    """Verify every CUSTOM_LAMBDA Config rule has a corresponding handler.py."""
    errors = []
    detective_dir = os.path.join(controls_dir, "detective")
    if not os.path.isdir(detective_dir):
        return []

    # Find all Config rule files and extract CUSTOM_LAMBDA rules
    custom_rules: list[str] = []
    for fpath in _walk_json_files(detective_dir):
        basename = os.path.basename(fpath).lower()
        if basename not in {"config-rules.json", "config-org-rules.json"}:
            continue
        data = _load_json(fpath)
        if not data or not isinstance(data, dict):
            continue
        for key, rule in iter_rules(data):
            if rule.get("source_type") == "CUSTOM_LAMBDA":
                rule_name = rule.get("rule_name", key)
                custom_rules.append(rule_name)

    # Check each custom rule has handler.py and requirements.txt
    lambdas_dir = os.path.join(detective_dir, "config-rule-lambdas")
    for rule_name in custom_rules:
        handler_dir = os.path.join(lambdas_dir, rule_name)
        handler_py = os.path.join(handler_dir, "handler.py")
        requirements = os.path.join(handler_dir, "requirements.txt")

        if not os.path.isfile(handler_py):
            errors.append(
                f"CHECK-X8 lambda_handler: CUSTOM_LAMBDA rule '{rule_name}' "
                f"has no handler.py"
            )
        if not os.path.isfile(requirements):
            errors.append(
                f"CHECK-X8 lambda_requirements: rule '{rule_name}' "
                f"missing requirements.txt"
            )

    return errors


# ================================================================
# Check X9: Resource policy confused deputy protection
# ================================================================

def check_confused_deputy(controls_dir: str) -> list[str]:
    """Verify resource policies include confused deputy conditions."""
    errors = []
    rp_file = os.path.join(controls_dir, "preventive", "resource-policy.json")
    if not os.path.isfile(rp_file):
        return []

    data = _load_json(rp_file)
    if not data:
        return []

    # The artifact is one of two shapes:
    #   1. FLAT  — a single IAM document: {Version, Statement[], _metadata}
    #   2. NESTED — a map of named policies: {name: {Version, Statement[]}}
    # The flat shape is what the preventive authors actually emit. Normalize to a
    # list of (name, policy-doc) pairs so both shapes are checked; previously the
    # flat shape slipped through entirely (its top-level values are str/list, not
    # dicts), making the whole check a silent no-op for the real artifacts.
    if "Statement" in data:
        meta = data.get("_metadata") or {}
        name = "resource-policy"
        controls = meta.get("controls") if isinstance(meta, dict) else None
        if controls:
            name = f"resource-policy ({', '.join(controls)})"
        candidates = [(name, data)]
    else:
        candidates = [(k, v) for k, v in data.items() if k != "_metadata"]

    for key, policy in candidates:
        if not isinstance(policy, dict):
            continue

        # Skip VPCE policies — they use PrincipalOrgID, not SourceAccount/SourceArn
        if "vpce" in key.lower() or "endpoint" in key.lower():
            continue

        # Only check IAM-style policy documents (must have Statement array)
        # Skip config templates like JWT authorizer configs, encryption settings, etc.
        if "Statement" not in policy and not any(
            isinstance(v, dict) and "Statement" in v for v in policy.values()
        ):
            continue

        policy_str = json.dumps(policy)
        # Confused deputy protection can be: SourceAccount, SourceArn, PrincipalOrgID
        # TLS enforcement uses SecureTransport, network perimeter uses SourceVpc/SourceVpce
        # These are legitimate alternative conditions — not confused deputy gaps
        has_identity_condition = any(
            cond in policy_str
            for cond in (
                "aws:SourceAccount", "aws:SourceArn", "aws:PrincipalOrgID",
                "aws:SecureTransport", "aws:SourceVpc", "aws:SourceVpce",
            )
        )
        if not has_identity_condition:
            errors.append(
                f"CHECK-X9 confused_deputy: '{key}' missing access restriction "
                f"conditions (SourceAccount, SourceArn, PrincipalOrgID, SecureTransport, or SourceVpc)"
            )

    return errors


# ================================================================
# Check X10: Stale control IDs across all artifacts
# ================================================================

def check_stale_control_ids(controls_dir: str, mapping: dict) -> list[str]:
    """Scan ALL files for CTRL-* references and validate against mapping-results."""
    errors = []
    valid_ids = {c.get("id") for c in mapping.get("controls", []) if c.get("id")}
    if not valid_ids:
        return errors

    stale: list[tuple[str, str]] = []

    for fpath in _walk_all_files(controls_dir):
        # Skip binary files and terraform state
        ext = os.path.splitext(fpath)[1].lower()
        if ext in (".tfstate", ".zip", ".gz", ".png", ".jpg", ".lock"):
            continue
        norm = fpath.replace("\\", "/")
        # Skip .terraform directory contents
        if "/.terraform/" in norm:
            continue

        try:
            content = open(fpath).read()
        except (OSError, UnicodeDecodeError):
            continue

        for ref in _CTRL_ID_PATTERN.findall(content):
            if ref not in valid_ids:
                stale.append((ref, os.path.relpath(fpath, controls_dir)))

    if stale:
        unique = sorted(set(stale))
        errors.append(
            f"CHECK-X10 stale_control_ids: {len(unique)} stale CTRL-* references found"
        )
        for cid, fpath in unique[:20]:  # Cap output at 20
            errors.append(f"  {cid} in {fpath}")

    return errors


# ================================================================
# Check X11: CFN Guard file exists (proactive layer)
# ================================================================

def check_proactive_completeness(controls_dir: str) -> list[str]:
    """Verify proactive artifacts exist."""
    errors = []
    proactive_dir = os.path.join(controls_dir, "proactive")
    if not os.path.isdir(proactive_dir):
        return []

    guard_file = os.path.join(proactive_dir, "cfn-guard-rules.guard")
    if not os.path.isfile(guard_file):
        errors.append("CHECK-X11 proactive: cfn-guard-rules.guard missing")

    return errors


# ================================================================
# Main
# ================================================================

def validate_all(controls_dir: str) -> list[str]:
    """Run all cross-artifact checks."""
    errors = []

    state_dirs = _find_state_dir(controls_dir)
    validated = None
    mapping = None
    if state_dirs:
        validated = _load_json(os.path.join(state_dirs["validate"], "validated.json"))
        mapping = _load_json(os.path.join(state_dirs["map"], "mapping-results.json"))

    # Always run (no state dependency)
    errors.extend(check_framework_header_consistency(controls_dir))
    errors.extend(check_no_duplicate_names(controls_dir))
    errors.extend(check_lambda_handler_completeness(controls_dir))
    errors.extend(check_confused_deputy(controls_dir))
    errors.extend(check_proactive_completeness(controls_dir))
    errors.extend(check_boundary_org_prerequisite(controls_dir))

    # Require mapping-results
    if mapping:
        errors.extend(check_control_coverage(controls_dir, mapping))
        errors.extend(check_stale_control_ids(controls_dir, mapping))

    # Require validated
    if validated:
        errors.extend(check_resource_type_consistency(controls_dir, validated))
        errors.extend(check_condition_key_consistency(controls_dir, validated))

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_cross.py <controls_dir>", file=sys.stderr)
        sys.exit(1)

    controls_dir = sys.argv[1]
    if not os.path.isdir(controls_dir):
        print(f"Directory not found: {controls_dir}", file=sys.stderr)
        sys.exit(1)

    errors = validate_all(controls_dir)

    if errors:
        print(f"CROSS-VALIDATION FAILED: {len(errors)} errors", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    else:
        print("CROSS-VALIDATION PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
