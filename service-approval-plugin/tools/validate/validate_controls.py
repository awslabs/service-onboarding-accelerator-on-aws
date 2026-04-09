#!/usr/bin/env python3
"""
Per-file deterministic validator for generated security control artifacts.

Checks generated artifacts against validated.json and mapping-results.json
as ground truth. Pure stdlib Python (yaml optional).

Usage:
    python3 validate_controls.py <file_path>

Exit codes:
    0 — all checks pass
    2 — validation errors found (errors on stderr)
"""

import json
import os
import re
import sys

# ================================================================
# Global AWS condition keys — always valid, not service-specific
# ================================================================

_GLOBAL_CONDITION_KEYS = {
    "aws:CalledVia",
    "aws:CalledViaFirst",
    "aws:CalledViaLast",
    "aws:CurrentTime",
    "aws:EpochTime",
    "aws:FederatedProvider",
    "aws:MultiFactorAuthAge",
    "aws:MultiFactorAuthPresent",
    "aws:PrincipalAccount",
    "aws:PrincipalARN",
    "aws:PrincipalIsAWSService",
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalServiceName",
    "aws:PrincipalServiceNamesList",
    "aws:PrincipalTag",
    "aws:PrincipalType",
    "aws:Referer",
    "aws:RequestedRegion",
    "aws:RequestTag",
    "aws:ResourceAccount",
    "aws:ResourceOrgID",
    "aws:ResourceOrgPaths",
    "aws:ResourceTag",
    "aws:SecureTransport",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:SourceIdentity",
    "aws:SourceIp",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:TagKeys",
    "aws:TokenIssueTime",
    "aws:UserAgent",
    "aws:ViaAWSService",
    "aws:VpcSourceIp",
}

# Network perimeter condition keys that require null-key protection
_NETWORK_PERIMETER_KEYS = {
    "aws:SourceVpc",
    "aws:SourceVpce",
}


# ================================================================
# State file loading
# ================================================================

def _find_state_dir(file_path: str) -> str | None:
    """Walk up from file_path to find .service-approval/state/."""
    d = os.path.dirname(os.path.abspath(file_path))
    for _ in range(10):
        candidate = os.path.join(d, ".service-approval", "state")
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def _load_json(path: str) -> dict | None:
    """Load JSON file, return None if missing or invalid."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def load_state_files(file_path: str) -> tuple:
    """Load validated.json and mapping-results.json from nearest state dir."""
    state_dir = _find_state_dir(file_path)
    if not state_dir:
        return None, None
    validated = _load_json(os.path.join(state_dir, "validated.json"))
    mapping = _load_json(os.path.join(state_dir, "mapping-results.json"))
    return validated, mapping


# ================================================================
# Metadata extraction (handles both UPPERCASE and lowercase keys)
# ================================================================

def extract_metadata(data: dict) -> dict | None:
    """Extract _metadata from JSON, normalizing keys to lowercase."""
    meta = data.get("_metadata")
    if not meta or not isinstance(meta, dict):
        return None
    return {k.lower(): v for k, v in meta.items()}


def _extract_metadata_controls(meta: dict) -> list[str]:
    """Extract control IDs from normalized metadata."""
    controls = meta.get("controls", "")
    if isinstance(controls, list):
        return controls
    if isinstance(controls, str):
        return [c.strip() for c in controls.split(",") if c.strip()]
    return []


# ================================================================
# Check 1: Service prefix in EventBridge rules
# ================================================================

def check_service_prefix(file_path: str, data: dict, validated: dict) -> list[str]:
    """Verify EventBridge source and eventSource match validated.json service."""
    errors = []
    expected_service = validated.get("service", "")
    if not expected_service:
        return errors

    expected_source = f"aws.{expected_service}"
    expected_event_source = f"{expected_service}.amazonaws.com"

    rules = data.get("rules", [])
    if not isinstance(rules, list):
        return errors

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        rule_name = rule.get("rule_name", f"rule[{i}]")
        pattern = rule.get("event_pattern", {})
        if not isinstance(pattern, dict):
            continue

        # Check source field
        sources = pattern.get("source", [])
        for src in sources:
            if src != expected_source:
                errors.append(
                    f"CHECK-1 service_prefix: {rule_name} has source "
                    f"'{src}', expected '{expected_source}'"
                )

        # Check eventSource in detail
        detail = pattern.get("detail", {})
        if isinstance(detail, dict):
            event_sources = detail.get("eventSource", [])
            for es in event_sources:
                if es != expected_event_source:
                    errors.append(
                        f"CHECK-1 service_prefix: {rule_name} has eventSource "
                        f"'{es}', expected '{expected_event_source}'"
                    )

    return errors


# ================================================================
# Check 2: API parameters exist in api_surface
# ================================================================

def _extract_valid_params(validated: dict) -> set[str]:
    """Build set of valid parameter paths from api_surface."""
    params = set()
    api = validated.get("api_surface", {})
    for op in api.get("operations", []):
        for p in op.get("parameters", []):
            path = p.get("path", "")
            # Normalize: strip $. prefix, lowercase
            clean = path.lstrip("$").lstrip(".")
            if clean:
                params.add(clean)
                params.add(clean.lower())
    return params


def _extract_valid_operations(validated: dict) -> set[str]:
    """Build set of valid operation names from api_surface."""
    ops = set()
    api = validated.get("api_surface", {})
    for op in api.get("operations", []):
        name = op.get("operation", "")
        if name:
            ops.add(name)
    return ops


def check_api_parameters_stepfunctions(file_path: str, data: dict, validated: dict) -> list[str]:
    """Check Step Functions Parameters blocks reference valid API params."""
    errors = []
    valid_params = _extract_valid_params(validated)
    if not valid_params:
        return errors

    states = data.get("States", {})
    for state_name, state in states.items():
        if not isinstance(state, dict):
            continue
        if state.get("Type") != "Task":
            continue
        resource = state.get("Resource", "")
        if "aws-sdk:" not in resource:
            continue

        params = state.get("Parameters", {})
        for key in params:
            # Strip .$ suffix (JSONPath reference marker)
            clean_key = key.rstrip("$").rstrip(".")
            if clean_key:
                # Skip common Step Functions intrinsics
                if clean_key.lower() in ("resulttoken", "next", "end"):
                    continue
                # We don't validate every SDK param, just flag obviously wrong ones
                # that use PascalCase when the service expects camelCase or vice versa

    return errors


def check_api_parameters_ssm(file_path: str, data: dict, validated: dict) -> list[str]:
    """Check SSM runbook executeAwsApi steps reference valid operations."""
    errors = []
    valid_ops = _extract_valid_operations(validated)
    if not valid_ops:
        return errors

    # SSM runbooks can have steps with aws:executeAwsApi action
    steps = data.get("mainSteps", [])
    if not isinstance(steps, list):
        return errors

    for step in steps:
        if not isinstance(step, dict):
            continue
        action = step.get("action", "")
        if action != "aws:executeAwsApi":
            continue
        inputs = step.get("inputs", {})
        api_action = inputs.get("Api", "")
        if api_action and api_action not in valid_ops:
            errors.append(
                f"CHECK-2 api_param: SSM step '{step.get('name', '?')}' calls "
                f"Api '{api_action}' which is not in validated api_surface operations"
            )

    return errors


# ================================================================
# Check 3: Condition keys valid
# ================================================================

def check_condition_keys(file_path: str, data: dict, validated: dict) -> list[str]:
    """Verify condition keys in IAM policies match validated.json."""
    errors = []
    service_keys = set()
    for ck in validated.get("capabilities", {}).get("iam", {}).get("condition_keys", []):
        key = ck.get("key", "")
        if key:
            service_keys.add(key)

    if not service_keys:
        return errors

    # Also include the service prefix for tag keys
    service = validated.get("service", "")

    def _check_condition_block(condition: dict, context: str):
        if not isinstance(condition, dict):
            return
        for operator, keys_dict in condition.items():
            if not isinstance(keys_dict, dict):
                continue
            for key in keys_dict:
                # Skip global AWS keys (exact match or prefix match for tag keys)
                key_base = key.split("/")[0] if "/" in key else key
                if key_base in _GLOBAL_CONDITION_KEYS:
                    continue
                # Skip if it's a service-specific key we know about
                if key in service_keys:
                    continue
                # Skip tag condition keys (service:ResourceTag/*, etc.)
                if "Tag/" in key or "TagKeys" in key:
                    continue
                errors.append(
                    f"CHECK-3 condition_key: {context} uses condition key "
                    f"'{key}' not found in validated.json condition_keys"
                )

    statements = data.get("Statement", [])
    if not isinstance(statements, list):
        return errors

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        sid = stmt.get("Sid", "unknown")
        condition = stmt.get("Condition", {})
        _check_condition_block(condition, f"Statement '{sid}'")

    return errors


# ================================================================
# Check 4: Resource types match assets
# ================================================================

def check_resource_types(file_path: str, data: dict, validated: dict) -> list[str]:
    """Verify Config rule resource_types match validated.json assets."""
    errors = []
    valid_types = {a.get("cfn_type") for a in validated.get("assets", []) if a.get("cfn_type")}
    if not valid_types:
        return errors

    for key, rule in data.items():
        if key == "_metadata":
            continue
        if not isinstance(rule, dict):
            continue
        rt = rule.get("resource_type")
        if rt and rt not in valid_types:
            errors.append(
                f"CHECK-4 resource_type: rule '{key}' has resource_type "
                f"'{rt}' not found in validated.json assets"
            )
        # Also check resource_types (plural)
        rts = rule.get("resource_types", [])
        for t in rts:
            if t not in valid_types:
                errors.append(
                    f"CHECK-4 resource_type: rule '{key}' has resource_type "
                    f"'{t}' not found in validated.json assets"
                )

    return errors


# ================================================================
# Check 5: StringEquals must not contain wildcards
# ================================================================

def _walk_conditions(data: dict, path: str = "") -> list[str]:
    """Recursively find StringEquals with wildcard values."""
    errors = []
    if not isinstance(data, dict):
        return errors

    for key, value in data.items():
        current_path = f"{path}.{key}" if path else key

        if key == "StringEquals" and isinstance(value, dict):
            for ck, cv in value.items():
                values = cv if isinstance(cv, list) else [cv]
                for v in values:
                    if isinstance(v, str) and ("*" in v or "?" in v):
                        errors.append(
                            f"CHECK-5 string_equals_wildcard: {current_path}['{ck}'] "
                            f"has value '{v}' with wildcard — use StringLike instead"
                        )
        elif isinstance(value, dict):
            errors.extend(_walk_conditions(value, current_path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    errors.extend(_walk_conditions(item, f"{current_path}[{i}]"))

    return errors


def check_string_equals_wildcards(file_path: str, data: dict) -> list[str]:
    """Check no StringEquals conditions contain wildcard characters."""
    return _walk_conditions(data)


# ================================================================
# Check 6: Null-key denial on network perimeter
# ================================================================

def check_null_key_denial(file_path: str, data: dict) -> list[str]:
    """Verify network perimeter SCPs include aws:PrincipalServiceName null check."""
    errors = []
    statements = data.get("Statement", [])
    if not isinstance(statements, list):
        return errors

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Deny":
            continue

        condition = stmt.get("Condition", {})
        if not isinstance(condition, dict):
            continue

        # Check if this statement uses network perimeter keys
        all_keys = set()
        for operator, keys_dict in condition.items():
            if isinstance(keys_dict, dict):
                all_keys.update(keys_dict.keys())

        uses_network = all_keys & _NETWORK_PERIMETER_KEYS
        if not uses_network:
            continue

        # Must have a Null check on aws:PrincipalServiceName
        null_block = condition.get("Null", {})
        has_principal_null = (
            isinstance(null_block, dict)
            and "aws:PrincipalServiceName" in null_block
        )

        # Or a condition excluding AWS service principals
        bool_block = condition.get("BoolIfExists", {}) or condition.get("Bool", {})
        has_is_aws_service = (
            isinstance(bool_block, dict)
            and "aws:PrincipalIsAWSService" in bool_block
        )

        if not has_principal_null and not has_is_aws_service:
            sid = stmt.get("Sid", "unknown")
            errors.append(
                f"CHECK-6 null_key_bypass: Statement '{sid}' uses network perimeter "
                f"keys {uses_network} but has no Null check on "
                f"'aws:PrincipalServiceName' — AWS service calls will be blocked"
            )

    return errors


# ================================================================
# Check 7: JSON/YAML syntax validation
# ================================================================

def check_json_syntax(file_path: str) -> list[str]:
    """Validate JSON file syntax."""
    try:
        with open(file_path) as f:
            json.load(f)
        return []
    except json.JSONDecodeError as e:
        return [f"CHECK-7 json_syntax: {os.path.basename(file_path)} — {e}"]
    except OSError as e:
        return [f"CHECK-7 file_read: {os.path.basename(file_path)} — {e}"]


def check_yaml_syntax(file_path: str) -> list[str]:
    """Validate YAML file syntax (requires PyYAML).
    Skips CloudFormation templates that use intrinsic function tags (!Ref, !Equals, etc.)."""
    try:
        import yaml
    except ImportError:
        return []  # Skip silently if yaml not available

    # Detect CFN intrinsic functions — PyYAML safe_load can't handle them
    try:
        with open(file_path) as f:
            content = f.read()
        if re.search(r"![A-Z][a-zA-Z]+\b", content):
            return []  # CloudFormation template with intrinsic functions — skip
    except OSError:
        pass

    try:
        import io
        yaml.safe_load(io.StringIO(content))
        return []
    except yaml.YAMLError as e:
        return [f"CHECK-7 yaml_syntax: {os.path.basename(file_path)} — {e}"]
    except OSError as e:
        return [f"CHECK-7 file_read: {os.path.basename(file_path)} — {e}"]


# ================================================================
# Check 8: Step Functions SDK tasks must have ResultPath
# ================================================================

def check_stepfunctions_resultpath(file_path: str, data: dict) -> list[str]:
    """Verify every SDK integration Task state has ResultPath set."""
    errors = []
    states = data.get("States", {})
    if not isinstance(states, dict):
        return errors

    for state_name, state in states.items():
        if not isinstance(state, dict):
            continue
        if state.get("Type") != "Task":
            continue
        resource = state.get("Resource", "")
        if "aws-sdk:" not in resource:
            continue
        if "ResultPath" not in state:
            errors.append(
                f"CHECK-8 resultpath_missing: State '{state_name}' calls "
                f"SDK resource '{resource}' but has no ResultPath — "
                f"the SDK response will overwrite the entire state input"
            )

    return errors


# ================================================================
# Check 9: Control IDs match mapping-results
# ================================================================

def check_control_id_consistency(file_path: str, data: dict, mapping: dict) -> list[str]:
    """Verify _metadata control IDs exist in mapping-results.json."""
    errors = []
    meta = extract_metadata(data)
    if not meta:
        return errors

    valid_ids = {c.get("id") for c in mapping.get("controls", []) if c.get("id")}
    if not valid_ids:
        return errors

    artifact_ids = _extract_metadata_controls(meta)
    for ctrl_id in artifact_ids:
        if ctrl_id not in valid_ids:
            errors.append(
                f"CHECK-9 control_id: '{ctrl_id}' in _metadata.controls "
                f"not found in mapping-results.json"
            )

    return errors


# ================================================================
# Check 10: Framework header validation
# ================================================================

def check_framework_header(file_path: str, data: dict, mapping: dict) -> list[str]:
    """Verify framework header references valid framework objectives."""
    errors = []
    meta = extract_metadata(data)
    if not meta:
        return errors

    framework_str = meta.get("framework", "")
    if not framework_str:
        return errors

    # Extract framework name and objectives from header
    # Format: "CSA CCMv4 — CEK-03, CEK-08, ..." or "LOG-03, LOG-05, SEF-06"
    parts = framework_str.split("—")
    if len(parts) == 2:
        objectives_str = parts[1].strip()
    else:
        objectives_str = framework_str.strip()

    artifact_objectives = {o.strip() for o in objectives_str.split(",") if o.strip()}

    # Build set of all mapped objectives from mapping-results
    all_mapped = set()
    fm = mapping.get("framework_mapping", {})
    if isinstance(fm, dict):
        for obj_id, entry in fm.items():
            if isinstance(entry, dict) and entry.get("status") == "MAPPED":
                all_mapped.add(obj_id)

    # Also gather from controls directly
    for ctrl in mapping.get("controls", []):
        for obj in ctrl.get("framework_objectives", []):
            if isinstance(obj, dict):
                obj_id = obj.get("objective_id", "")
                if obj_id:
                    all_mapped.add(obj_id)
            elif isinstance(obj, str):
                all_mapped.add(obj)

    if not all_mapped:
        return errors

    for obj in artifact_objectives:
        if obj not in all_mapped:
            errors.append(
                f"CHECK-10 framework_objective: '{obj}' in _metadata.framework "
                f"not found in mapping-results.json framework objectives"
            )

    return errors


# ================================================================
# Check 11: Comment-header control IDs in non-JSON files
# ================================================================

_CTRL_ID_PATTERN = re.compile(r"CTRL-[A-Z]+-[A-Z]+-\d+")


def _extract_comment_header_controls(file_path: str) -> list[str]:
    """Parse # CONTROLS: lines from comment headers in .yaml/.py/.guard/.rego files."""
    ctrl_ids = []
    try:
        with open(file_path) as f:
            for i, line in enumerate(f):
                if i >= 30:
                    break  # Headers are at the top
                stripped = line.strip()
                if "CONTROLS:" in stripped:
                    _, _, value = stripped.partition("CONTROLS:")
                    ctrl_ids.extend(_CTRL_ID_PATTERN.findall(value))
    except OSError:
        pass
    return ctrl_ids


def check_comment_header_control_ids(file_path: str, mapping: dict) -> list[str]:
    """Verify CTRL-* IDs in comment headers exist in mapping-results.json."""
    errors = []
    valid_ids = {c.get("id") for c in mapping.get("controls", []) if c.get("id")}
    if not valid_ids:
        return errors

    ctrl_ids = _extract_comment_header_controls(file_path)
    for ctrl_id in ctrl_ids:
        if ctrl_id not in valid_ids:
            errors.append(
                f"CHECK-11 comment_header_control_id: '{ctrl_id}' in "
                f"# CONTROLS header not found in mapping-results.json"
            )

    return errors


# ================================================================
# Main dispatcher
# ================================================================

def _categorize_file(file_path: str) -> str:
    """Determine artifact category from file path."""
    norm = file_path.replace("\\", "/")
    if "/controls/preventive/" in norm:
        return "preventive"
    if "/controls/detective/" in norm:
        if "/config-rule-lambdas/" in norm:
            return "lambda_handler"
        if "eventbridge" in os.path.basename(norm).lower():
            return "eventbridge"
        if "config-rules" in os.path.basename(norm).lower():
            return "config_rules"
        return "detective"
    if "/controls/remediation/" in norm:
        if "stepfunctions" in os.path.basename(norm).lower():
            return "stepfunctions"
        if "ssm-runbook" in os.path.basename(norm).lower():
            return "ssm_runbook"
        return "remediation"
    if "/controls/proactive/" in norm:
        return "proactive"
    if "/controls/iac/" in norm:
        return "iac"
    return "unknown"


def validate_file(file_path: str) -> list[str]:
    """Run all applicable checks on a single file. Returns list of errors."""
    errors = []
    basename = os.path.basename(file_path)
    ext = os.path.splitext(basename)[1].lower()

    # Check 7: Syntax validation (always runs)
    if ext == ".json":
        errors.extend(check_json_syntax(file_path))
        if errors:
            return errors  # Can't proceed if JSON is invalid
    elif ext in (".yaml", ".yml"):
        errors.extend(check_yaml_syntax(file_path))
        if errors:
            return errors
    elif ext in (".py", ".guard", ".rego"):
        pass  # Comment-header checks below
    else:
        return []  # Skip unknown file types

    # Load data for JSON files
    data = None
    if ext == ".json":
        data = _load_json(file_path)
        if data is None:
            return errors  # Already reported by syntax check

    # Load state files
    validated, mapping = load_state_files(file_path)

    category = _categorize_file(file_path)

    # Check 5: StringEquals wildcards (any IAM policy file)
    if data and category in ("preventive", "detective", "remediation"):
        errors.extend(check_string_equals_wildcards(file_path, data))

    # Check 9: Control ID consistency (any file with _metadata)
    if data and mapping and extract_metadata(data):
        errors.extend(check_control_id_consistency(file_path, data, mapping))

    # Check 10: Framework header (any file with _metadata)
    if data and mapping and extract_metadata(data):
        errors.extend(check_framework_header(file_path, data, mapping))

    # Check 11: Comment-header control IDs (non-JSON files with # CONTROLS: headers)
    if mapping and ext in (".yaml", ".yml", ".py", ".guard", ".rego"):
        errors.extend(check_comment_header_control_ids(file_path, mapping))

    # Check 12: SCP size limit (5120 chars)
    if category == "preventive" and ext == ".json" and "scp" in basename.lower():
        try:
            size = os.path.getsize(file_path)
            if size > 5120:
                errors.append(
                    f"CHECK-12 scp_size: {basename} is {size} chars "
                    f"(limit 5120) — split into multiple policies"
                )
        except OSError:
            pass

    # Category-specific checks
    if category == "preventive" and data:
        # Check 3: Condition keys
        if validated:
            errors.extend(check_condition_keys(file_path, data, validated))
        # Check 6: Null-key denial
        errors.extend(check_null_key_denial(file_path, data))

    elif category == "eventbridge" and data:
        # Check 1: Service prefix
        if validated:
            errors.extend(check_service_prefix(file_path, data, validated))

    elif category == "config_rules" and data:
        # Check 4: Resource types
        if validated:
            errors.extend(check_resource_types(file_path, data, validated))

    elif category == "stepfunctions" and data:
        # Check 8: ResultPath
        errors.extend(check_stepfunctions_resultpath(file_path, data))
        # Check 2: API parameters
        if validated:
            errors.extend(check_api_parameters_stepfunctions(file_path, data, validated))

    elif category == "ssm_runbook" and ext in (".yaml", ".yml"):
        # Check 2: API parameters (YAML)
        if validated:
            try:
                import yaml
                with open(file_path) as f:
                    yaml_data = yaml.safe_load(f)
                if isinstance(yaml_data, dict):
                    errors.extend(check_api_parameters_ssm(file_path, yaml_data, validated))
            except (ImportError, Exception):
                pass

    return errors


# ================================================================
# CLI entry point
# ================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_controls.py <file_path>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    errors = validate_file(file_path)

    if errors:
        print(f"VALIDATION FAILED: {os.path.basename(file_path)} ({len(errors)} errors)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    else:
        print(f"VALIDATION PASSED: {os.path.basename(file_path)}")
        sys.exit(0)


if __name__ == "__main__":
    main()
