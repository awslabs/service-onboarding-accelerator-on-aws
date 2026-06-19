#!/usr/bin/env python3
"""
Semantic mapping checks (deterministic).

Beyond JSON/YAML syntax (covered by validate_deployable Tier-1) and the catalog
cross-check (validate_control_mappings), the mapping has semantic invariants that
must hold for it to be internally coherent. These are pure structural checks over
mapping-results.json + the parsed framework + validated.json:

  S1. **Control references resolve.** Every control id named under a framework
      objective's `controls[]` ("Satisfied By") must exist in the mapping's own
      `controls[]` inventory. A dangling reference means the crosswalk points at a
      control that was never generated.
  S2. **Mapped objective ids exist.** Every `framework_mapping[].objective_id`
      must exist in the parsed framework (map-framework-parsed.json
      `framework_objectives[].id`). A mapping to a nonexistent objective is a
      fabricated objective.
  S3. **No action/condition-key drift.** No control may claim an IAM `action` or
      `condition_key` that is absent from validated.json's verified surface. A
      control gating an action the service does not expose is unenforceable.

Runs in the post-map gate. Deterministic; advisory counts surface in
mapping-review.json, and `--strict` makes it gate.

CLI:
    python3 validate_mapping_semantics.py --slug <slug> [--strict]
Exit codes: 0 ok (advisory default), 2 with --strict when any check fails.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _verified_surface(validated: dict | None) -> tuple[set[str], set[str]]:
    """Return (verified_actions, verified_condition_keys) as lowercased sets.

    Actions are taken from validated.json's API surface (operation→action) and
    the IAM permission-only actions; condition keys from
    capabilities.iam.condition_keys[]. Bare operation names are also admitted as
    actions so a control listing `prefix:Op` matches when only `Op` is verified.
    Returns empty sets when validated.json is unavailable (the check then no-ops,
    surfacing nothing rather than failing spuriously).
    """
    actions: set[str] = set()
    keys: set[str] = set()
    if not isinstance(validated, dict):
        return actions, keys

    def _add_action(a: str) -> None:
        a = a.strip().lower()
        actions.add(a)
        if ":" in a:
            actions.add(a.split(":", 1)[1])

    api = validated.get("api_surface") or {}
    for op in api.get("operations", []) or []:
        if isinstance(op, dict):
            name = op.get("iam_action") or op.get("action") or op.get("operation")
            if isinstance(name, str):
                _add_action(name)
    caps_iam = (validated.get("capabilities") or {}).get("iam") or {}
    for a in caps_iam.get("permission_only_actions", []) or []:
        if isinstance(a, str):
            _add_action(a)
    for ck in caps_iam.get("condition_keys", []) or []:
        if isinstance(ck, dict) and isinstance(ck.get("key"), str):
            keys.add(ck["key"].strip().lower())
        elif isinstance(ck, str):
            keys.add(ck.strip().lower())
    return actions, keys


def check(mapping: dict, framework: dict | None, validated: dict | None) -> list[str]:
    """Return semantic-violation error strings (S1/S2/S3)."""
    errors: list[str] = []

    control_ids = {
        c.get("id") for c in mapping.get("controls", []) or []
        if isinstance(c, dict) and c.get("id")
    }

    # S2 prep: parsed framework objective ids (when available). map-parse-framework
    # emits each objective under `objective_id` (the canonical key, matching the
    # `framework_mapping[].objective_id` we compare against); legacy/archived parsed
    # files used `id`. Accept either so a valid mapping is not flagged as fabricated.
    fw_obj_ids: set[str] | None = None
    if isinstance(framework, dict):
        fw_obj_ids = {
            (o.get("objective_id") or o.get("id"))
            for o in framework.get("framework_objectives", []) or []
            if isinstance(o, dict) and (o.get("objective_id") or o.get("id"))
        }

    for obj in mapping.get("framework_mapping", []) or []:
        if not isinstance(obj, dict):
            continue
        oid = obj.get("objective_id")
        # S2: mapped objective must exist in the parsed framework.
        if fw_obj_ids is not None and obj.get("status") == "MAPPED":
            if oid not in fw_obj_ids:
                errors.append(
                    f"SEMANTIC-S2 framework_mapping objective {oid!r} does not exist "
                    f"in the parsed framework — fabricated objective id."
                )
        # S1: every referenced control id must resolve to the inventory.
        for c in obj.get("controls", []) or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("control_id")
            if cid and cid not in control_ids:
                errors.append(
                    f"SEMANTIC-S1 objective {oid!r} is satisfied-by control {cid!r} "
                    f"which is absent from the mapping's controls[] inventory — "
                    f"dangling control reference."
                )

    # S3: no control may claim an action/condition key absent from validated.json.
    verified_actions, verified_keys = _verified_surface(validated)
    if verified_actions or verified_keys:
        for c in mapping.get("controls", []) or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id", "<unknown>")
            for a in c.get("actions", []) or []:
                if not isinstance(a, str):
                    continue
                al = a.strip().lower()
                bare = al.split(":", 1)[1] if ":" in al else al
                if al not in verified_actions and bare not in verified_actions:
                    errors.append(
                        f"SEMANTIC-S3 control {cid}: claims action {a!r} which is "
                        f"absent from validated.json's verified API surface — "
                        f"unenforceable / unverified action."
                    )
            if verified_keys:
                for k in c.get("condition_keys", []) or []:
                    if not isinstance(k, str):
                        continue
                    kl = k.strip().lower()
                    # AWS global condition keys (the `aws:` namespace —
                    # aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID, the
                    # tag keys, etc.) are available to every service and are NOT
                    # enumerated in a service's per-service condition_keys[] list,
                    # so they are not "drift". Only service-specific keys are
                    # checked against the verified surface.
                    if kl.startswith("aws:"):
                        continue
                    if kl not in verified_keys:
                        errors.append(
                            f"SEMANTIC-S3 control {cid}: claims condition key {k!r} "
                            f"which is absent from validated.json's verified condition "
                            f"keys — unverified key."
                        )
    return errors


def check_service(service_root: Path) -> list[str]:
    mapping = _load_json(service_root / "04-map" / "mapping-results.json")
    if not isinstance(mapping, dict):
        return []
    framework = _load_json(service_root / "04-map" / "map-framework-parsed.json")
    validated = _load_json(service_root / "03-validate" / "validated.json")
    return check(
        mapping,
        framework if isinstance(framework, dict) else None,
        validated if isinstance(validated, dict) else None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--strict", action="store_true", help="exit 2 on any violation")
    args = parser.parse_args()
    if not args.slug:
        parser.error("provide --slug")

    root = Path(os.getcwd()) / ".service-approval" / args.slug
    errors = check_service(root)
    if errors:
        print(f"SEMANTIC mapping checks: {len(errors)} finding(s):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 2 if args.strict else 0
    print("semantic mapping checks: no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
