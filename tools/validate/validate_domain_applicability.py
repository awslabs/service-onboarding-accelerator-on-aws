#!/usr/bin/env python3
"""
Validate framework-domain applicability of the control mapping.

The accelerator is a control-mapping + reference tool, not an AppSec or
datacenter-security product. Two recurring over-claims this validator catches:

  1. Application-code over-claim — a platform/infrastructure config mechanism
     (CloudFormation Guard, AWS Config rule, SCP, RCP, tag policy, OPA, IAM
     policy) mapped to an application-code security objective (CCMv4 AIS-02
     secure development, AIS-04 secure deployment/testing, AIS-05 application
     security testing). Those mechanisms inspect IAM requests, resource
     configuration, or IaC template properties — never the workload's source
     code, dependencies, or runtime behavior, so they cannot satisfy the
     objective.

  2. Inapplicable-domain over-claim — an objective in a domain that is N/A by
     default for a serverless / managed / infrastructure service (CCMv4 DCS
     datacenter, UEM endpoint management, BCR business-continuity, IPY
     portability, and the TVM vulnerability-metric objective TVM-10) marked
     MAPPED without an explicit `applicability_justification` + `reference_url`
     override.

A third, optional check flags a resource-tag mechanism mapped to a
data-sensitivity-classification objective (CCMv4 DSP-03 / DSP-04): tagging a
resource as security-owned/platform-owned classifies the resource, not the
sensitivity of the data inside it.

Domain/objective lists below are CCMv4-specific (the framework whose objectives
this sub-pipeline maps). They are matched by objective-id prefix, so the
validator simply finds nothing — and warns — for a framework that does not use
these prefixes; it never hard-fails on an unrecognised framework.

Advisory by default (warn, exit 0); --strict exits 2 on any finding so a run can
hard-gate the map phase once the upstream skill reliably produces justifications.

CLI:
    python3 validate_domain_applicability.py --slug <slug> [--strict]
    python3 validate_domain_applicability.py <map-framework-mapped.json> \
        [--controls <map-controls-generated.json>] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# --- CCMv4 applicability policy (matched by objective-id prefix) -------------

# Application-code security objectives a platform/infra-config mechanism can
# never satisfy. AIS objectives about interface/API authentication that a
# request-time control genuinely governs are intentionally NOT in this set.
APP_CODE_OBJECTIVES = {"AIS-02", "AIS-04", "AIS-05"}

# Mechanisms that are platform/infrastructure config — they evaluate IAM
# requests, resource state, or IaC templates, not application code. Matched as
# lowercased substrings against the control's `mechanism` string.
PLATFORM_CONFIG_MECHANISMS = (
    "cloudformation guard",
    "config rule",
    "scp",
    "rcp",
    "tag policy",
    "opa",
    "iam",
)

# Domains that are N/A by default for serverless / managed / infrastructure
# services. A MAPPED objective in one of these requires both
# applicability_justification and reference_url. Keyed by objective-id prefix
# (the domain token before the first '-').
NA_BY_DEFAULT_DOMAINS = {
    "DCS": "datacenter/physical security is AWS-managed under shared responsibility",
    "UEM": "endpoint/device management does not apply to a serverless/managed service",
    "BCR": "business-continuity/DR-exercise processes; map only with a genuine backup/DR API",
    "IPY": "cross-cloud data-portability does not apply without a portability capability",
}

# Specific vulnerability-metric objectives (TVM-10-class) that a managed/serverless
# service does not itself produce. TVM-05 ("works-with-Inspector") is intentionally
# left mappable and is NOT in this set.
NA_BY_DEFAULT_OBJECTIVES = {
    "TVM-10": "a managed/serverless service does not itself produce vulnerability metrics",
}

# Data-sensitivity classification objectives. A resource-ownership tag control
# classifies the resource, not the sensitivity of the data inside it.
DATA_CLASSIFICATION_OBJECTIVES = {"DSP-03", "DSP-04"}
TAG_MECHANISM_TOKENS = ("tag policy", "tag",)


def _load_json(path: str | Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def _domain_prefix(objective_id: str) -> str:
    return objective_id.split("-", 1)[0] if objective_id else ""


def _is_platform_config(mechanism: str) -> bool:
    m = (mechanism or "").lower()
    return any(tok in m for tok in PLATFORM_CONFIG_MECHANISMS)


def _is_tag_mechanism(mechanism: str) -> bool:
    return "tag" in (mechanism or "").lower()


def check_applicability(
    fw_mapped: dict, controls_by_id: dict[str, dict] | None
) -> list[str]:
    """Validate domain applicability. Returns error strings (empty = clean).

    `controls_by_id` maps control_id -> control dict (from map-controls-generated.json)
    and supplies each control's `mechanism`. When None, the mechanism-dependent
    checks (app-code over-claim, DSP tag over-claim) are skipped; the
    N/A-by-default field check still runs.
    """
    errors: list[str] = []
    mappings = fw_mapped.get("framework_mapping", [])

    # Warn (not fail) if no objective uses a CCMv4 prefix this policy knows — the
    # validator is a no-op for non-CCMv4 frameworks rather than a hard failure.
    known_prefixes = (
        {p for p in NA_BY_DEFAULT_DOMAINS}
        | {"AIS", "TVM", "DSP"}
    )
    seen_prefixes = {_domain_prefix(m.get("objective_id", "")) for m in mappings}
    if mappings and not (known_prefixes & seen_prefixes):
        print(
            "domain-applicability: no CCMv4 domain prefixes (AIS/DCS/UEM/BCR/IPY/"
            "TVM/DSP) found in this mapping — applicability policy is CCMv4-specific, "
            "skipping (no findings possible for this framework).",
            file=sys.stderr,
        )
        return errors

    for entry in mappings:
        oid = entry.get("objective_id", "")
        status = entry.get("status")
        if status != "MAPPED":
            continue
        prefix = _domain_prefix(oid)
        ctrls = entry.get("controls", [])

        # Check 1 — application-code over-claim.
        if oid in APP_CODE_OBJECTIVES and controls_by_id is not None:
            for cm in ctrls:
                cid = cm.get("control_id")
                ctrl = controls_by_id.get(cid, {})
                mech = ctrl.get("mechanism", "")
                if _is_platform_config(mech):
                    errors.append(
                        f"domain-applicability: {oid} is an application-code security "
                        f"objective but is mapped to {cid} ({mech}) — a platform/infra "
                        f"config mechanism cannot inspect function/application code. "
                        f"Mark {oid} N/A or map only a control that directly tests "
                        f"application code."
                    )

        # Check 2 — N/A-by-default domain mapped without justification.
        na_reason = NA_BY_DEFAULT_DOMAINS.get(prefix) or NA_BY_DEFAULT_OBJECTIVES.get(oid)
        if na_reason:
            justification = (entry.get("applicability_justification") or "").strip()
            ref = (entry.get("reference_url") or "").strip()
            if not (justification and ref):
                errors.append(
                    f"domain-applicability: {oid} is N/A-by-default for a "
                    f"serverless/managed service ({na_reason}) but is MAPPED without "
                    f"both applicability_justification and reference_url. Mark it N/A "
                    f"or add the override fields with a public AWS doc URL."
                )

        # Check 3 (optional) — resource-tag mechanism on a data-classification objective.
        if oid in DATA_CLASSIFICATION_OBJECTIVES and controls_by_id is not None:
            for cm in ctrls:
                cid = cm.get("control_id")
                ctrl = controls_by_id.get(cid, {})
                mech = ctrl.get("mechanism", "")
                if _is_tag_mechanism(mech):
                    errors.append(
                        f"domain-applicability: {oid} is a data-sensitivity "
                        f"classification objective but is mapped to {cid} ({mech}) — a "
                        f"resource-tag mechanism classifies the resource, not the "
                        f"sensitivity of the data. Mark {oid} N/A unless the service "
                        f"provides a data-sensitivity classification capability."
                    )

    return errors


def check_service(service_root: Path) -> list[str]:
    """Validate a service's map-framework-mapped.json (no-op if absent)."""
    map_dir = service_root / "04-map"
    mapped_path = map_dir / "map-framework-mapped.json"
    if not mapped_path.exists():
        return []
    fw_mapped = _load_json(mapped_path)
    controls_by_id: dict[str, dict] | None = None
    cg_path = map_dir / "map-controls-generated.json"
    if cg_path.exists():
        cg = _load_json(cg_path)
        controls_by_id = {c["id"]: c for c in cg.get("controls", []) if c.get("id")}
    return check_applicability(fw_mapped, controls_by_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mapped", nargs="?", help="path to map-framework-mapped.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--controls", help="path to map-controls-generated.json (mechanism lookup)")
    parser.add_argument("--strict", action="store_true", help="exit 2 on any finding")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.mapped:
        fw_mapped = _load_json(args.mapped)
        controls_by_id = None
        if args.controls:
            cg = _load_json(args.controls)
            controls_by_id = {c["id"]: c for c in cg.get("controls", []) if c.get("id")}
        errors = check_applicability(fw_mapped, controls_by_id)
    else:
        parser.error("provide a map-framework-mapped.json path OR --slug")

    if errors:
        print(f"DOMAIN APPLICABILITY ({len(errors)} issue(s)):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        if args.strict:
            sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
