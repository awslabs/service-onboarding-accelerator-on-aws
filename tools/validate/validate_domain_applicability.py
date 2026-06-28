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

  2. Inapplicable-objective over-claim — an objective that is N/A by default for a
     serverless / managed / infrastructure service marked MAPPED without an
     explicit `applicability_justification` + `reference_url` override. The set of
     N/A-by-default objectives is read per-objective from the CCMv4 domain-guidance
     KB (`data/domain-mapping-guidance/ccmv4.json`, each objective's `mappable`
     field) when present, so an objective the guidance marks `mappable` — e.g.
     BCR-04 business-continuity planning, satisfied by multi-AZ resilience — is no
     longer collateral damage of a blanket domain-N/A rule, while the backup/DR and
     datacenter/endpoint objectives stay N/A-by-default. When the guidance file is
     absent the validator falls back to the historical hardcoded domain set
     (DCS / UEM / BCR / IPY + the TVM-10 vulnerability-metric objective).

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

# Repo root = three levels up (tools/validate/<this>.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_GUIDANCE_PATH = _REPO_ROOT / "data" / "domain-mapping-guidance" / "ccmv4.json"

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


def load_na_by_default(guidance_path: str | Path | None = None) -> dict[str, str] | None:
    """Build objective_id -> na_reason from the CCMv4 domain-guidance KB.

    Returns the per-objective N/A-by-default map (every objective whose guidance
    `mappable` is "default_na"), or None when the guidance file is absent — in
    which case the caller falls back to the historical hardcoded domain set so
    behavior is unchanged on a checkout without the KB.
    """
    p = Path(guidance_path) if guidance_path else _GUIDANCE_PATH
    if not p.exists():
        return None
    guidance = _load_json(p)
    out: dict[str, str] = {}
    for domain in guidance.get("domains", []):
        for obj in domain.get("objectives", []):
            if obj.get("mappable") == "default_na":
                oid = obj.get("objective_id")
                if oid:
                    out[oid] = obj.get("na_reason", "N/A by default for this service class")
    return out


def _domain_prefix(objective_id: str) -> str:
    return objective_id.split("-", 1)[0] if objective_id else ""


def _na_by_default_reason(
    oid: str, prefix: str, na_objectives: dict[str, str] | None
) -> str | None:
    """Reason an objective is N/A by default for this screen, or None if it is not.

    This screen stays scoped to the domains it has always covered (DCS / UEM / BCR
    / IPY + the TVM-10 vulnerability-metric objective); the comprehensive,
    every-default_na check lives in validate_domain_mapping_accuracy.py. Within
    that scope, when the guidance KB is loaded (`na_objectives` is a dict),
    N/A-by-default is decided per-objective from the guidance `mappable` field —
    so a guidance `mappable`/`conditional` objective in a historically-N/A domain
    (e.g. BCR-04 business-continuity planning, satisfied by multi-AZ resilience) is
    no longer collateral damage of the blanket domain rule, while the backup/DR and
    datacenter/endpoint objectives stay N/A-by-default. When the guidance is absent
    (`na_objectives` is None), fall back to the hardcoded domain/objective reason.
    """
    in_scope = prefix in NA_BY_DEFAULT_DOMAINS or oid in NA_BY_DEFAULT_OBJECTIVES
    if not in_scope:
        return None
    if na_objectives is not None:
        # Guidance is the per-objective source of truth within the screen's scope.
        return na_objectives.get(oid)
    return NA_BY_DEFAULT_DOMAINS.get(prefix) or NA_BY_DEFAULT_OBJECTIVES.get(oid)


def _is_platform_config(mechanism: str) -> bool:
    m = (mechanism or "").lower()
    return any(tok in m for tok in PLATFORM_CONFIG_MECHANISMS)


def _is_tag_mechanism(mechanism: str) -> bool:
    return "tag" in (mechanism or "").lower()


def check_applicability(
    fw_mapped: dict,
    controls_by_id: dict[str, dict] | None,
    na_objectives: dict[str, str] | None = None,
) -> list[str]:
    """Validate domain applicability. Returns error strings (empty = clean).

    `controls_by_id` maps control_id -> control dict (from map-controls-generated.json)
    and supplies each control's `mechanism`. When None, the mechanism-dependent
    checks (app-code over-claim, DSP tag over-claim) are skipped; the
    N/A-by-default field check still runs.

    `na_objectives` is the per-objective N/A-by-default map from the CCMv4
    domain-guidance KB (objective_id -> na_reason). When provided, N/A-by-default
    is decided per-objective from the guidance (so a `mappable` objective such as
    BCR-04 no longer flags). When None, the historical hardcoded domain/objective
    sets are used instead, preserving prior behavior on a checkout without the KB.
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

        # Check 2 — N/A-by-default objective mapped without justification.
        # Per-objective from the guidance KB when loaded; hardcoded domain/object
        # sets as the fallback (see _na_by_default_reason).
        na_reason = _na_by_default_reason(oid, prefix, na_objectives)
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


def check_service(
    service_root: Path, na_objectives: dict[str, str] | None = None
) -> list[str]:
    """Validate a service's map-framework-mapped.json (no-op if absent).

    Loads the CCMv4 domain-guidance N/A-by-default map by default so BCR-04 and
    other guidance-`mappable` objectives are no longer blanket-flagged; pass
    `na_objectives` explicitly to override (tests).
    """
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
    if na_objectives is None:
        na_objectives = load_na_by_default()
    return check_applicability(fw_mapped, controls_by_id, na_objectives)


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
