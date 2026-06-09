#!/usr/bin/env python3
"""Canopy report loader.

Parses a Canopy service-security report (e.g., lambda-canopy.json) into
normalized records consumed by:
  - skills/research-mitigations         (mitigations[])
  - skills/research-attack-surface      (threats[] + MITRE ATT&CK mappings)
  - skills/map-generate-controls        (implementations[] -> controls[])

Canopy graph shape:
  metadata:        service info, identifiers, related namespaces
  entities[]:      resource types within the service
  operations[]:    API surface
  threats[]:       threat statements with inline MITRE ATT&CK technique IDs
                   in mappings[type=FRAMEWORK, frameworkName=MITRE ATT&CK]
  mitigations[]:   mitigation statements with verification API parameters,
                   linked to threats and implementations via mappings[]
  implementations: concrete controls (DETECTIVE Config rules, PROACTIVE
                   CFN Hooks), linked to mitigations via mappings[]

All cross-references use UUIDs in mappings[type=...] arrays.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def parse_canopy(path: str | Path) -> dict[str, Any]:
    with open(path) as f:
        data = json.load(f)
    _validate_shape(data, path)
    return data


def is_canopy_file(path: str | Path) -> bool:
    p = Path(path)
    if not p.is_file() or p.suffix.lower() != ".json":
        return False
    if "canopy" in p.name.lower():
        return True
    try:
        with open(p) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return False
    required = {"metadata", "threats", "mitigations", "implementations"}
    return required.issubset(data.keys() if isinstance(data, dict) else set())


def get_service_name(canopy: dict) -> str:
    return canopy.get("metadata", {}).get("name", "unknown")


def get_mitigations(canopy: dict) -> list[dict]:
    """Normalize Canopy mitigations[] into the existing_mitigations[] shape.

    Output shape matches schemas/research-mitigations.schema.json mitigation:
      { id (M-<normalized-alias>), mitigation_goal, statement, resource_type,
        source: "canopy", source_mitigation: <canopy-alias>,
        verification_apis[], threat_ids[] }

    `id` must match `^M-.+`; we derive it deterministically from the Canopy
    alias (e.g., "Mitigation.LAMBDA.CapacityProvider.1" -> "M-LAMBDA-CapacityProvider-1")
    so downstream control.mitigation_ids[] cross-references are stable.
    """
    entity_index = _index_by_id(canopy.get("entities", []))
    threat_index = _index_by_id(canopy.get("threats", []))
    out: list[dict] = []
    for mit in canopy.get("mitigations", []):
        entity_ids = _mapping_ids(mit, "ENTITY")
        threat_ids = _mapping_ids(mit, "THREAT")
        resource_type = ""
        if entity_ids:
            ent = entity_index.get(entity_ids[0])
            if ent:
                resource_type = ent.get("name", "")
        statement = mit.get("statement", "")
        out.append(
            {
                "id": _canopy_mitigation_id(mit),
                "mitigation_goal": _statement_to_goal(statement),
                "statement": statement,
                "resource_type": resource_type,
                "source": "canopy",
                "source_mitigation": mit.get("alias", mit["id"]),
                "verification_apis": [
                    {"service": p["service"], "operation": p["operation"]}
                    for p in mit.get("verificationRequestParameters", [])
                ],
                "threat_ids": [
                    threat_index[tid].get("alias", tid)
                    for tid in threat_ids
                    if tid in threat_index
                ],
            }
        )
    return out


def _canopy_mitigation_id(mit: dict) -> str:
    """Produce a stable M-* id from a Canopy mitigation alias.

    'Mitigation.LAMBDA.CapacityProvider.1' -> 'M-LAMBDA-CapacityProvider-1'
    Falls back to 'M-<uuid>' if no alias is present.
    """
    alias = mit.get("alias", "")
    if not alias:
        return f"M-{mit['id']}"
    parts = alias.split(".")
    if parts and parts[0].lower() == "mitigation":
        parts = parts[1:]
    return "M-" + "-".join(parts) if parts else f"M-{mit['id']}"


def _statement_to_goal(statement: str) -> str:
    """Derive a short mitigation_goal from the full statement.

    Canopy doesn't ship a separate goal field; the statement is the goal.
    Returned verbatim (downstream consumers expect prose, not a slug).
    """
    return statement.strip() or "(unspecified)"


def get_threats_with_mitre(canopy: dict) -> list[dict]:
    """Extract threats with their MITRE ATT&CK technique mappings.

    Output shape:
      { id, alias, source, prerequisites, threatAction,
        mitre_techniques[]: [{ technique_id, source: "canopy" }],
        entity_ids[], mitigation_ids[] }
    """
    out: list[dict] = []
    for th in canopy.get("threats", []):
        techniques = [
            {"technique_id": m["id"], "source": "canopy"}
            for m in th.get("mappings", [])
            if m.get("type") == "FRAMEWORK"
            and m.get("frameworkName") == "MITRE ATT&CK"
        ]
        out.append(
            {
                "id": th["id"],
                "alias": th.get("alias", ""),
                "source": th.get("source", ""),
                "prerequisites": th.get("prerequisites", ""),
                "threatAction": th.get("threatAction", ""),
                "mitre_techniques": techniques,
                "entity_ids": _mapping_ids(th, "ENTITY"),
                "mitigation_ids": _mapping_ids(th, "MITIGATION"),
            }
        )
    return out


def build_threat_mitre_index(canopy: dict) -> dict[str, list[str]]:
    """Map mitigation key -> [MITRE technique IDs] via Canopy's threat graph.

    Walks: mitigation -> linked threats -> their MITRE ATT&CK techniques.
    Used by map-generate-controls to populate controls[].attack_techniques[].

    The returned dict is indexed by THREE keys for every mitigation:
      - normalized M-* id (canonical)
      - Canopy alias (e.g., 'Mitigation.LAMBDA.CapacityProvider.1')
      - raw Canopy UUID
    so callers can look up by whichever id they hold.
    """
    threat_index = _index_by_id(canopy.get("threats", []))
    out: dict[str, list[str]] = {}
    for mit in canopy.get("mitigations", []):
        techniques: set[str] = set()
        for tid in _mapping_ids(mit, "THREAT"):
            threat = threat_index.get(tid)
            if not threat:
                continue
            for m in threat.get("mappings", []):
                if (
                    m.get("type") == "FRAMEWORK"
                    and m.get("frameworkName") == "MITRE ATT&CK"
                ):
                    techniques.add(m["id"])
        sorted_techniques = sorted(techniques)
        for key in (_canopy_mitigation_id(mit), mit.get("alias", ""), mit["id"]):
            if key:
                out[key] = sorted_techniques
    return out


def get_implementations_as_controls(canopy: dict) -> list[dict]:
    """Convert Canopy implementations[] into pre-built controls[].

    Canopy ships only DETECTIVE (AWS::Config::ConfigRule) and PROACTIVE
    (AWS::CloudFormation::Type::HOOK) implementations. Mapping:

      DETECTIVE  + AWS::Config::ConfigRule           -> CTRL-RES-DET-NNN
      PROACTIVE  + AWS::CloudFormation::Type::HOOK   -> CTRL-RES-PRO-NNN

    Output shape matches schemas/map-controls-generated.schema.json controls[].
    Caller is responsible for populating attack_techniques[] via
    build_threat_mitre_index().
    """
    mit_index = _index_by_id(canopy.get("mitigations", []))
    entity_index = _index_by_id(canopy.get("entities", []))
    threat_mitre = build_threat_mitre_index(canopy)

    counters = {"DET": 0, "PRO": 0}
    out: list[dict] = []
    for impl in canopy.get("implementations", []):
        category = _impl_to_category(impl)
        if category is None:
            continue
        counters[category] += 1
        ctrl_id = f"CTRL-RES-{category}-{counters[category]:03d}"

        mit_ids = _mapping_ids(impl, "MITIGATION")
        # Use normalized M-* ids so control.mitigation_ids[] matches the ids
        # produced by get_mitigations() for cross-reference downstream.
        normalized_mit_ids = [
            _canopy_mitigation_id(mit_index[mid])
            for mid in mit_ids
            if mid in mit_index
        ]
        statements = [
            mit_index[mid].get("statement", "")
            for mid in mit_ids
            if mid in mit_index
        ]

        entity_ids = _mapping_ids(impl, "ENTITY")
        entity_resource_types = [
            entity_index[eid].get("name", "")
            for eid in entity_ids
            if eid in entity_index
        ]

        # Inherit MITRE techniques via this control's linked mitigations
        techniques: set[str] = set()
        for mid in mit_ids:
            for tid in threat_mitre.get(mid, []):
                techniques.add(tid)

        mechanism, actions, hook_resource_types = _impl_mechanism_and_actions(impl)
        resource_types = sorted(set(entity_resource_types) | set(hook_resource_types))

        out.append(
            {
                "id": ctrl_id,
                "name": impl.get("alias", ctrl_id),
                "scope": "RES",
                "category": category,
                "mechanism": mechanism,
                "description": _impl_description(impl, statements),
                "actions": actions,
                "condition_keys": [],
                "parameters_controlled": _impl_parameters(impl),
                "resource_types": resource_types,
                "mitigation_ids": normalized_mit_ids,
                "framework_keywords": _impl_keywords(impl, statements),
                "security_rationale": _impl_rationale(impl, statements),
                "posture": _category_to_posture(category),
                "provenance": "canopy",
                "attack_techniques": [
                    {"technique_id": t, "source": "canopy"}
                    for t in sorted(techniques)
                ],
                "_metadata": {
                    "canopy_implementation_id": impl["id"],
                    "canopy_implementation_alias": impl.get("alias", ""),
                },
            }
        )
    return out


def detect_posture_gaps(canopy: dict) -> list[dict]:
    """Identify posture layers Canopy doesn't cover (PRV preventive, COR corrective).

    Canopy ships PRO+DET only. For every mitigation, emit posture_gap entries
    flagging the missing PRV (preventive request-time) and COR (corrective)
    layers so map-assemble surfaces them in coverage_gaps.
    """
    gaps: list[dict] = []
    for mit in canopy.get("mitigations", []):
        mit_id = _canopy_mitigation_id(mit)
        for posture in ("PRV", "COR"):
            gaps.append(
                {
                    "mitigation_id": mit_id,
                    "posture": posture,
                    "reason": (
                        f"Canopy provides {_canopy_layers_str()} only; "
                        f"{_posture_label(posture)} layer requires AWS-doc-derived "
                        "controls (SCP/IAM/key policy for PRV; runbooks/Lambda "
                        "for COR) which are not generated when Canopy supersedes."
                    ),
                }
            )
    return gaps


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
_REQUIRED_TOP_LEVEL = {
    "metadata",
    "entities",
    "operations",
    "threats",
    "mitigations",
    "implementations",
}


def _validate_shape(data: dict, path: str | Path) -> None:
    if not isinstance(data, dict):
        raise ValueError(f"Canopy file {path} is not a JSON object")
    missing = _REQUIRED_TOP_LEVEL - data.keys()
    if missing:
        raise ValueError(
            f"Canopy file {path} missing required top-level keys: {sorted(missing)}"
        )


def _index_by_id(items: list[dict]) -> dict[str, dict]:
    return {item["id"]: item for item in items if "id" in item}


def _mapping_ids(obj: dict, mapping_type: str) -> list[str]:
    return [
        m["id"]
        for m in obj.get("mappings", [])
        if m.get("type") == mapping_type and "id" in m
    ]


def _impl_to_category(impl: dict) -> str | None:
    behavior = impl.get("behavior", "").upper()
    if behavior == "DETECTIVE":
        return "DET"
    if behavior == "PROACTIVE":
        return "PRO"
    return None


def _category_to_posture(category: str) -> str:
    return {
        "PRO": "preventative-proactive",
        "PRV": "preventative-request",
        "DET": "reactive-detective",
        "COR": "reactive-corrective",
    }[category]


def _impl_mechanism_and_actions(impl: dict) -> tuple[str, list[str], list[str]]:
    """Return (mechanism, actions, resource_types).

    actions: IAM action strings matching `^[a-z0-9-]+:[A-Za-z0-9*]+$`
             (Config rules ship these in governed_api_operations[]).
    resource_types: CFN resource type strings (e.g. AWS::Lambda::CapacityProvider)
                    pulled from CFN Hooks' governed_resource_properties[].

    Splitting these prevents schema-pattern violations: actions[] is enforced
    as iam-action format by map-controls-generated.schema.json, while
    resource_types[] has no pattern constraint.
    """
    impl_type = impl.get("implementationType", "")
    actions: list[str] = []
    res_types: list[str] = []
    guide = impl.get("implementationGuide", {})
    config_rule = guide.get("config_rule")
    cfn_hook = (
        guide.get("cloudformation_hook") or guide.get("cfn_hook") or guide.get("hook")
    )
    if config_rule:
        for op in config_rule.get("governed_api_operations", []):
            actions.append(f"{op['service']}:{op['operation']}")
        return "AWS Config rule", sorted(set(actions)), res_types
    if cfn_hook:
        for op in cfn_hook.get("governed_api_operations", []):
            actions.append(f"{op['service']}:{op['operation']}")
        for prop in cfn_hook.get("governed_resource_properties", []):
            res_types.append(prop["type"])
        return "CloudFormation Hook", sorted(set(actions)), sorted(set(res_types))
    return impl_type or "AWS-managed control", actions, res_types


def _impl_description(impl: dict, statements: list[str]) -> str:
    if statements:
        return statements[0]
    return impl.get("alias", "")


def _impl_rationale(impl: dict, statements: list[str]) -> str:
    if not statements:
        return f"Canopy implementation {impl.get('alias', impl['id'])}"
    if len(statements) == 1:
        return statements[0]
    return " ".join(statements)


def _impl_parameters(impl: dict) -> list[str]:
    params: set[str] = set()
    guide = impl.get("implementationGuide", {})
    for section in ("config_rule", "cloudformation_hook", "cfn_hook", "hook"):
        block = guide.get(section)
        if not block:
            continue
        for op in block.get("governed_api_operations", []):
            for p in op.get("request_parameters", []):
                if "path" in p:
                    params.add(p["path"])
            for p in op.get("response_parameters", []):
                if "path" in p:
                    params.add(p["path"])
        for prop in block.get("governed_resource_properties", []):
            for p in prop.get("properties", []):
                if "path" in p:
                    params.add(p["path"])
    return sorted(params)


def _impl_keywords(impl: dict, statements: list[str]) -> list[str]:
    text = " ".join([impl.get("alias", "")] + statements).lower()
    keywords = []
    for kw in (
        "encryption",
        "kms",
        "iam",
        "policy",
        "principal",
        "vpc",
        "logging",
        "audit",
        "access",
        "identity",
        "configuration",
        "rotation",
    ):
        if kw in text:
            keywords.append(kw)
    return keywords[:10]


def _canopy_layers_str() -> str:
    return "DETECTIVE (Config rules) + PROACTIVE (CFN Hooks)"


def _posture_label(category: str) -> str:
    return {
        "PRV": "preventative-request (PRV)",
        "COR": "reactive-corrective (COR)",
    }.get(category, category)


# ---------------------------------------------------------------------------
# CLI for ad-hoc inspection
# ---------------------------------------------------------------------------
def _summary(canopy: dict) -> dict:
    return {
        "service": get_service_name(canopy),
        "entities": len(canopy.get("entities", [])),
        "operations": len(canopy.get("operations", [])),
        "threats": len(canopy.get("threats", [])),
        "mitigations": len(canopy.get("mitigations", [])),
        "implementations": len(canopy.get("implementations", [])),
        "implementations_by_behavior": dict(
            _count_by(canopy.get("implementations", []), "behavior")
        ),
    }


def _count_by(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for item in items:
        counts[item.get(key, "?")] += 1
    return counts


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 scripts/canopy_loader.py <canopy.json>", file=sys.stderr)
        sys.exit(2)

    data = parse_canopy(sys.argv[1])
    print(json.dumps(_summary(data), indent=2))
    print(f"\nMitigations (first 2):")
    print(json.dumps(get_mitigations(data)[:2], indent=2))
    print(f"\nThreats with MITRE (first 2):")
    print(json.dumps(get_threats_with_mitre(data)[:2], indent=2))
    print(f"\nControls (first 2):")
    print(json.dumps(get_implementations_as_controls(data)[:2], indent=2))
