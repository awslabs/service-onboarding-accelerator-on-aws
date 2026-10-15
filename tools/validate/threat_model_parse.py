"""Reference parser for the AWS Threat Model threat-model JSON shape.

AWS Threat Model exports use a top-level `mitigations[]` and `threats[]`, with each
mitigation carrying `mappings[]` whose entries point back at `entities[]`,
`mitigation goals`, threats, and implementations. The earlier
research-mitigations parser only iterated `entities[].mitigations[]`, which
silently dropped every AWS Threat Model mitigation.

This module is the reference implementation used by tests; the
research-mitigations and research-attack-surface skills follow the same
detection rules (see those SKILL.md files).
"""

from __future__ import annotations

import json
from typing import Any


def is_threat_model_shape(data: dict[str, Any]) -> bool:
    """Return True when the file looks like an AWS Threat Model export.

    Detector: top-level `mitigations[]` is present AND `entities[]` entries
    do NOT carry a `mitigations` sub-key. Either condition alone is
    insufficient: a file with both top-level and entity-nested mitigations
    is the legacy nested shape (which already worked) — we only re-route
    when the entity branch yields nothing.
    """
    top_level_mits = data.get("mitigations") or []
    entities = data.get("entities") or []
    if not isinstance(top_level_mits, list) or not isinstance(entities, list):
        return False
    if not top_level_mits:
        return False
    return not any("mitigations" in e for e in entities if isinstance(e, dict))


def is_threat_model_threats_shape(data: dict[str, Any]) -> bool:
    """Return True when the file carries a top-level AWS Threat Model `threats[]`.

    Distinct from `is_threat_model_shape` — research-attack-surface only needs the
    threat list, not the mitigation list, so the detector is independent.
    """
    threats = data.get("threats")
    mitigations = data.get("mitigations")
    return (
        isinstance(threats, list)
        and bool(threats)
        and isinstance(mitigations, list)
        and bool(mitigations)
    )


def _entity_resource_types(entity: dict[str, Any]) -> list[str]:
    """Read published CFN identifiers, preserving multiple types and legacy input."""
    identifiers = entity.get("identifiers")
    if isinstance(identifiers, dict):
        types = identifiers.get("cfnResourceTypes")
        if isinstance(types, list):
            found = _dedup(t for t in types if isinstance(t, str) and t.startswith("AWS::"))
            if found:
                return found
    legacy = entity.get("resource_type") or entity.get("entityType")
    # Published entityType can be a semantic label ("RESOURCE"). Never invent
    # a CFN type from that label.
    return [legacy] if isinstance(legacy, str) and legacy.startswith("AWS::") else []


# ---------------------------------------------------------------------------
# Implementation ingestion
# ---------------------------------------------------------------------------
# Newer AWS Threat Model exports (e.g. the Aurora DSQL export) carry a top-level
# `implementations[]` array alongside `mitigations[]`. Each implementation is a
# typed control example: a preventive policy (SCP / RCP / resource-based policy /
# declarative policy), a proactive CloudFormation Hook, or a detective AWS Config
# rule / CloudTrail event. It carries the exact governed actions, condition keys,
# API operations, or resource properties AND a REFERENCE link to the public AWS
# documentation the example is grounded in. This lets the pipeline cite the
# AWS Threat Model implementation directly (its `alias`) and link straight to that public
# doc — the first-priority citation source for every control family.

# Map AWS Threat Model `implementationType` → the pipeline's mechanism vocabulary. The
# mechanism strings mirror the values map-generate-controls / the reference index
# use so downstream matching lines up.
_IMPLEMENTATION_TYPE_TO_MECHANISM = {
    "AWS::Organizations::Policy::SERVICE_CONTROL_POLICY": "SCP",
    "AWS::Organizations::Policy::RESOURCE_CONTROL_POLICY": "RCP",
    "AWS::Organizations::Policy::DECLARATIVE_POLICY": "Declarative Policy",
    "AWS::CloudFormation::Type::HOOK": "CFN Hook",
    "AWS::Config::ConfigRule": "Config Rule",
    "AWS::CloudTrail::Trail::MANAGEMENT_EVENT": "CloudTrail",
    "AWS::CloudTrail::Trail::DATA_EVENT": "CloudTrail",
}


def _mechanism_for_implementation_type(implementation_type: str) -> str:
    """Return the mechanism string for an AWS Threat Model `implementationType`.

    Resource-based policies use the wildcard form `AWS::*::*::RESOURCE_POLICY`
    (the service/resource segments vary), so match on the `RESOURCE_POLICY`
    suffix rather than an exact key. An unknown type returns the raw string so
    a caller can still surface it.
    """
    if implementation_type in _IMPLEMENTATION_TYPE_TO_MECHANISM:
        return _IMPLEMENTATION_TYPE_TO_MECHANISM[implementation_type]
    if implementation_type.endswith("::RESOURCE_POLICY"):
        return "Resource Policy"
    return implementation_type or ""


def _collect_reference_links(context_entries: list[Any]) -> list[dict[str, str]]:
    """Flatten every `links[]` carried by an implementation/mitigation context.

    AWS Threat Model attaches public AWS documentation URLs to REFERENCE (and, for some
    detective implementations, DATA_PERIMETER) context entries. Both are public
    doc anchors we want to surface as the citation URL, so collect links from any
    context entry that carries them, de-duplicated by href.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for ctx in context_entries or []:
        if not isinstance(ctx, dict):
            continue
        for link in ctx.get("links") or []:
            if not isinstance(link, dict):
                continue
            href = str(link.get("href", "")).strip()
            if not href or href in seen:
                continue
            seen.add(href)
            out.append({"href": href, "title": str(link.get("title", "")).strip()})
    return out


def _collect_scoping_context(context_entries: list[Any]) -> list[str]:
    """Return the SCOPING context strings (the 'how this control works' prose)."""
    out: list[str] = []
    for ctx in context_entries or []:
        if not isinstance(ctx, dict) or ctx.get("type") != "SCOPING":
            continue
        text = str(ctx.get("context", "")).strip()
        if text:
            out.append(text)
    return out


def _parse_implementation_guide(guide: dict[str, Any]) -> dict[str, Any]:
    """Normalize a typed `implementationGuide` into a flat, uniform shape.

    Populates only the keys relevant to the guide's type; every implementation
    also gets flat `actions` / `resources` / `condition_keys` unions (empty when
    the guide is not an authorization policy) so matching/scoring code has one
    shape to read regardless of behavior.
    """
    parsed: dict[str, Any] = {
        "authorization_policy": None,
        "actions": [],
        "resources": [],
        "condition_keys": [],
        "governed_resource_type": "",
        "config_rule_type": "",
        "governed_api_operations": [],
        "monitored_operations": [],
        "governed_resource_properties": [],
        "governed_attributes": [],
        "policy_type": "",
        "guidance": "",
    }
    if not isinstance(guide, dict):
        return parsed

    guidance = guide.get("guidance")
    if isinstance(guidance, dict):
        parsed["guidance"] = str(guidance.get("description", "") or "")

    auth = guide.get("authorization_policy")
    if isinstance(auth, dict):
        perms = [p for p in auth.get("governed_iam_permissions", []) if isinstance(p, dict)]
        parsed["authorization_policy"] = perms
        parsed["governed_resource_type"] = str(auth.get("governed_resource_type", "") or "")
        actions, resources, condition_keys = [], [], []
        for perm in perms:
            actions.extend(a for a in perm.get("actions", []) if isinstance(a, str))
            resources.extend(r for r in perm.get("resources", []) if isinstance(r, str))
            condition_keys.extend(
                k for k in perm.get("condition_keys", []) if isinstance(k, str)
            )
        parsed["actions"] = _dedup(actions)
        parsed["resources"] = _dedup(resources)
        parsed["condition_keys"] = _dedup(condition_keys)

    config_rule = guide.get("config_rule")
    if isinstance(config_rule, dict):
        parsed["config_rule_type"] = str(config_rule.get("rule_type", "") or "")
        parsed["governed_api_operations"] = [
            op for op in config_rule.get("governed_api_operations", []) if isinstance(op, dict)
        ]

    cloudtrail = guide.get("cloudtrail_event")
    if isinstance(cloudtrail, dict):
        parsed["monitored_operations"] = [
            op for op in cloudtrail.get("monitored_operations", []) if isinstance(op, dict)
        ]

    hook = guide.get("cloudformation_hook")
    if isinstance(hook, dict):
        parsed["governed_resource_properties"] = [
            p for p in hook.get("governed_resource_properties", []) if isinstance(p, dict)
        ]

    declarative = guide.get("declarative_policy")
    if isinstance(declarative, dict):
        parsed["policy_type"] = str(declarative.get("policy_type", "") or "")
        parsed["governed_attributes"] = [
            a for a in declarative.get("governed_attributes", []) if isinstance(a, dict)
        ]

    return parsed


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving de-duplication for a list of strings."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def parse_threat_model_implementations(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize an AWS Threat Model doc's top-level `implementations[]` into control rows.

    Each output entry carries:
      - id / alias: the source `id` (UUID) and `alias`
      - behavior: PREVENTIVE | PROACTIVE | DETECTIVE | DIRECTIVE
      - implementation_type: the raw `implementationType`
      - mechanism: mapped to the pipeline vocab (SCP / RCP / Resource Policy /
        Declarative Policy / CFN Hook / Config Rule / CloudTrail)
      - the parsed guide fields (actions/resources/condition_keys +
        authorization_policy, governed_api_operations, monitored_operations,
        governed_resource_properties, governed_attributes/policy_type)
      - scoping_context[]: the SCOPING prose
      - reference_links[{href,title}]: public AWS doc URLs cited by the
        implementation's REFERENCE/DATA_PERIMETER context
      - mitigation_ids[] / entity_ids[]: from mappings[]

    Returns [] when the doc carries no `implementations[]` array (older AWS Threat Model
    exports and non-AWS Threat Model files).
    """
    implementations = data.get("implementations")
    if not isinstance(implementations, list):
        return []

    out: list[dict[str, Any]] = []
    for impl in implementations:
        if not isinstance(impl, dict):
            continue
        implementation_type = str(impl.get("implementationType", "") or "")
        context = impl.get("implementationContext") or []
        mappings = impl.get("mappings") or []
        row: dict[str, Any] = {
            "id": impl.get("id", ""),
            "alias": impl.get("alias", ""),
            "behavior": str(impl.get("behavior", "") or "").upper(),
            "implementation_type": implementation_type,
            "mechanism": _mechanism_for_implementation_type(implementation_type),
            "scoping_context": _collect_scoping_context(context),
            "reference_links": _collect_reference_links(context),
            "mitigation_ids": [
                m.get("id")
                for m in mappings
                if isinstance(m, dict) and m.get("type") == "MITIGATION" and m.get("id")
            ],
            "entity_ids": [
                m.get("id")
                for m in mappings
                if isinstance(m, dict) and m.get("type") == "ENTITY" and m.get("id")
            ],
        }
        row.update(_parse_implementation_guide(impl.get("implementationGuide") or {}))
        out.append(row)

    return out


def parse_threat_model_mitigation_index(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return `{mitigation_id: {alias, statement, scoping_context, reference_links}}`.

    A control that maps to an AWS Threat Model mitigation can pull that mitigation's cited
    public doc link (from its `mitigationContext[type==REFERENCE].links`) even
    when the matching implementation carries no link of its own. Keyed by the
    mitigation's source `id` (UUID) so an implementation's `mitigation_ids[]`
    resolve directly. Returns {} for a non-AWS Threat Model or implementation-only doc.
    """
    if not is_threat_model_shape(data):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for mit in data.get("mitigations", []):
        if not isinstance(mit, dict) or not mit.get("id"):
            continue
        context = mit.get("mitigationContext") or []
        index[mit["id"]] = {
            "alias": mit.get("alias", ""),
            "statement": mit.get("statement", ""),
            "scoping_context": _collect_scoping_context(context),
            "reference_links": _collect_reference_links(context),
        }
    return index


def parse_threat_model_mitigations(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk an AWS Threat Model-shaped doc's top-level mitigations[] and emit
    `existing_mitigations[]` entries.

    Each output entry carries:
      - id: the source `id` (UUID) — caller may rewrite to `M-...` if needed
      - alias: the source `alias`
      - statement: the source `statement` (preserved verbatim)
      - request_parameters[]: flattened from
            mit["configurationRequestParameters"][i]["paths"][j]["path"]
      - configuration_request_parameters[]: the original nested structure
      - resource_type: recovered via mappings[type=="ENTITY"].id ->
            entities[].id -> entityType (or resource_type when present)
    """
    if not is_threat_model_shape(data):
        return []

    entities_by_id = {
        e.get("id"): e
        for e in data.get("entities", [])
        if isinstance(e, dict) and e.get("id")
    }

    out: list[dict[str, Any]] = []
    for mit in data.get("mitigations", []):
        if not isinstance(mit, dict):
            continue

        # A mitigation may govern several entities or several CFN types.
        resource_types = _dedup(
            resource_type
            for link in (mit.get("mappings") or [])
            if isinstance(link, dict) and link.get("type") == "ENTITY"
            for resource_type in _entity_resource_types(entities_by_id.get(link.get("id"), {}))
        )

        # Flatten configurationRequestParameters[].paths[].path -> request_parameters[]
        cfg_params = mit.get("configurationRequestParameters") or []
        flat_paths: list[str] = []
        for cp in cfg_params:
            if not isinstance(cp, dict):
                continue
            for p in cp.get("paths") or []:
                if isinstance(p, dict) and isinstance(p.get("path"), str):
                    flat_paths.append(p["path"])

        context = mit.get("mitigationContext") or []
        out.append(
            {
                "id": mit.get("id", ""),
                "source_uuid": mit.get("id", ""),
                "alias": mit.get("alias", ""),
                "statement": mit.get("statement", ""),
                "mitigation_goal": mit.get("statement", ""),  # AWS Threat Model folds goal into statement
                "request_parameters": flat_paths,
                "configuration_request_parameters": cfg_params,
                "resource_type": resource_types[0] if resource_types else "",
                "resource_types": resource_types,
                "scoping_context": _collect_scoping_context(context),
                "reference_links": _collect_reference_links(context),
            }
        )

    return out


def build_threat_model_index(data: dict[str, Any], service: str = "", source: dict | None = None) -> dict[str, Any]:
    """Assemble the persisted threat-model-index.json payload from an AWS Threat Model doc.

    Shape validated by schemas/threat-model-index.schema.json. The `mitigations[]` are
    the normalized parse (id + alias + statement + cited REFERENCE links) and
    `implementations[]` are the typed control examples. This is the single source
    of truth a downstream `type: "threat_model"` citation resolves its alias against.
    """
    index = {
        "_metadata": {
            "service": service or (data.get("metadata") or {}).get("name") or "unknown",
            "source": "threat_model",
            "generated": "service-approval",
        },
        "mitigations": parse_threat_model_mitigations(data),
        "implementations": parse_threat_model_implementations(data),
    }
    if source:
        from threat_model_source import citation_url
        index["_metadata"]["threat_model_source"] = source
        for section in ("mitigations", "implementations"):
            for row in index[section]:
                url = citation_url(source, row.get("alias", ""))
                if url:
                    row["threat_model_url"] = url
    return index


def threat_model_index_aliases(index: dict[str, Any]) -> set[str]:
    """Return the set of every resolvable alias in a threat-model-index.json payload.

    The union of mitigation `alias` and implementation `alias`. A
    `type: "threat_model"` citation's `id` must be a member of this set — an
    unresolvable alias is a hard failure in validate_citation_coverage.py.
    """
    aliases: set[str] = set()
    for m in index.get("mitigations", []) or []:
        if isinstance(m, dict) and m.get("alias"):
            aliases.add(m["alias"])
    for i in index.get("implementations", []) or []:
        if isinstance(i, dict) and i.get("alias"):
            aliases.add(i["alias"])
    return aliases


def load_threat_model_index(path: str) -> dict[str, Any] | None:
    """Load a threat-model-index.json file, or None when it is absent/unreadable.

    Absence is not itself an error here — a run with no AWS Threat Model input has no
    index, and citation resolution only requires it when a `type: "threat_model"`
    citation is actually present. The caller decides how to treat None.
    """
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None
