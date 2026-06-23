"""Reference parser for the Canopy threat-model JSON shape.

Canopy exports use a top-level `mitigations[]` and `threats[]`, with each
mitigation carrying `mappings[]` whose entries point back at `entities[]`,
`mitigation goals`, threats, and implementations. The earlier
research-mitigations parser only iterated `entities[].mitigations[]`, which
silently dropped every Canopy mitigation.

This module is the reference implementation used by tests; the
research-mitigations and research-attack-surface skills follow the same
detection rules (see those SKILL.md files).
"""

from __future__ import annotations

from typing import Any


def is_canopy_shape(data: dict[str, Any]) -> bool:
    """Return True when the file looks like a Canopy export.

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


def is_canopy_threats_shape(data: dict[str, Any]) -> bool:
    """Return True when the file carries a top-level Canopy `threats[]`.

    Distinct from `is_canopy_shape` — research-attack-surface only needs the
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


def _entity_resource_type(entity: dict[str, Any]) -> str:
    """Recover a resource_type string from a Canopy entity entry."""
    return entity.get("resource_type") or entity.get("entityType") or ""


def parse_canopy_mitigations(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk a Canopy-shaped doc's top-level mitigations[] and emit
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
    if not is_canopy_shape(data):
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

        # Recover the linked entity (and thus resource_type) via the ENTITY mapping
        entity_id = next(
            (
                m.get("id")
                for m in (mit.get("mappings") or [])
                if isinstance(m, dict) and m.get("type") == "ENTITY"
            ),
            None,
        )
        ent = entities_by_id.get(entity_id, {}) if entity_id else {}
        resource_type = _entity_resource_type(ent)

        # Flatten configurationRequestParameters[].paths[].path -> request_parameters[]
        cfg_params = mit.get("configurationRequestParameters") or []
        flat_paths: list[str] = []
        for cp in cfg_params:
            if not isinstance(cp, dict):
                continue
            for p in cp.get("paths") or []:
                if isinstance(p, dict) and isinstance(p.get("path"), str):
                    flat_paths.append(p["path"])

        out.append(
            {
                "id": mit.get("id", ""),
                "alias": mit.get("alias", ""),
                "statement": mit.get("statement", ""),
                "mitigation_goal": mit.get("statement", ""),  # Canopy folds goal into statement
                "request_parameters": flat_paths,
                "configuration_request_parameters": cfg_params,
                "resource_type": resource_type,
            }
        )

    return out
