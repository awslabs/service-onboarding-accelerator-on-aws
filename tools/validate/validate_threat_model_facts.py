#!/usr/bin/env python3
"""
AWS Threat Model-factual validator (deterministic).

When a control or preventive decision cites an AWS Threat Model mitigation as its intent
source, that citation must be FACTUAL: the cited mitigation `alias` must actually
exist in the provided AWS Threat Model export, the control's gated operation must be
consistent with that mitigation's `configurationRequestParameters[]`, and any
mitigation text the citation quotes must appear verbatim in the AWS Threat Model export.
This catches a fabricated or drifted AWS Threat Model citation — a control that claims
AWS Threat Model intent the AWS Threat Model file does not support.

It is deterministic (no LLM): pure set membership + normalized text search
against the AWS Threat Model file. Runs in BOTH review gates (post-map and post-generate).

Two citation field shapes are accepted (a citation is "threat_model" under either):
  - map / framework-mapping rows: `citation.source == "threat_model"` +
    `citation.mitigation_alias` (+ optionally a quoted `mitigation_statement`).
  - preventive-plan rows: `citation.type == "threat_model"` + `citation.id`.

Three checks per threat-model-cited item:
  1. **Alias exists.** The cited alias must match a `mitigations[].alias` (or,
     when the item cites a threat, a `threats[].alias`) in the AWS Threat Model export.
  2. **Operation consistency.** When the item names gated operations (a control's
     `actions[]`, or a plan row's `plan_actions[]`), at least one must correspond
     to an operation the cited mitigation actually governs (the
     `configurationRequestParameters[].operation` set). An IAM action
     `prefix:DoThing` maps to the AWS Threat Model operation `DoThing` (case-insensitive,
     trailing-wildcard stripped). When the item names no operations, this check
     is skipped (alias existence alone is the assertion).
  3. **Statement is verbatim.** When the citation quotes mitigation text (a
     `mitigation_statement` / `statement` field), that text must appear verbatim
     — normalized for case/whitespace/punctuation — in the cited mitigation's
     `statement`. A citation that quotes text not found in AWS Threat Model is a FAIL.
     Citations that quote no text are not subject to this check.

Scope: map-framework-mapped.json rows are checked only when the objective row's
`status == "MAPPED"`. `UNCERTAIN` rows are the honest escape hatch and are
exempt. `assessment_gap`-sourced citations name no AWS Threat Model mitigation and are not
AWS Threat Model citations, so they are naturally out of scope.

CLI:
    python3 validate_threat_model_facts.py --slug <slug> [--strict]
    python3 validate_threat_model_facts.py --threat-model <file> [--plan <p>] [--mapping <m>] \
        [--fw-mapped <f>] [--strict]
Exit codes: 0 ok (or advisory: violations without --strict), 2 factual violation
under --strict.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_model_parse import (  # type: ignore
    is_threat_model_shape,
    is_threat_model_threats_shape,
    parse_threat_model_implementations,
)


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _bare_op(action: str) -> str:
    """`bedrock-agentcore:CreateAgentRuntime` -> `createagentruntime`."""
    a = action.split(":", 1)[1] if ":" in action else action
    return a.strip().lower().rstrip("*")


def _normalize_text(text: str) -> str:
    """Fold case, whitespace, and punctuation for verbatim comparison.

    A legitimate citation should not fail on trivial formatting differences
    (a trailing period, doubled spaces, smart quotes), so we compare on a
    normalized form: lowercased, punctuation stripped, whitespace collapsed.
    """
    lowered = (text or "").lower()
    kept = [ch if (ch.isalnum() or ch.isspace()) else " " for ch in lowered]
    return " ".join("".join(kept).split())


def _implementation_index(threat_model: dict) -> dict[str, dict]:
    """`{implementation_alias: parsed-implementation-row}` for the export.

    AWS Threat Model `implementations[]` carry their own `alias` (e.g.
    `Implementation.DSQL.2`). A preventive/detective control may anchor a
    AWS Threat Model citation directly to an implementation (the round that added
    AWS Threat Model-first citations across all four families), so an implementation
    alias is an equally valid AWS Threat Model citation target as a mitigation/threat
    alias. Returns {} for a non-AWS Threat Model or implementation-only doc.
    """
    return {
        row["alias"]: row
        for row in parse_threat_model_implementations(threat_model)
        if isinstance(row, dict) and row.get("alias")
    }


def mitigation_statement(threat_model: dict, alias: str) -> str:
    """The AWS Threat Model `statement` for a mitigation/threat alias (empty if none).

    Implementation aliases carry no free-text `statement` (their intent lives
    in a typed policy body), so they return empty — a citation that quotes a
    statement while anchoring to an implementation is caught by the verbatim
    check as text the export does not contain.
    """
    for m in threat_model.get("mitigations", []) or []:
        if isinstance(m, dict) and m.get("alias") == alias:
            return str(m.get("statement") or "")
    for t in threat_model.get("threats", []) or []:
        if isinstance(t, dict) and t.get("alias") == alias:
            return str(t.get("statement") or "")
    return ""


def threat_model_alias_set(threat_model: dict) -> set[str]:
    """All mitigation + threat + implementation aliases present in the export."""
    out: set[str] = set()
    for m in threat_model.get("mitigations", []) or []:
        if isinstance(m, dict) and m.get("alias"):
            out.add(m["alias"])
    for t in threat_model.get("threats", []) or []:
        if isinstance(t, dict) and t.get("alias"):
            out.add(t["alias"])
    out.update(_implementation_index(threat_model).keys())
    return out


def mitigation_operations(threat_model: dict, alias: str) -> set[str]:
    """The set of bare operation names a mitigation/threat governs (lowercased).

    Pulled from `configurationRequestParameters[].operation` (mitigations) and
    `requestParameters[].operation` (threats). Empty set when the alias names a
    mitigation with no operation-scoped parameters (some are resource-level only).
    """
    ops: set[str] = set()
    for m in threat_model.get("mitigations", []) or []:
        if not isinstance(m, dict) or m.get("alias") != alias:
            continue
        for cp in m.get("configurationRequestParameters", []) or []:
            if isinstance(cp, dict) and cp.get("operation"):
                ops.add(str(cp["operation"]).lower())
    for t in threat_model.get("threats", []) or []:
        if not isinstance(t, dict) or t.get("alias") != alias:
            continue
        for cp in t.get("requestParameters", []) or []:
            if isinstance(cp, dict) and cp.get("operation"):
                ops.add(str(cp["operation"]).lower())
    # Implementation aliases: governed operations come from the parsed guide —
    # authorization_policy actions (bare op, wildcards dropped), config-rule
    # governed_api_operations, and cloudtrail monitored_operations. An empty set
    # (e.g. a `dsql:*` wildcard policy) leaves the op-drift check a no-op, as it
    # is for a resource-level-only mitigation.
    impl = _implementation_index(threat_model).get(alias)
    if impl:
        for action in impl.get("actions", []) or []:
            if isinstance(action, str) and not action.endswith("*"):
                ops.add(_bare_op(action))
        for key in ("governed_api_operations", "monitored_operations"):
            for op in impl.get(key, []) or []:
                if isinstance(op, dict) and op.get("operation"):
                    ops.add(str(op["operation"]).lower())
    return ops


def _citation_alias(cit: dict) -> str | None:
    """The cited AWS Threat Model alias under either field shape.

    map / framework-mapping rows use `source == "threat_model"` + `mitigation_alias`;
    preventive-plan rows use `type == "threat_model"` + `id`. Returns None when the
    citation is not an AWS Threat Model citation.
    """
    if not isinstance(cit, dict):
        return None
    if cit.get("source") == "threat_model":
        # An AWS Threat Model-sourced map citation. Alias may be absent (caught downstream).
        return cit.get("mitigation_alias")
    if cit.get("type") == "threat_model":
        return cit.get("id")
    return None


def _is_threat_model_citation(cit: dict) -> bool:
    return isinstance(cit, dict) and (
        cit.get("source") == "threat_model" or cit.get("type") == "threat_model"
    )


def _quoted_statement(cit: dict) -> str:
    """Any verbatim mitigation text the citation quotes (empty if none)."""
    for k in ("mitigation_statement", "statement"):
        v = cit.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _threat_model_cited_items(
    plan: dict | None, mapping: dict | None, fw_mapped: dict | None
) -> list[dict]:
    """Collect {id, alias, actions[], statement, source} for every threat-model-cited item.

    Reads preventive-plan.json decisions, mapping-results.json controls, and
    map-framework-mapped.json control rows (MAPPED objectives only — UNCERTAIN
    rows are the honesty escape hatch and are exempt). Only items whose citation
    is an AWS Threat Model citation (either field shape) are returned.
    """
    items: list[dict] = []

    def _maybe_add(obj: dict, action_keys: tuple[str, ...], source: str) -> None:
        cit = obj.get("citation")
        if not _is_threat_model_citation(cit):
            return
        actions: list[str] = []
        for k in action_keys:
            v = obj.get(k)
            if isinstance(v, list):
                actions.extend(a for a in v if isinstance(a, str))
        items.append({
            "id": obj.get("control_id") or obj.get("id") or "<unknown>",
            "alias": _citation_alias(cit),
            "actions": actions,
            "statement": _quoted_statement(cit),
            "source": source,
        })

    if isinstance(plan, dict):
        for d in plan.get("decisions", []) or []:
            if isinstance(d, dict):
                _maybe_add(d, ("plan_actions", "actions"), "preventive-plan")
    if isinstance(mapping, dict):
        for c in mapping.get("controls", []) or []:
            if isinstance(c, dict):
                _maybe_add(c, ("actions",), "mapping-results")
    if isinstance(fw_mapped, dict):
        for f in fw_mapped.get("framework_mapping", []) or []:
            if not isinstance(f, dict) or f.get("status") != "MAPPED":
                continue
            oid = f.get("objective_id", "<unknown>")
            for cm in f.get("controls", []) or []:
                if isinstance(cm, dict):
                    _maybe_add(cm, ("actions",), f"framework-mapping {oid}")

    return items


def check(
    threat_model: dict,
    plan: dict | None,
    mapping: dict | None,
    fw_mapped: dict | None = None,
) -> list[str]:
    """Return factual-violation error strings for threat-model-cited items."""
    errors: list[str] = []
    if not (is_threat_model_shape(threat_model) or is_threat_model_threats_shape(threat_model)):
        # Not an AWS Threat Model file — nothing authoritative to check against. The caller
        # decides whether that is itself a problem; here we stay quiet.
        return errors

    aliases = threat_model_alias_set(threat_model)
    items = _threat_model_cited_items(plan, mapping, fw_mapped)

    for item in items:
        alias = item["alias"]
        if not alias:
            errors.append(
                f"THREAT_MODEL-FACT {item['source']} {item['id']}: citation is threat-model-sourced "
                f"but names no mitigation alias. A threat_model citation must name the "
                f"mitigation alias it claims intent from."
            )
            continue
        if alias not in aliases:
            errors.append(
                f"THREAT_MODEL-FACT {item['source']} {item['id']}: cites threat_model alias "
                f"{alias!r} which does not exist in the provided AWS Threat Model export — "
                f"fabricated or drifted citation."
            )
            continue
        # Operation consistency — only when the item names operations AND the
        # mitigation governs operations (resource-only mitigations are exempt).
        item_ops = {_bare_op(a) for a in item["actions"] if a}
        gov_ops = mitigation_operations(threat_model, alias)
        if item_ops and gov_ops and not (item_ops & gov_ops):
            errors.append(
                f"THREAT_MODEL-FACT {item['source']} {item['id']}: gated operation(s) "
                f"{sorted(item_ops)} are not among the operations AWS Threat Model mitigation "
                f"{alias!r} governs ({sorted(gov_ops)}) — the citation does not "
                f"support this control's target action."
            )
        # Verbatim provenance — only when the citation quotes mitigation text.
        quoted = item.get("statement", "")
        if quoted:
            source_stmt = mitigation_statement(threat_model, alias)
            if _normalize_text(quoted) not in _normalize_text(source_stmt):
                errors.append(
                    f"THREAT_MODEL-FACT {item['source']} {item['id']}: cited statement "
                    f"{quoted!r} is not found verbatim in AWS Threat Model mitigation "
                    f"{alias!r}'s statement — the citation quotes text the AWS Threat Model "
                    f"export does not contain."
                )
    return errors


def find_threat_model_file(service_root: Path) -> Path | None:
    """Return the validated source selected by intake, never a folder fallback."""
    from validate_threat_model_input import load_run_export
    return load_run_export(service_root)[0]


def check_service(service_root: Path) -> list[str]:
    """Run the factual check, failing closed when the required export is absent."""
    from validate_threat_model_input import load_run_export
    threat_model_path, errors = load_run_export(service_root)
    if errors:
        return errors
    threat_model = _load_json(threat_model_path)
    if not isinstance(threat_model, dict):
        return ["AWS Threat Model export became unreadable after input validation."]
    plan = _load_json(service_root / "05-recommended-guidance" / "preventive-plan.json")
    mapping = _load_json(service_root / "04-map" / "mapping-results.json")
    fw_mapped = _load_json(service_root / "04-map" / "map-framework-mapped.json")
    return check(threat_model, plan if isinstance(plan, dict) else None,
                 mapping if isinstance(mapping, dict) else None,
                 fw_mapped if isinstance(fw_mapped, dict) else None)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--threat-model", help="explicit AWS Threat Model export path")
    parser.add_argument("--plan", help="explicit preventive-plan.json path")
    parser.add_argument("--mapping", help="explicit mapping-results.json path")
    parser.add_argument("--fw-mapped", dest="fw_mapped",
                        help="explicit map-framework-mapped.json path")
    parser.add_argument("--advisory", action="store_true",
                        help="report violations without failing (exit 0); "
                             "by default any factual violation blocks (exit 2)")
    parser.add_argument("--strict", action="store_true",
                        help="deprecated no-op; blocking is the default")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.threat_model:
        threat_model = _load_json(Path(args.threat_model))
        if not isinstance(threat_model, dict):
            print(f"ERROR: {args.threat_model} unreadable", file=sys.stderr)
            return 2
        plan = _load_json(Path(args.plan)) if args.plan else None
        mapping = _load_json(Path(args.mapping)) if args.mapping else None
        fw_mapped = _load_json(Path(args.fw_mapped)) if args.fw_mapped else None
        errors = check(threat_model, plan if isinstance(plan, dict) else None,
                       mapping if isinstance(mapping, dict) else None,
                       fw_mapped if isinstance(fw_mapped, dict) else None)
    else:
        parser.error("provide --slug OR --threat-model")

    if errors:
        label = "advisory" if args.advisory else "FAILED"
        print(f"THREAT_MODEL-FACTUAL {label} ({len(errors)} violations):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 0 if args.advisory else 2
    print("threat-model-factual: no violations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
