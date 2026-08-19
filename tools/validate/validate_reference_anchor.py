#!/usr/bin/env python3
"""
Reference-anchor enforcement for generated preventive controls.

Preventive control generation is repo-anchored: every emitted preventive policy
artifact must trace to a known-good example in the reference index
(data/reference-repos/index.yaml). This validator proves that anchoring — it is
the gate that makes "we only generate when we can anchor to a reference"
checkable rather than aspirational.

Rule: every policy artifact under <slug>/05-recommended-guidance/preventive/ MUST anchor to
a known-good example. Two anchor mechanisms satisfy the rule:

  1. **Repo anchor** — `_metadata.reference` whose `example_id` resolves to a
     real entry in the reference index.
  2. **AWS Threat Model anchor** — `_metadata.citation = {type: "threat_model", id: "<alias>"}`
     whose alias resolves to a real mitigation/implementation in the ingested
     AWS Threat Model index (02-research/threat-model-index.json). AWS Threat Model supplies both the
     control intent AND the policy shape (governed actions + condition_keys), so
     an AWS Threat Model-anchored preventive control is fully anchored — a repo `reference`
     is no longer mandatory when a resolvable AWS Threat Model anchor is present.

An artifact with neither a resolvable repo anchor nor a resolvable AWS Threat Model anchor
is a hard failure.

`_metadata.reference` shape (written by the preventive authoring sub-skills):

    "_metadata": {
      ...
      "reference": {
        "example_id": "service-control-policy-examples-deny-...",
        "repo": "service-control-policy-examples",
        "url": "https://github.com/aws-samples/.../blob/<sha>/<path>"
      }
    }

`_metadata.citation` shape for an AWS Threat Model anchor:

    "_metadata": {
      ...
      "citation": {
        "type": "threat_model",
        "id": "Implementation.DSQL.2",
        "url": "https://docs.aws.amazon.com/.../data-perimeters.html",
        "verified_via": "mcp"
      }
    }

Exempt (no anchor required) — these emit no enforcing policy:
  - gap/skip stubs: _metadata.status == "NOT_APPLICABLE", or a *_gap note
    (scp_gap / rcp_gap / etc.) is present and the policy body is empty.
  - documentation-only files: compensating-controls-documentation.json and
    rootcause-report.json (the root-cause critic's report — a findings document,
    not an enforcing policy).
  - non-JSON files (the policy artifacts under preventive/ are JSON).

CLI:
    python3 validate_reference_anchor.py <file>            # single artifact
    python3 validate_reference_anchor.py --slug <slug>     # whole preventive dir
Exit codes: 0 ok, 2 anchor violation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Reuse the shared index loader.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from reference_index import example_ids, is_refer_only  # type: ignore
except Exception:  # pragma: no cover - import guard
    example_ids = None  # resolved lazily in _known_ids

    def is_refer_only(_mechanism: str) -> bool:  # type: ignore
        # Fallback when the shared index module can't be imported: hardcode the
        # refer-only mechanism strings so the trust-policy guard still fires.
        return (_mechanism or "").strip().lower() in {
            "iam trust policy", "trust policy",
        }

# AWS Threat Model anchor resolution — a `type: "threat_model"` citation resolves the anchor
# requirement for a preventive artifact when its alias is in the ingested index.
try:
    from threat_model_parse import threat_model_index_aliases, load_threat_model_index  # type: ignore
except Exception:  # pragma: no cover - import guard
    threat_model_index_aliases = None
    load_threat_model_index = None


# Files under preventive/ that are documentation, not enforcing policy.
_DOC_ONLY_BASENAMES = {
    "compensating-controls-documentation.json",
    "rootcause-report.json",
}


def _known_ids() -> set[str]:
    """Return the set of valid anchor ids, or empty set if index is absent.

    A missing index is itself a failure mode, but it is surfaced per-artifact
    (an artifact that claims an anchor we cannot resolve) rather than here, so
    the caller still gets a precise message.
    """
    if example_ids is None:
        return set()
    try:
        return example_ids()
    except FileNotFoundError:
        return set()


def _load_threat_model_aliases(service_root: Path) -> set[str] | None:
    """Return the resolvable AWS Threat Model alias set for a service, or None if absent.

    None means the run has no threat-model-index.json (no AWS Threat Model input). A threat_model
    anchor cited without an index is unresolvable — see _threat_model_anchor_alias.
    """
    if load_threat_model_index is None or threat_model_index_aliases is None:
        return None
    index = load_threat_model_index(str(service_root / "02-research" / "threat-model-index.json"))
    if index is None:
        return None
    return threat_model_index_aliases(index)


def _threat_model_anchor_alias(meta: dict) -> str | None:
    """Return the cited AWS Threat Model alias when _metadata.citation is a threat_model anchor.

    Returns the alias string for a `{type: "threat_model", id: <alias>}` citation, or
    None when the artifact carries no threat_model citation.
    """
    citation = meta.get("citation")
    if isinstance(citation, dict) and citation.get("type") == "threat_model":
        alias = str(citation.get("id", "")).strip()
        return alias or None
    return None


def _is_gap_or_stub(meta: dict, data: dict) -> bool:
    """True when the artifact is an explicit gap/skip stub (no policy emitted)."""
    status = str(meta.get("status", "")).upper()
    if status in {"NOT_APPLICABLE", "SKIPPED", "GAP"}:
        return True
    # *_gap note + empty statement body.
    has_gap_note = any(k.endswith("_gap") for k in meta)
    statements = data.get("Statement")
    body_empty = not statements  # None or []
    return has_gap_note and body_empty


def _surfaces_url(meta: dict) -> bool:
    """True when the artifact surfaces a citation/reference URL to the customer.

    An artifact surfaces a URL when its resolved reference anchor carries one
    (`_metadata.reference.url`) or its citation carries one
    (`_metadata.citation.url`). When it does, the report links the customer out
    to that policy, so the artifact MUST carry an applicability block explaining
    what the cited policy targets and where not to apply it.
    """
    reference = meta.get("reference")
    if isinstance(reference, dict) and str(reference.get("url", "")).strip():
        return True
    citation = meta.get("citation")
    if isinstance(citation, dict) and str(citation.get("url", "")).strip():
        return True
    return False


def _applicability_errors(basename: str, meta: dict) -> list[str]:
    """Enforce: a URL-surfacing artifact must carry a non-empty applicability.

    Tied to the presence of a customer-facing URL (see `_surfaces_url`). A
    threat-model-only artifact with just an id and no URL is exempt — there is no
    external link to clarify.
    """
    if not _surfaces_url(meta):
        return []
    applicability = meta.get("applicability")
    if not isinstance(applicability, dict):
        return [
            f"P8 reference_anchor: {basename} surfaces a citation/reference URL "
            f"but carries no _metadata.applicability. A cited preventive policy "
            f"must state what resource subset it targets (applies_to) and how to "
            f"use it, including where NOT to apply it (usage_notes)."
        ]
    errors: list[str] = []
    for field in ("applies_to", "usage_notes"):
        if not str(applicability.get(field, "")).strip():
            errors.append(
                f"P8 reference_anchor: {basename} has _metadata.applicability but "
                f"its '{field}' is empty. Both applies_to and usage_notes must be "
                f"non-empty for a URL-cited preventive policy."
            )
    return errors


def _is_authored_policy(data: dict) -> bool:
    """True when the artifact emits enforcing policy (Statement[] non-empty).

    The not_anchored escape hatch is only valid for REFER/pointer artifacts —
    files that document an objective and point at a reference rather than
    authoring policy of their own. An authored policy with an empty `Statement[]`
    is impossible (it does nothing); a populated Statement[] means we are
    shipping enforcing policy and MUST anchor.
    """
    statements = data.get("Statement")
    if isinstance(statements, list) and len(statements) > 0:
        return True
    return False


def _mapping_control_ids(service_root: Path) -> set[str] | None:
    """Return the set of mapping-results.json control ids for orphan-check.

    Returns None when mapping-results is unavailable (so the orphan check
    silently no-ops rather than spuriously failing — the schema's pattern
    rule already enforces shape).
    """
    mr = service_root / "04-map" / "mapping-results.json"
    if not mr.is_file():
        return None
    try:
        with mr.open() as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return {c.get("id") for c in data.get("controls", []) if isinstance(c, dict) and c.get("id")}


def check_artifact(
    file_path: str,
    known_ids: set[str] | None = None,
    mapping_ids: set[str] | None = None,
    threat_model_aliases: set[str] | None = None,
) -> list[str]:
    """Validate one preventive artifact's reference anchor. Returns errors.

    `threat_model_aliases` is the resolvable AWS Threat Model alias set for the run; a
    `{type: "threat_model"}` citation resolves the anchor requirement when its alias is
    a member. None means no threat-model-index.json was found for the run.
    """
    errors: list[str] = []
    basename = os.path.basename(file_path)
    if not basename.endswith(".json"):
        return errors
    if basename in _DOC_ONLY_BASENAMES:
        return errors

    try:
        with open(file_path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        # JSON syntax is validated elsewhere (CHECK-7); don't double-report.
        return errors
    if not isinstance(data, dict):
        return errors

    meta = data.get("_metadata")
    if not isinstance(meta, dict):
        errors.append(
            f"P8 reference_anchor: {basename} has no _metadata block — a "
            f"preventive artifact must carry a reference anchor."
        )
        return errors

    if _is_gap_or_stub(meta, data):
        return errors  # gap/skip stubs emit no policy; no anchor required

    # Refer-only mechanisms (trust policies) must NEVER carry a repo anchor or
    # author policy. There is no vetted trust-policy example library, so a trust
    # policy that resolves a reference example has been stamped with an
    # unrelated (identity-policy) anchor — an incoherent shape. A trust policy
    # must be a REFER artifact: no Statement[] body, not_anchored: true, and a
    # service-doc citation pointing at the confused-deputy pattern.
    mechanism = str(meta.get("mechanism", ""))
    if is_refer_only(mechanism):
        reference = meta.get("reference")
        has_anchor = isinstance(reference, dict) and reference.get("example_id")
        if has_anchor:
            errors.append(
                f"P8 reference_anchor: {basename} is a refer-only mechanism "
                f"({mechanism!r}) but carries _metadata.reference.example_id "
                f"'{reference.get('example_id')}'. Trust policies have no vetted "
                f"example library and must be referred, not authored — emit a "
                f"REFER artifact (no anchor, not_anchored: true, service-doc "
                f"citation for the confused-deputy pattern) instead."
            )
        if _is_authored_policy(data):
            errors.append(
                f"P8 reference_anchor: {basename} is a refer-only mechanism "
                f"({mechanism!r}) but ships enforcing policy (Statement[] is "
                f"non-empty). Trust policies must be referred, not authored."
            )
        return errors

    # not_anchored escape hatch: a REFER/pointer artifact may declare
    # itself un-anchored, but ONLY if it is not actually authoring policy
    # (Statement[] is empty) AND it states the reason explicitly. Without
    # the explicit not_anchored_reason, "no anchor" is indistinguishable
    # from the authoring sub-skill silently dropping the anchor on the
    # floor — fail closed.
    if meta.get("not_anchored") is True:
        if _is_authored_policy(data):
            errors.append(
                f"P8 reference_anchor: {basename} declares "
                f"_metadata.not_anchored: true but ships enforcing policy "
                f"(Statement[] is non-empty). The not_anchored escape "
                f"hatch is only valid for REFER/pointer artifacts; an "
                f"authored policy MUST resolve a reference anchor or be "
                f"removed."
            )
        if not str(meta.get("not_anchored_reason", "")).strip():
            errors.append(
                f"P8 reference_anchor: {basename} declares "
                f"_metadata.not_anchored: true but no "
                f"_metadata.not_anchored_reason. The reason is required so "
                f"reviewers can tell why the artifact ships without an "
                f"anchor — silent un-anchored REFER files are forbidden."
            )
        # Even an un-anchored REFER must trace back to a real upstream control.
        sid = meta.get("source_control_id")
        if mapping_ids is not None and sid is not None and sid not in mapping_ids:
            errors.append(
                f"P8 reference_anchor: {basename} declares "
                f"source_control_id '{sid}' which does not exist in "
                f"mapping-results.json — orphan artifact."
            )
        return errors

    ids = known_ids if known_ids is not None else _known_ids()
    reference = meta.get("reference")
    has_repo_anchor = isinstance(reference, dict) and reference.get("example_id")
    repo_resolves = bool(has_repo_anchor and reference["example_id"] in ids)

    # AWS Threat Model anchor: a resolvable `{type: "threat_model"}` citation fully anchors a
    # preventive artifact — AWS Threat Model supplies both the control intent and the
    # policy shape (governed actions + condition_keys), so a repo `reference` is
    # not additionally required. The artifact is anchored when EITHER the repo
    # anchor OR the AWS Threat Model anchor resolves.
    threat_model_alias = _threat_model_anchor_alias(meta)
    if threat_model_alias is not None:
        threat_model_resolves = threat_model_aliases is not None and threat_model_alias in threat_model_aliases
        # Fail only when neither anchor resolves — a repo anchor that resolves
        # still carries the artifact even if the AWS Threat Model index is not loaded.
        if not threat_model_resolves and not repo_resolves:
            if threat_model_aliases is None:
                errors.append(
                    f"P8 reference_anchor: {basename} cites AWS Threat Model alias "
                    f"{threat_model_alias!r} but no threat-model-index.json was found at "
                    f"02-research/threat-model-index.json — an AWS Threat Model anchor must resolve "
                    f"to an ingested AWS Threat Model alias."
                )
            else:
                errors.append(
                    f"P8 reference_anchor: {basename} cites AWS Threat Model alias "
                    f"{threat_model_alias!r} which does not resolve to any "
                    f"mitigation/implementation alias in threat-model-index.json. Cite a "
                    f"real AWS Threat Model alias."
                )
        # A repo reference, when ALSO present, must resolve — a bogus repo anchor
        # is never acceptable, even alongside a good AWS Threat Model anchor.
        if has_repo_anchor and not repo_resolves:
            errors.append(
                f"P8 reference_anchor: {basename} references example_id "
                f"'{reference['example_id']}' which does not resolve to any entry "
                f"in data/reference-repos/index.yaml."
            )
        # Orphan + applicability checks still apply to an AWS Threat Model-anchored artifact.
        sid = meta.get("source_control_id")
        if mapping_ids is not None and sid is not None and sid not in mapping_ids:
            errors.append(
                f"P8 reference_anchor: {basename} declares source_control_id "
                f"'{sid}' which does not exist in mapping-results.json — orphan "
                f"artifact."
            )
        errors.extend(_applicability_errors(basename, meta))
        return errors

    # An authored preventive policy with no anchor is the original P8
    # failure mode; flag it before the resolution check.
    if not has_repo_anchor:
        if _is_authored_policy(data):
            errors.append(
                f"P8 reference_anchor: {basename} emits a preventive policy but "
                f"carries no _metadata.reference.example_id and no resolvable "
                f"AWS Threat Model citation. Every preventive control must anchor to a "
                f"reference example in data/reference-repos/index.yaml or an AWS Threat Model "
                f"implementation (or be a gap/skip stub). If nothing covers this "
                f"objective, do not author a policy — point to the reference or "
                f"route to detective."
            )
        else:
            # REFER/pointer with no Statement body, no anchor, and no
            # explicit not_anchored declaration. The artifact is in a
            # silent un-anchored state — fail closed so the run cannot
            # claim coverage it does not have.
            errors.append(
                f"P8 reference_anchor: {basename} has no _metadata.reference "
                f"and no enforcing Statement[] body, but does NOT declare "
                f"_metadata.not_anchored: true with a reason. A REFER/pointer "
                f"artifact must explicitly state it is un-anchored — silent "
                f"un-anchored artifacts are forbidden."
            )
        return errors

    example_id = reference["example_id"]
    if example_id not in ids:
        errors.append(
            f"P8 reference_anchor: {basename} references example_id "
            f"'{example_id}' which does not resolve to any entry in "
            f"data/reference-repos/index.yaml. The anchor must be a real, "
            f"current index id (rebuild the index or fix the reference)."
        )

    # Orphan source_control_id check — anchored or un-anchored, every
    # artifact must trace back to a real upstream control. mapping_ids is
    # None when mapping-results.json isn't available (helper test paths);
    # in that case skip the check rather than raise spuriously.
    sid = meta.get("source_control_id")
    if mapping_ids is not None and sid is not None and sid not in mapping_ids:
        errors.append(
            f"P8 reference_anchor: {basename} declares "
            f"source_control_id '{sid}' which does not exist in "
            f"mapping-results.json — orphan artifact."
        )

    # A cited (URL-surfacing) preventive policy must explain what it targets and
    # where not to apply it — the applicability block.
    errors.extend(_applicability_errors(basename, meta))
    return errors


def check_service(service_root: Path) -> list[str]:
    """Validate every preventive artifact under a service root. Returns errors."""
    errors: list[str] = []
    prev_dir = service_root / "05-recommended-guidance" / "preventive"
    if not prev_dir.is_dir():
        return errors
    ids = _known_ids()
    mids = _mapping_control_ids(service_root)
    threat_model_aliases = _load_threat_model_aliases(service_root)
    for fpath in sorted(prev_dir.glob("*.json")):
        errors.extend(check_artifact(str(fpath), ids, mids, threat_model_aliases))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="single artifact path")
    parser.add_argument("--slug", help="validate a service's preventive/ dir")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.file:
        # Locate the service root so a single-file check can resolve an AWS Threat Model
        # anchor against that run's threat-model-index.json.
        threat_model_aliases: set[str] | None = None
        for parent in Path(args.file).resolve().parents:
            if (parent / "05-recommended-guidance").is_dir() or (parent / "02-research").is_dir():
                threat_model_aliases = _load_threat_model_aliases(parent)
                break
        errors = check_artifact(args.file, threat_model_aliases=threat_model_aliases)
    else:
        parser.error("provide a file path OR --slug")

    if errors:
        print(f"REFERENCE ANCHOR FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
