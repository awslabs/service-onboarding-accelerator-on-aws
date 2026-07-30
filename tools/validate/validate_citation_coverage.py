#!/usr/bin/env python3
"""
Citation-coverage enforcement for the non-preventive control families.

Preventive controls are gated by validate_reference_anchor.py (P8): every
authored preventive policy must carry a `_metadata.reference` that resolves to a
reference-index example. This validator carries the SAME discipline to the other
three families — detective, proactive, and responsive: every authored artifact
under `05-recommended-guidance/{detective,proactive,responsive}/` MUST carry a
resolvable citation.

Two citation mechanisms (either satisfies the gate):

  1. **Repo anchor** — `_metadata.reference = {example_id, repo, url}` whose
     `example_id` resolves to a real entry in data/reference-repos/index.yaml.
     Used by Config custom rules and proactive CFN Guard rules, which anchor to
     aws-config-custom-policy-rule-samples (a Guard-DSL repo).

  2. **Doc anchor** — `_metadata.citation = {type: "aws_doc", title, url,
     verified_via: "mcp"}` whose `url` is a well-formed AWS documentation URL
     that was MCP-verified reachable at generation time (logged to pipeline.log).
     Used by AWS-managed Config rules (managed-rule doc), Checkov/OPA (Checkov
     policy-index doc), EventBridge/alarms/CloudTrail (relevant AWS doc), CFN
     Hooks (two-part: repo anchor for the Guard body + a doc anchor to the
     CloudFormation Guard Hooks user-guide), and responsive SSM-runbook
     references (the automation-runbook-reference doc + the specific runbook).

An artifact may carry BOTH (CFN Hooks needs the repo anchor for its rule body
AND the doc anchor for the hook mechanism); either resolving satisfies the gate,
and when both are present both must resolve.

Exempt (no citation required) — these emit no authored control body:
  - gap/skip stubs: `_metadata.status` in {NOT_APPLICABLE, SKIPPED, GAP}.
  - documentation-only files: compensating-controls-documentation.json.
  - non-JSON artifacts whose citation lives in a header comment are covered by
    their sibling JSON descriptor (config-rules.json etc.); the standalone
    `.guard` / `.rego` / `.py` files are not separately gated here — the JSON
    that references them carries the citation.

CLI:
    python3 validate_citation_coverage.py <file>          # single artifact
    python3 validate_citation_coverage.py --slug <slug>   # detective+proactive+responsive
Exit codes: 0 ok, 2 citation violation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Reuse the shared index loader for repo-anchor resolution.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from reference_index import example_ids  # type: ignore
except Exception:  # pragma: no cover - import guard
    example_ids = None  # resolved lazily in _known_ids


# Families this validator gates. Preventive is handled by
# validate_reference_anchor.py (P8) and is intentionally NOT here.
_GATED_FAMILIES = ("detective", "proactive", "responsive")

# Documentation-only / stub basenames that emit no authored control body.
_DOC_ONLY_BASENAMES = {
    "compensating-controls-documentation.json",
    "detective-routing.json",
    "citation-coverage.json",
}

# The proactive citation manifest — its own entries are validated (each names a
# non-JSON rule body and its citation), not treated as a single artifact.
_PROACTIVE_MANIFEST = "citations.json"

# A well-formed AWS documentation URL (docs.aws.amazon.com) OR the Checkov
# policy-index host (the plan's locked doc anchor for Checkov/OPA).
_AWS_DOC_URL_RE = re.compile(
    r"^https://(docs\.aws\.amazon\.com|www\.checkov\.io)/[^\s]+$"
)


def _known_ids() -> set[str]:
    if example_ids is None:
        return set()
    try:
        return example_ids()
    except FileNotFoundError:
        return set()


def _is_gap_or_stub(meta: dict) -> bool:
    status = str(meta.get("status", "")).upper()
    return status in {"NOT_APPLICABLE", "SKIPPED", "GAP"}


def _doc_anchor_errors(basename: str, citation: dict) -> list[str]:
    """Validate a doc-anchor citation shape: {type, title, url, verified_via}."""
    errors: list[str] = []
    if citation.get("type") != "aws_doc":
        errors.append(
            f"CITATION {basename}: _metadata.citation.type must be 'aws_doc' "
            f"(got {citation.get('type')!r})."
        )
    if not str(citation.get("title", "")).strip():
        errors.append(
            f"CITATION {basename}: _metadata.citation.title is empty — name the "
            f"cited AWS documentation page."
        )
    url = str(citation.get("url", "")).strip()
    if not _AWS_DOC_URL_RE.match(url):
        errors.append(
            f"CITATION {basename}: _metadata.citation.url {url!r} is not a "
            f"well-formed AWS documentation URL (https://docs.aws.amazon.com/... "
            f"or the Checkov policy-index URL). It must be MCP-verified reachable "
            f"at generation time and logged to pipeline.log — never a "
            f"training-data guess."
        )
    if citation.get("verified_via") != "mcp":
        errors.append(
            f"CITATION {basename}: _metadata.citation.verified_via must be 'mcp' "
            f"— the URL is proven live by an MCP fetch at generation time."
        )
    return errors


def _repo_anchor_errors(basename: str, reference: dict, known_ids: set[str]) -> list[str]:
    """Validate a repo-anchor reference: example_id resolves against the index."""
    ex_id = reference.get("example_id")
    if not ex_id:
        return [
            f"CITATION {basename}: _metadata.reference carries no example_id."
        ]
    if ex_id not in known_ids:
        return [
            f"CITATION {basename}: _metadata.reference.example_id {ex_id!r} does "
            f"not resolve to any entry in data/reference-repos/index.yaml. Use a "
            f"real index id (rebuild the index or fix the reference)."
        ]
    return []


def _check_proactive_manifest(data: dict, known_ids: set[str]) -> list[str]:
    """Validate proactive/citations.json — each entry cites a non-JSON rule body.

    Each `artifacts[]` entry names a rule body (e.g. cfn-guard-rules.guard) and
    carries a `reference` (repo anchor) and/or `citation` (doc anchor); both,
    when present, must resolve.
    """
    errors: list[str] = []
    entries = data.get("artifacts")
    if not isinstance(entries, list) or not entries:
        return [
            "CITATION citations.json: proactive citation manifest has no "
            "artifacts[] — it must cite every non-JSON proactive rule body "
            "(cfn-guard-rules.guard, checkov-config.yaml, opa-policies/*.rego)."
        ]
    for e in entries:
        if not isinstance(e, dict):
            continue
        name = e.get("artifact", "<unnamed>")
        reference = e.get("reference")
        citation = e.get("citation")
        has_ref = isinstance(reference, dict) and reference.get("example_id")
        has_cit = isinstance(citation, dict)
        if not has_ref and not has_cit:
            errors.append(
                f"CITATION citations.json[{name}]: neither a reference (repo "
                f"anchor) nor a citation (aws_doc anchor)."
            )
            continue
        if has_ref:
            errors.extend(_repo_anchor_errors(f"citations.json[{name}]", reference, known_ids))
        if has_cit:
            errors.extend(_doc_anchor_errors(f"citations.json[{name}]", citation))
    return errors


def check_artifact(file_path: str, known_ids: set[str] | None = None) -> list[str]:
    """Validate one detective/proactive/responsive artifact's citation."""
    errors: list[str] = []
    basename = os.path.basename(file_path)
    # Only the JSON descriptors are gated; the standalone rule bodies
    # (.guard/.rego/.py) are cited by their sibling JSON.
    if not basename.endswith(".json"):
        return errors

    ids = known_ids if known_ids is not None else _known_ids()

    # The proactive citation manifest is validated entry-by-entry.
    if basename == _PROACTIVE_MANIFEST:
        try:
            with open(file_path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return errors
        if isinstance(data, dict):
            return _check_proactive_manifest(data, ids)
        return errors

    if basename in _DOC_ONLY_BASENAMES:
        return errors

    try:
        with open(file_path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        # JSON syntax validated elsewhere (CHECK-7); don't double-report.
        return errors
    if not isinstance(data, dict):
        return errors

    meta = data.get("_metadata")
    if not isinstance(meta, dict):
        errors.append(
            f"CITATION {basename}: no _metadata block — every authored "
            f"detective/proactive/responsive artifact must carry a resolvable "
            f"citation (repo anchor or aws_doc anchor)."
        )
        return errors

    if _is_gap_or_stub(meta):
        return errors  # gap/skip stub — no authored body, no citation required

    reference = meta.get("reference")
    citation = meta.get("citation")
    has_reference = isinstance(reference, dict) and reference.get("example_id")
    has_citation = isinstance(citation, dict)

    if not has_reference and not has_citation:
        errors.append(
            f"CITATION {basename}: carries neither a _metadata.reference (repo "
            f"anchor) nor a _metadata.citation (aws_doc anchor). Every authored "
            f"artifact must cite a published AWS repo example or a MCP-verified "
            f"AWS documentation page."
        )
        return errors

    # When present, each mechanism must resolve. CFN Hooks legitimately carries
    # BOTH (repo anchor for the rule body + doc anchor for the hook mechanism).
    if has_reference:
        errors.extend(_repo_anchor_errors(basename, reference, ids))
    if has_citation:
        errors.extend(_doc_anchor_errors(basename, citation))
    return errors


def check_service(service_root: Path) -> list[str]:
    """Validate every gated artifact under a service's recommended-guidance dir."""
    errors: list[str] = []
    guidance = service_root / "05-recommended-guidance"
    if not guidance.is_dir():
        return errors
    ids = _known_ids()
    for family in _GATED_FAMILIES:
        fam_dir = guidance / family
        if not fam_dir.is_dir():
            continue
        for fpath in sorted(fam_dir.glob("*.json")):
            errors.extend(check_artifact(str(fpath), ids))
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="single artifact path")
    parser.add_argument("--slug", help="validate a service's detective/proactive/responsive dirs")
    args = parser.parse_args()

    if args.slug:
        root = Path(os.getcwd()) / ".service-approval" / args.slug
        errors = check_service(root)
    elif args.file:
        errors = check_artifact(args.file)
    else:
        parser.error("provide a file path OR --slug")

    if errors:
        print(f"CITATION COVERAGE FAILED ({len(errors)} errors):", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
