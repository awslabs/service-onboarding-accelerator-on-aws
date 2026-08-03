#!/usr/bin/env python3
"""
Build the deterministic citation-coverage rollup for the non-preventive families.

Mirrors build_preventive_coverage.py, but for detective / proactive / responsive.
Walks every authored artifact under
`05-recommended-guidance/{detective,proactive,responsive}/` and records the
citation each carries — a repo anchor (`_metadata.reference`) or a doc anchor
(`_metadata.citation`) — so the Summary Report and reviewers can account for
every artifact's provenance from one file.

Bucketing per artifact:
  - has _metadata.reference (repo anchor)  → "repo_anchor"
  - has _metadata.citation (type canopy)   → "canopy_anchor"
  - has _metadata.citation (aws_doc)       → "doc_anchor"
  - has both (e.g. CFN Hooks)              → "repo_anchor+doc_anchor"
  - gap/skip stub or doc-only              → "exempt"
  - neither                                → "uncited"  (a violation; the gate
                                              validate_citation_coverage.py fails
                                              the run, but the rollup still records
                                              it so the gap is visible)

CLI:
    python3 build_citation_coverage.py --slug <slug>
    python3 build_citation_coverage.py --guidance-dir <dir> [--out <out.json>]
Exit codes: 0 ok (file written), 2 guidance dir missing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_FAMILIES = ("detective", "proactive", "responsive")
_DOC_ONLY_BASENAMES = {
    "compensating-controls-documentation.json",
    "detective-routing.json",
    "citation-coverage.json",
}
# The proactive citation manifest expands into one row per non-JSON rule body.
_PROACTIVE_MANIFEST = "citations.json"


def _manifest_rows(family: str, data: dict) -> list[dict]:
    """Expand a proactive citations.json manifest into per-rule-body rows."""
    rows: list[dict] = []
    for e in data.get("artifacts", []) or []:
        if not isinstance(e, dict):
            continue
        reference = e.get("reference")
        citation = e.get("citation")
        has_ref = isinstance(reference, dict) and reference.get("example_id")
        has_cit = isinstance(citation, dict)
        cit_kind = "canopy_anchor" if (has_cit and citation.get("type") == "canopy") else "doc_anchor"
        if has_ref and has_cit:
            category = f"repo_anchor+{cit_kind}"
        elif has_ref:
            category = "repo_anchor"
        elif has_cit:
            category = cit_kind
        else:
            category = "uncited"
        row = {
            "artifact": f"{family}/{e.get('artifact', '<unnamed>')}",
            "family": family,
            "category": category,
        }
        if has_ref:
            row["reference"] = reference
        if has_cit:
            row["citation"] = citation
        rows.append(row)
    return rows


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _classify(meta: dict) -> tuple[str, dict | None, dict | None]:
    """Return (category, reference, citation) for one artifact's _metadata."""
    status = str(meta.get("status", "")).upper()
    if status in {"NOT_APPLICABLE", "SKIPPED", "GAP"}:
        return "exempt", None, None
    reference = meta.get("reference")
    citation = meta.get("citation")
    has_ref = isinstance(reference, dict) and reference.get("example_id")
    has_cit = isinstance(citation, dict)
    cit_kind = "canopy_anchor" if (has_cit and citation.get("type") == "canopy") else "doc_anchor"
    if has_ref and has_cit:
        return f"repo_anchor+{cit_kind}", reference, citation
    if has_ref:
        return "repo_anchor", reference, None
    if has_cit:
        return cit_kind, None, citation
    return "uncited", None, None


def build_coverage(guidance_dir: Path, service: str = "unknown") -> dict:
    """Build the citation-coverage rollup by walking the guidance families."""
    rows: list[dict] = []
    for family in _FAMILIES:
        fam_dir = guidance_dir / family
        if not fam_dir.is_dir():
            continue
        for fpath in sorted(fam_dir.glob("*.json")):
            if fpath.name in _DOC_ONLY_BASENAMES:
                continue
            data = _load_json(fpath)
            if not isinstance(data, dict):
                continue
            # Proactive manifest → expand into one row per non-JSON rule body.
            if fpath.name == _PROACTIVE_MANIFEST:
                rows.extend(_manifest_rows(family, data))
                continue
            meta = data.get("_metadata")
            if not isinstance(meta, dict):
                rows.append({
                    "artifact": f"{family}/{fpath.name}",
                    "family": family,
                    "category": "uncited",
                    "citation": None,
                })
                continue
            category, reference, citation = _classify(meta)
            row = {
                "artifact": f"{family}/{fpath.name}",
                "family": family,
                "category": category,
            }
            if reference is not None:
                row["reference"] = reference
            if citation is not None:
                row["citation"] = citation
            rows.append(row)

    totals = {
        "artifacts": len(rows),
        "repo_anchor": sum(1 for r in rows if "repo_anchor" in r["category"]),
        "doc_anchor": sum(1 for r in rows if "doc_anchor" in r["category"]),
        "canopy_anchor": sum(1 for r in rows if "canopy_anchor" in r["category"]),
        "exempt": sum(1 for r in rows if r["category"] == "exempt"),
        "uncited": sum(1 for r in rows if r["category"] == "uncited"),
    }
    return {
        "_metadata": {
            "service": service,
            "generated": "service-approval v3.0.0",
            "sources": [f"{f}/" for f in _FAMILIES],
        },
        "totals": totals,
        "artifacts": rows,
    }


def build_for_slug(slug: str, root: Path | None = None) -> dict | None:
    base = (root or Path(os.getcwd())) / ".service-approval" / slug / "05-recommended-guidance"
    if not base.is_dir():
        return None
    # Best-effort service name from a sibling coverage/plan file.
    service = slug
    prev = _load_json(base / "preventive-coverage.json")
    if isinstance(prev, dict):
        service = (prev.get("_metadata") or {}).get("service", slug)
    coverage = build_coverage(base, service)
    (base / "citation-coverage.json").write_text(json.dumps(coverage, indent=2))
    return coverage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--guidance-dir", help="explicit 05-recommended-guidance dir")
    parser.add_argument("--out", help="output path (default: alongside guidance dir)")
    args = parser.parse_args()

    if args.slug:
        coverage = build_for_slug(args.slug)
        if coverage is None:
            print("ERROR: 05-recommended-guidance dir missing", file=sys.stderr)
            return 2
        print(json.dumps(coverage["totals"], indent=2))
        return 0

    if not args.guidance_dir:
        parser.error("provide --slug OR --guidance-dir")
    base = Path(args.guidance_dir)
    if not base.is_dir():
        print(f"ERROR: {base} not a directory", file=sys.stderr)
        return 2
    coverage = build_coverage(base)
    out = Path(args.out) if args.out else base / "citation-coverage.json"
    out.write_text(json.dumps(coverage, indent=2))
    print(json.dumps(coverage["totals"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
