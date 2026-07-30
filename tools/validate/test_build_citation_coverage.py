"""Tests for build_citation_coverage.py — the citation-coverage rollup."""
from __future__ import annotations

import json
from pathlib import Path

import build_citation_coverage as bcc


_GOOD_DOC = {
    "type": "aws_doc",
    "title": "AWS Config Managed Rules — efs-encrypted-check",
    "url": "https://docs.aws.amazon.com/config/latest/developerguide/efs-encrypted-check.html",
    "verified_via": "mcp",
}
_GOOD_REF = {
    "example_id": "efs-encryption-check",
    "repo": "aws-config-custom-policy-rule-samples",
    "url": "https://github.com/aws-samples/x/blob/sha/y.guard",
}


def _mk(tmp_path: Path) -> Path:
    guidance = tmp_path / "05-recommended-guidance"
    for fam in ("detective", "proactive", "responsive"):
        (guidance / fam).mkdir(parents=True)
    return guidance


def _w(p: Path, obj: dict):
    p.write_text(json.dumps(obj))


def test_totals_and_buckets(tmp_path):
    g = _mk(tmp_path)
    _w(g / "detective" / "config-rules.json", {"_metadata": {"citation": _GOOD_DOC}})
    _w(g / "detective" / "config-org-rules.json", {"_metadata": {"reference": _GOOD_REF}})
    _w(g / "proactive" / "cfn-hooks-policy.json", {"_metadata": {"reference": _GOOD_REF, "citation": _GOOD_DOC}})
    _w(g / "responsive" / "ssm-runbook-reference.json", {"_metadata": {"citation": _GOOD_DOC}})
    _w(g / "detective" / "skip.json", {"_metadata": {"status": "NOT_APPLICABLE"}})
    _w(g / "proactive" / "uncited.json", {"_metadata": {}})

    cov = bcc.build_coverage(g, service="lambda")
    t = cov["totals"]
    assert t["artifacts"] == 6
    assert t["doc_anchor"] == 3          # config-rules, cfn-hooks, ssm-runbook-reference
    assert t["repo_anchor"] == 2         # config-org-rules, cfn-hooks
    assert t["exempt"] == 1              # skip.json
    assert t["uncited"] == 1             # uncited.json


def test_doc_only_basenames_skipped(tmp_path):
    g = _mk(tmp_path)
    _w(g / "detective" / "compensating-controls-documentation.json", {"x": 1})
    _w(g / "detective" / "detective-routing.json", {"routed": []})
    cov = bcc.build_coverage(g)
    assert cov["totals"]["artifacts"] == 0


def test_build_for_slug_writes_file(tmp_path):
    root = tmp_path
    g = _mk(root / ".service-approval" / "lambda")
    _w(g / "detective" / "config-rules.json", {"_metadata": {"citation": _GOOD_DOC}})
    cov = bcc.build_for_slug("lambda", root=root)
    assert cov is not None
    out = g / "citation-coverage.json"
    assert out.is_file()
    written = json.loads(out.read_text())
    assert written["totals"]["doc_anchor"] == 1
