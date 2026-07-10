#!/usr/bin/env python3
"""Semantically anchor a custom / non-CCMv4 framework's objectives to CCMv4.

When the active framework has no `data/domain-mapping-guidance/<fw>.json` of its
own, the per-domain mapping guidance (allow/deny classes, coverage ceilings,
applicability) has nothing to key on. Rather than fall back to an unconstrained
single pass, anchor each custom objective to its nearest CCMv4 objective(s) by
DESCRIPTION (not by ID) and reuse that CCMv4 objective's guidance.

The match is deterministic and reproducible — a TF-IDF cosine over the custom
objective's title+specification text against every CCMv4 objective's title+intent
text (built from data/domain-mapping-guidance/ccmv4.json). No embedding model, no
LLM, so the same inputs always produce the same anchors.

Output `custom_to_ccmv4_anchor.json`:
    {
      "schema_version": "1.0",
      "framework": "<active framework name>",
      "threshold": 0.7,
      "anchors": {
        "<custom_objective_id>": {
          "ccmv4_ids": ["CEK-03", ...],          # ranked best-first
          "anchor_score": 0.81,                    # cosine of the best match
          "status": "anchored" | "uncertain"      # >= threshold vs below
        }, ...
      }
    }

A custom objective whose best match scores below the threshold is marked
`uncertain` — the mapper maps it UNCERTAIN and flags it for review rather than
force-fitting the nearest (weak) CCMv4 guidance onto it.

Usage:
    python3 scripts/anchor-custom-framework.py --slug <slug> [--threshold 0.7]
    python3 scripts/anchor-custom-framework.py <map-framework-parsed.json> \
        [--output <path>] [--threshold 0.7]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CCMV4_GUIDANCE = _REPO_ROOT / "data" / "domain-mapping-guidance" / "ccmv4.json"
_DEFAULT_THRESHOLD = 0.7

# Generic tokens that carry no discriminating signal for a control objective.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "for", "in", "on", "by", "with",
    "is", "are", "be", "as", "that", "this", "it", "its", "at", "from", "must",
    "shall", "should", "requires", "require", "required", "control", "controls",
    "policy", "procedures", "process", "objective", "establish", "documented",
    "maintain", "maintained", "ensure", "provide", "including", "such", "which",
    "their", "they", "any", "all", "not", "no", "per", "via", "using", "use",
}
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall((text or "").lower())
            if t not in _STOPWORDS and len(t) > 2]


def _ccmv4_docs() -> dict[str, str]:
    """CCMv4 objective_id -> title + intent text (the anchor corpus)."""
    kb = json.loads(_CCMV4_GUIDANCE.read_text())
    docs: dict[str, str] = {}
    for d in kb.get("domains", []):
        for o in d.get("objectives", []):
            oid = o.get("objective_id")
            if oid:
                docs[oid] = f"{o.get('title', '')} {o.get('intent', '')}"
    return docs


def _build_idf(all_token_lists: list[list[str]]) -> dict[str, float]:
    """Smoothed inverse-document-frequency over the corpus + queries combined."""
    n = len(all_token_lists)
    df: Counter = Counter()
    for toks in all_token_lists:
        for t in set(toks):
            df[t] += 1
    return {t: math.log((n + 1) / (c + 1)) + 1.0 for t, c in df.items()}


def _tfidf_vec(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = Counter(tokens)
    return {t: tf[t] * idf.get(t, 0.0) for t in tf}


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    dot = sum(a[t] * b[t] for t in common)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _objective_text(o: dict) -> str:
    return " ".join(str(o.get(k, "")) for k in ("title", "specification", "domain"))


def _objective_id(o: dict) -> str:
    return o.get("objective_id") or o.get("id") or ""


def anchor_objectives(
    custom_objectives: list[dict],
    threshold: float = _DEFAULT_THRESHOLD,
    top_k: int = 2,
) -> dict[str, dict]:
    """Anchor each custom objective to its nearest CCMv4 objective(s).

    Returns custom_id -> {ccmv4_ids[], anchor_score, status}. The IDF is built
    over the CCMv4 corpus plus the custom queries so discriminative tokens are
    weighted the same for both sides. Deterministic — ties broken by CCMv4 id.
    """
    ccmv4 = _ccmv4_docs()
    ccmv4_ids = sorted(ccmv4)
    ccmv4_tokens = {cid: _tokens(ccmv4[cid]) for cid in ccmv4_ids}

    query_tokens = {
        _objective_id(o): _tokens(_objective_text(o))
        for o in custom_objectives if _objective_id(o)
    }

    idf = _build_idf(list(ccmv4_tokens.values()) + list(query_tokens.values()))
    ccmv4_vecs = {cid: _tfidf_vec(ccmv4_tokens[cid], idf) for cid in ccmv4_ids}

    anchors: dict[str, dict] = {}
    for qid, qtoks in query_tokens.items():
        qvec = _tfidf_vec(qtoks, idf)
        # (-score, cid) sort → best score first, ties broken by cid ascending.
        scored = sorted(
            ((_cosine(qvec, ccmv4_vecs[cid]), cid) for cid in ccmv4_ids),
            key=lambda sc: (-sc[0], sc[1]),
        )
        best_score = round(scored[0][0], 4) if scored else 0.0
        top = [cid for score, cid in scored[:top_k] if score > 0.0]
        anchors[qid] = {
            "ccmv4_ids": top,
            "anchor_score": best_score,
            "status": "anchored" if best_score >= threshold else "uncertain",
        }
    return anchors


def _load_json(path: Path):
    with open(path) as fh:
        return json.load(fh)


def build_result(parsed: dict, threshold: float) -> dict:
    objectives = parsed.get("framework_objectives", [])
    framework = (parsed.get("framework") or {})
    anchors = anchor_objectives(objectives, threshold)
    anchored = sum(1 for a in anchors.values() if a["status"] == "anchored")
    return {
        "schema_version": "1.0",
        "framework": framework.get("name") or parsed.get("framework_name") or "custom",
        "threshold": threshold,
        "anchors": anchors,
        "summary": {
            "total": len(anchors),
            "anchored": anchored,
            "uncertain": len(anchors) - anchored,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("parsed", nargs="?", help="path to map-framework-parsed.json")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--output", "-o", help="output path")
    parser.add_argument("--threshold", type=float, default=_DEFAULT_THRESHOLD,
                        help=f"anchor score threshold (default {_DEFAULT_THRESHOLD})")
    args = parser.parse_args()

    if args.slug:
        map_dir = Path.cwd() / ".service-approval" / args.slug / "04-map"
        parsed_path = map_dir / "map-framework-parsed.json"
        out_path: Path | None = map_dir / "custom_to_ccmv4_anchor.json"
    elif args.parsed:
        parsed_path = Path(args.parsed)
        out_path = Path(args.output) if args.output else None
    else:
        parser.error("provide map-framework-parsed.json OR --slug")
        return 2

    if not parsed_path.exists():
        print(f"SKIP: {parsed_path} not found", file=sys.stderr)
        return 0

    parsed = _load_json(parsed_path)
    # CCMv4 is anchored to itself — no need to run for the native framework.
    fw_name = ((parsed.get("framework") or {}).get("name") or "").lower()
    if "ccmv4" in fw_name or "ccm v4" in fw_name:
        print("custom-anchor: active framework is CCMv4 — no anchoring needed.",
              file=sys.stderr)
        return 0

    result = build_result(parsed, args.threshold)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        s = result["summary"]
        print(f"Custom anchor written: {out_path}\n"
              f"  Objectives: {s['total']} (anchored={s['anchored']}, "
              f"uncertain={s['uncertain']})", file=sys.stderr)
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
