#!/usr/bin/env python3
"""
Control-conflict pre-filter (deterministic candidate finder).

The conflict/contradiction check has two parts:
  1. This deterministic pre-filter scans the generated control set for PAIRS that
     might contradict each other and emits a candidate list.
  2. A clean LLM subagent (dispatched by the orchestrator, no prior context)
     confirms/explains each candidate and writes the final conflict-report.json.

Code can't reason about semantic contradiction in general, but it CAN cheaply
surface the obvious structural candidates so the judge has a focused set instead
of the full N^2 cross-product. This module is that pre-filter.

Candidate kinds surfaced (same gated action, opposing posture):
  - "deny_vs_allow": an SCP/RCP/IAM Deny on an action that another artifact's
    Allow explicitly grants (the Deny may invalidate a control that assumes the
    action is permitted).
  - "incompatible_conditions": two Deny statements gating the SAME action with
    DIFFERENT condition keys (they may impose contradictory requirements).

The judge decides whether a candidate is a real conflict; the pre-filter only
narrows the search. Both deny-vs-allow across the cross-product and condition
divergence are intentionally broad — false positives are fine (the judge filters
them); false negatives are not.

CLI:
    python3 detect_control_conflicts.py --slug <slug>   # prints candidate JSON
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Vendored/build directories to skip when walking artifact trees.
SKIP_DIRS = {"node_modules", ".git", "cdk.out", "__pycache__", ".terraform", ".venv"}


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _norm_action(a: str) -> str:
    return a.strip().lower() if isinstance(a, str) else ""


def _statements(data: dict) -> list[dict]:
    s = data.get("Statement")
    if isinstance(s, dict):
        return [s]
    if isinstance(s, list):
        return [x for x in s if isinstance(x, dict)]
    return []


def _actions(stmt: dict) -> list[str]:
    a = stmt.get("Action")
    if isinstance(a, str):
        return [a]
    if isinstance(a, list):
        return [x for x in a if isinstance(x, str)]
    return []


def _condition_keys(stmt: dict) -> set[str]:
    keys: set[str] = set()
    cond = stmt.get("Condition")
    if isinstance(cond, dict):
        for op_map in cond.values():
            if isinstance(op_map, dict):
                keys.update(k.lower() for k in op_map.keys())
    return keys


def _collect_policy_statements(generate_dir: Path) -> list[dict]:
    """Collect {file, sid, effect, actions[], condition_keys[]} for every policy
    statement under 05-recommended-guidance/ (preventive + proactive JSON policies)."""
    out: list[dict] = []
    if not generate_dir.is_dir():
        return out
    for p in sorted(generate_dir.rglob("*.json")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        data = _load_json(p)
        if not isinstance(data, dict) or "Statement" not in data:
            continue
        rel = str(p.relative_to(generate_dir))
        for i, stmt in enumerate(_statements(data)):
            effect = stmt.get("Effect")
            if effect not in ("Allow", "Deny"):
                continue
            out.append({
                "file": rel,
                "sid": stmt.get("Sid", f"[{i}]"),
                "effect": effect,
                "actions": [_norm_action(a) for a in _actions(stmt)],
                "condition_keys": sorted(_condition_keys(stmt)),
            })
    return out


def _action_pair_overlaps(a: list[str], b: list[str]) -> list[str]:
    """Actions shared between two statements, treating a bare `*` or
    `prefix:*` glob as matching any action under that prefix."""
    shared: set[str] = set()
    sa, sb = set(a), set(b)
    # exact matches
    shared |= sa & sb
    # glob matches: prefix:* matches prefix:anything
    for x in sa:
        if x.endswith(":*"):
            pref = x[:-1]  # keep trailing colon
            shared |= {y for y in sb if y.startswith(pref)}
    for y in sb:
        if y.endswith(":*"):
            pref = y[:-1]
            shared |= {x for x in sa if x.startswith(pref)}
    # drop the globs themselves from the reported overlap (report concrete actions)
    return sorted(s for s in shared if not s.endswith(":*"))


def find_candidates(statements: list[dict]) -> list[dict]:
    """Return candidate conflict pairs for the judge to confirm."""
    candidates: list[dict] = []
    n = len(statements)
    for i in range(n):
        for j in range(i + 1, n):
            s1, s2 = statements[i], statements[j]
            overlap = _action_pair_overlaps(s1["actions"], s2["actions"])
            if not overlap:
                continue
            effects = {s1["effect"], s2["effect"]}
            if effects == {"Allow", "Deny"}:
                candidates.append({
                    "a": f"{s1['file']}#{s1['sid']}",
                    "b": f"{s2['file']}#{s2['sid']}",
                    "kind": "deny_vs_allow",
                    "shared_actions": overlap,
                    "explanation": (
                        "one statement denies an action the other allows; the deny "
                        "may invalidate a control that assumes the action is permitted"
                    ),
                })
            elif effects == {"Deny"}:
                k1, k2 = set(s1["condition_keys"]), set(s2["condition_keys"])
                if k1 != k2:
                    candidates.append({
                        "a": f"{s1['file']}#{s1['sid']}",
                        "b": f"{s2['file']}#{s2['sid']}",
                        "kind": "incompatible_conditions",
                        "shared_actions": overlap,
                        "explanation": (
                            "two denies gate the same action with different condition "
                            f"keys ({sorted(k1)} vs {sorted(k2)}); they may impose "
                            "contradictory requirements"
                        ),
                    })
    return candidates


def build_prefilter_report(service_root: Path) -> dict:
    """Build the candidate-only conflict report (judge fills in verdicts)."""
    generate_dir = service_root / "05-recommended-guidance"
    statements = _collect_policy_statements(generate_dir)
    candidates = find_candidates(statements)
    return {
        "_metadata": {
            "service": service_root.name,
            "generated": "service-approval v3.0.0",
            "stage": "prefilter",
        },
        "statements_scanned": len(statements),
        "candidates": candidates,
        "pairs": [],
        "verdict": "PENDING_JUDGE",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slug", required=True, help="service slug under .service-approval/")
    args = parser.parse_args()
    root = Path(os.getcwd()) / ".service-approval" / args.slug
    report = build_prefilter_report(root)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
