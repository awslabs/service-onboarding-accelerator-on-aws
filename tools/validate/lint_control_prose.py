"""Lint for control description / rationale prose.

The map-generate-controls and map-framework-mapping skills emit free-text
strings (control `description`, control `security_rationale`, mapped-
objective `rationale`). The "state only what is verified" authoring rule
asks authors to keep these strings broad and objective-level.

This lint surfaces two kinds of drift:

1. **Length budget.** Strings longer than the budget tend to pile up
   speculative specifics — exact attack chains, exact action lists, causal
   guarantees that aren't supported by the input data.

2. **Banned causal-filler phrases.** A short closed list of words that
   over-claim what a single control does. `ensures`, `guarantees`,
   `prevents all`, `completely`, `fully mitigates`, `eliminates`, etc.

The lint is advisory by default — it returns a list of findings rather
than raising. Callers (validators, CI) can decide whether to block.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
import re

# Default per-string budget. Most usefully-broad rationales fit in 200
# characters; longer strings are almost always speculative drift. The
# generated `description` field is allowed a slightly looser budget.
DEFAULT_RATIONALE_BUDGET = 200
DEFAULT_DESCRIPTION_BUDGET = 280

# Banned causal-filler phrases. These are case-insensitive whole-word /
# whole-phrase matches. The list is intentionally short — the goal is to
# catch obvious overreach, not to police prose.
BANNED_PHRASES: tuple[str, ...] = (
    "ensures",
    "guarantees",
    "guarantee",
    "prevents all",
    "completely blocks",
    "completely prevents",
    "fully mitigates",
    "fully prevents",
    "eliminates",
    "100% effective",
    "always blocks",
    "never allows",
)

# Compile a single regex that matches any banned phrase as a word boundary
# match (so `ensures` matches but `assures` does not contain it as a
# standalone word, and "censure" doesn't trip).
_BANNED_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in BANNED_PHRASES) + r")\b",
    re.IGNORECASE,
)


@dataclass
class LintFinding:
    """One finding emitted by lint_control_prose."""

    field: str  # e.g. "description", "security_rationale", "rationale"
    kind: str  # "length" | "banned_phrase"
    detail: str  # human-readable explanation
    excerpt: str  # the offending substring (or the whole string for length)


def find_banned_phrases(text: str) -> list[str]:
    """Return the list of distinct banned phrases that appear in `text`.

    Returns an empty list when the text is clean.
    """
    if not text:
        return []
    return sorted({m.group(0).lower() for m in _BANNED_RE.finditer(text)})


def lint_control_prose(
    control: dict,
    rationale_budget: int = DEFAULT_RATIONALE_BUDGET,
    description_budget: int = DEFAULT_DESCRIPTION_BUDGET,
) -> list[LintFinding]:
    """Lint a single control's prose strings.

    Looks at `description`, `security_rationale`, and (when present) any
    nested `rationale` strings on framework-objective control mappings.
    Returns a list of LintFinding; empty list means the control is clean.
    """
    findings: list[LintFinding] = []

    fields_to_check: list[tuple[str, str, int]] = []
    if isinstance(control.get("description"), str):
        fields_to_check.append(
            ("description", control["description"], description_budget)
        )
    if isinstance(control.get("security_rationale"), str):
        fields_to_check.append(
            ("security_rationale", control["security_rationale"], rationale_budget)
        )
    # framework-mapping output nests `controls[].rationale`
    if isinstance(control.get("rationale"), str):
        fields_to_check.append(("rationale", control["rationale"], rationale_budget))

    for field, value, budget in fields_to_check:
        if len(value) > budget:
            findings.append(
                LintFinding(
                    field=field,
                    kind="length",
                    detail=(
                        f"{field} is {len(value)} chars (budget {budget}); "
                        "over-long prose tends to pile up speculative "
                        "specifics — broaden to objective level."
                    ),
                    excerpt=value[:80] + ("..." if len(value) > 80 else ""),
                )
            )
        banned = find_banned_phrases(value)
        if banned:
            findings.append(
                LintFinding(
                    field=field,
                    kind="banned_phrase",
                    detail=(
                        f"{field} contains causal-filler phrase(s): "
                        f"{', '.join(banned)}. A single control rarely "
                        "ensures/guarantees/eliminates anything in the "
                        "absolute — hedge to what is verified."
                    ),
                    excerpt=value[:80] + ("..." if len(value) > 80 else ""),
                )
            )

    return findings


def lint_mapping_file(mapping: dict) -> list[tuple[str, LintFinding]]:
    """Lint every control in a mapping-results.json-shaped dict.

    Returns (control_id, finding) pairs across the top-level `controls[]`
    and any nested `framework_mapping[].controls[]` rationales.
    """
    results: list[tuple[str, LintFinding]] = []
    for control in mapping.get("controls", []) or []:
        cid = control.get("control_id", "<unknown>")
        for f in lint_control_prose(control):
            results.append((cid, f))
    for obj in mapping.get("framework_mapping", []) or []:
        for control in obj.get("controls", []) or []:
            cid = control.get("control_id", obj.get("objective_id", "<unknown>"))
            for f in lint_control_prose(control):
                results.append((cid, f))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Advisory lint of control prose.")
    parser.add_argument("--slug", help="service slug under .service-approval/")
    parser.add_argument("--mapping", help="explicit path to mapping-results.json")
    parser.add_argument(
        "--strict", action="store_true",
        help="exit 2 if any finding is reported (default: advisory, exit 0)",
    )
    args = parser.parse_args()

    if args.mapping:
        mapping_path = Path(args.mapping)
    elif args.slug:
        mapping_path = Path(
            f".service-approval/{args.slug}/04-map/mapping-results.json"
        )
    else:
        print("ERROR: pass --slug or --mapping", file=sys.stderr)
        return 2

    if not mapping_path.exists():
        print(f"lint_control_prose: {mapping_path} not found — nothing to lint")
        return 0

    mapping = json.loads(mapping_path.read_text())
    results = lint_mapping_file(mapping)
    if not results:
        print(f"lint_control_prose: {mapping_path} — no findings")
        return 0

    for cid, f in results:
        print(f"  [{cid}] {f.field} ({f.kind}): {f.detail}")
    print(f"lint_control_prose: {len(results)} advisory finding(s)")
    return 2 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
