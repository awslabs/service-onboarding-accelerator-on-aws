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

# Banned causal-filler / absolute-overreach phrases. Case-insensitive
# whole-word / whole-phrase matches. The list is intentionally short — the
# goal is to catch obvious overreach, not to police prose. The bare verbs
# (`prevents`/`blocks`/`blocking`/`cannot`) are the overreach actually
# observed in control rationales ("blocks unauthorized calls", "X cannot
# happen"); prefer "constrains"/"supports"/"enforces at request time".
BANNED_PHRASES: tuple[str, ...] = (
    "ensures",
    "guarantees",
    "guarantee",
    "prevents all",
    "prevents",
    "blocks",
    "blocking",
    "cannot",
    "completely blocks",
    "completely prevents",
    "fully mitigates",
    "fully prevents",
    "eliminates",
    "100% effective",
    "always blocks",
    "never allows",
    "confused-deputy",
    "confused deputy",
)

# Compile a single regex that matches any banned phrase as a word boundary
# match (so `ensures` matches but `assures` does not contain it as a
# standalone word, and "censure" doesn't trip).
_BANNED_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(p) for p in BANNED_PHRASES) + r")\b",
    re.IGNORECASE,
)

# `only` is absolute overreach in a control claim ("denies all but X only"),
# but it is also part of legitimate, non-claim text we must NOT flag: the
# coverage-level label "Supportive Only" and the compounds "read-only" /
# "write-only". Fixed-width negative lookbehinds (with IGNORECASE) exclude
# exactly those before matching a standalone `only`.
_ONLY_RE = re.compile(
    r"(?<!supportive )(?<!read-)(?<!write-)\bonly\b",
    re.IGNORECASE,
)

# "denies … untrusted" — a strong claim that a control denies untrusted
# principals/sources. Match `denies` followed by `untrusted` within the same
# sentence (no period between them).
_DENIES_UNTRUSTED_RE = re.compile(
    r"\bdenies\b[^.]*\buntrusted\b",
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

    Returns an empty list when the text is clean. Beyond the fixed
    `BANNED_PHRASES` list, two context-sensitive matchers run: a standalone
    `only` (excluding "Supportive Only" / "read-only" / "write-only") and the
    `denies … untrusted` claim.
    """
    if not text:
        return []
    found = {m.group(0).lower() for m in _BANNED_RE.finditer(text)}
    if _ONLY_RE.search(text):
        found.add("only")
    if _DENIES_UNTRUSTED_RE.search(text):
        found.add("denies … untrusted")
    return sorted(found)


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


# ---------------------------------------------------------------------------
# Rendered-markdown scanning
# ---------------------------------------------------------------------------
# The customer-facing catalog (controls-catalog.md) and the framework crosswalk
# (framework-mapping.md) are re-rendered from the JSON. A render-time re-wording
# that strengthens a claim (JSON says "requires", the .md says "ensures") never
# reaches the JSON-only lint, so the .md must be scanned too.

# A control id as emitted by map-generate-controls.
_CTRL_ID_RE = re.compile(r"CTRL-(?:ORG|ACC|RES)-(?:PRO|PRV|DET|COR)-\d{3}")

# Catalog per-control prose bullets (the free-text lines under a control
# header). The bold label may carry the colon inside (`**Description:**`) or
# outside (`**Description**:`) the asterisks — accept either.
_CATALOG_PROSE_BULLET_RE = re.compile(
    r"^\s*-\s*\*\*(?:Description|Implementation|Governs|Security Rationale)\s*:?\s*\*\*\s*:?",
    re.IGNORECASE,
)


def _md_control_prose_lines(md_text: str):
    """Yield (control_id, line) for each per-control prose line in a rendered map .md.

    "Per-control prose" is scoped deliberately so structural/template text is
    NOT linted: only (a) table rows that name a control id (mapping + MITRE
    crosswalk rows carry the description/rationale columns) and (b) catalog
    bullets (Description / Implementation / Governs / Security Rationale) under
    the nearest preceding control header. Objective-level N/A reasons,
    coverage-level labels, and section headers are skipped — they are not
    per-control claims and legitimately use words like "cannot"/"only".
    """
    current: str | None = None
    for raw in md_text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("#"):
            m = _CTRL_ID_RE.search(stripped)
            if m:
                current = m.group(0)
            continue
        ids_in_line = _CTRL_ID_RE.findall(raw)
        if ids_in_line:
            yield ids_in_line[0], raw
        elif _CATALOG_PROSE_BULLET_RE.match(raw) and current:
            yield current, raw


def lint_markdown_prose(md_text: str) -> list[tuple[str, LintFinding]]:
    """Return (control_id, finding) for banned phrases in rendered map .md prose.

    Scans only per-control prose lines (see `_md_control_prose_lines`).
    """
    results: list[tuple[str, LintFinding]] = []
    for cid, line in _md_control_prose_lines(md_text):
        banned = find_banned_phrases(line)
        if banned:
            results.append((
                cid,
                LintFinding(
                    field="markdown",
                    kind="banned_phrase",
                    detail=(
                        f"rendered .md prose for {cid} contains causal-filler / "
                        f"overreach phrase(s): {', '.join(banned)}. Keep the "
                        "customer-facing prose broad and objective-level."
                    ),
                    excerpt=line.strip()[:120],
                ),
            ))
    return results


def _banned_by_control_from_json(mapping: dict) -> dict[str, set[str]]:
    """Map each control_id → the set of banned phrases present in its SOURCE
    JSON prose (description / security_rationale / rationale / name)."""
    out: dict[str, set[str]] = {}

    def add(cid: str | None, text) -> None:
        if not cid or not isinstance(text, str):
            return
        b = find_banned_phrases(text)
        if b:
            out.setdefault(cid, set()).update(b)

    for control in mapping.get("controls", []) or []:
        cid = control.get("control_id") or control.get("id")
        for k in ("description", "security_rationale", "rationale", "name"):
            add(cid, control.get(k))
    for obj in mapping.get("framework_mapping", []) or []:
        for control in obj.get("controls", []) or []:
            cid = control.get("control_id")
            for k in ("description", "security_rationale", "rationale"):
                add(cid, control.get(k))
    return out


def find_md_divergences(md_text: str, mapping: dict) -> list[tuple[str, LintFinding]]:
    """Return (control_id, finding) for upward re-wording at render time.

    A banned/stronger word that appears in the rendered .md prose for a control
    but is ABSENT from that control's source JSON prose is a render-time
    over-claim — the .md must never make a claim stronger than its source.
    """
    json_banned = _banned_by_control_from_json(mapping)
    results: list[tuple[str, LintFinding]] = []
    for cid, line in _md_control_prose_lines(md_text):
        md_banned = set(find_banned_phrases(line))
        if not md_banned:
            continue
        introduced = sorted(md_banned - json_banned.get(cid, set()))
        if introduced:
            results.append((
                cid,
                LintFinding(
                    field="markdown",
                    kind="divergence",
                    detail=(
                        f"rendered .md introduces stronger word(s) {introduced} for "
                        f"{cid} that are absent from the source JSON rationale — do "
                        "not re-word upward at render time; the .md must not make a "
                        "claim stronger than the JSON."
                    ),
                    excerpt=line.strip()[:120],
                ),
            ))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint of control prose (JSON + rendered .md).")
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

    # Scan the rendered .md siblings too: catch banned phrases and upward
    # re-wording that never reach the JSON.
    map_dir = mapping_path.parent
    for md_name in ("controls-catalog.md", "framework-mapping.md"):
        md_path = map_dir / md_name
        if not md_path.exists():
            continue
        md_text = md_path.read_text()
        for cid, f in lint_markdown_prose(md_text):
            results.append((f"{md_name}:{cid}", f))
        for cid, f in find_md_divergences(md_text, mapping):
            results.append((f"{md_name}:{cid}", f))

    if not results:
        print(f"lint_control_prose: {mapping_path} (+ rendered .md) — no findings")
        return 0

    for cid, f in results:
        print(f"  [{cid}] {f.field} ({f.kind}): {f.detail}")
    print(f"lint_control_prose: {len(results)} finding(s)")
    return 2 if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
