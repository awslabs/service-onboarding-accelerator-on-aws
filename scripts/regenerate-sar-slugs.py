#!/usr/bin/env python3
"""Regenerate sar-slugs.json by scraping the SAR landing page.

Updates both:
  - input/sar-slugs.json
  - data/sar-slugs.json

Usage:
    python3 scripts/regenerate-sar-slugs.py [--check]

With --check, exits non-zero if the generated output differs from the files
on disk (for CI).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

SAR_LANDING_URL = (
    "https://docs.aws.amazon.com/service-authorization/latest/reference/"
    "reference_policies_actions-resources-contextkeys.html"
)
LIST_HREF_RE = re.compile(r"(?:^|/)list_([a-z0-9._\-]+)\.html$", re.IGNORECASE)
REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS = [
    REPO_ROOT / "input" / "sar-slugs.json",
    REPO_ROOT / "service-approval-plugin" / "data" / "sar-slugs.json",
]


class SarLinkParser(HTMLParser):
    """Extract (display_name, slug) pairs from <a href="...list_<slug>.html">Name</a>."""

    def __init__(self) -> None:
        super().__init__()
        self.entries: dict[str, str] = {}
        self._current_slug: str | None = None
        self._buffer: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        match = LIST_HREF_RE.search(href)
        if match:
            self._current_slug = match.group(1)
            self._buffer = []

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or self._current_slug is None:
            return
        name = " ".join("".join(self._buffer).split()).strip()
        if name:
            existing = self.entries.get(name)
            if existing and existing != self._current_slug:
                print(
                    f"WARN: duplicate display name '{name}' with conflicting slugs "
                    f"({existing!r} vs {self._current_slug!r}); keeping first",
                    file=sys.stderr,
                )
            else:
                self.entries[name] = self._current_slug
        self._current_slug = None
        self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._current_slug is not None:
            self._buffer.append(data)


def fetch_sar_landing(url: str = SAR_LANDING_URL) -> str:
    # Refuse non-https schemes (file://, ftp://, etc.) — Bandit B310.
    scheme = urlparse(url).scheme.lower()
    if scheme != "https":
        raise ValueError(f"refusing to fetch non-https URL (scheme={scheme!r})")
    req = urllib.request.Request(url, headers={"User-Agent": "service-onboarding-sar-slugs/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310  # noqa: S310 - scheme validated above
        return resp.read().decode("utf-8", errors="replace")


def scrape_slugs(html: str) -> dict[str, str]:
    parser = SarLinkParser()
    parser.feed(html)
    # Sort case-insensitively to match existing file layout
    return dict(sorted(parser.entries.items(), key=lambda kv: kv[0].lower()))


def serialize(slugs: dict[str, str]) -> str:
    return json.dumps(slugs, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if files on disk differ from scraped output",
    )
    args = ap.parse_args()

    html = fetch_sar_landing()
    slugs = scrape_slugs(html)
    if len(slugs) < 100:
        print(
            f"ERROR: only scraped {len(slugs)} slugs — page format may have changed",
            file=sys.stderr,
        )
        return 2

    content = serialize(slugs)
    drift = False
    for path in TARGETS:
        existing = path.read_text() if path.exists() else ""
        if existing == content:
            print(f"unchanged: {path.relative_to(REPO_ROOT)} ({len(slugs)} slugs)")
            continue
        drift = True
        if args.check:
            print(f"DRIFT: {path.relative_to(REPO_ROOT)}", file=sys.stderr)
            continue
        path.write_text(content)
        print(f"wrote: {path.relative_to(REPO_ROOT)} ({len(slugs)} slugs)")

    return 1 if (args.check and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
