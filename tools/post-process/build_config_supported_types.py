#!/usr/bin/env python3
"""
Regenerate data/config-supported-resource-types.json — the set of CloudFormation
resource types AWS Config can record.

## Why this exists

Some services/resources are not recordable by AWS Config, so authoring a Config
rule for them is a no-op. The detective generator gates Config-rule emission on
this list (validate_config_support.py + integrity check P13): a Config rule is
never emitted for an unsupported resource type — those controls route to
CloudTrail / EventBridge or record a reasoned gap instead.

## Sources (two, unioned)

1. **botocore `config` service model — the `ResourceType` enum (authoritative
   machine source).** The AWS SDK model at
   `botocore/data/config/<version>/service-2.json.gz` ships an enum of every
   resource type `PutConfigurationRecorder` / the recorder API accepts. This is a
   real SDK enumeration — preferred over doc scraping, offline, deterministic.
   Its one weakness is freshness: the pinned botocore can lag the doc by a month
   or two (newly-supported types land in the doc first).

2. **Public doc additions — AWS Config "Supported Resource Types" reference.**
   `https://docs.aws.amazon.com/config/latest/developerguide/resource-config-reference.html`
   is the freshest source of truth and is updated monthly. Types confirmed
   present in that doc via the `aws-documentation` MCP but not yet in the pinned
   SDK enum are carried in `_doc_additions` (with the doc URL as provenance) and
   unioned into `supported`. This keeps the gate correct for just-launched
   services (e.g. AWS::DSQL::Cluster) without waiting for an SDK bump.

Provenance in the output file is public (SDK model + public doc URL), so it is
allowed under the provenance rule.

## Refreshing

    python3 tools/post-process/build_config_supported_types.py

To add a doc-confirmed type the SDK enum still lacks, MCP-verify it against the
resource-config-reference page (search_table for the type), then add it to
DOC_ADDITIONS below with the harvest date. Re-run this script.

Freshness caveat: the SDK enum reflects the pinned botocore version; the doc is
updated monthly. Re-run after a botocore bump or when a newly-launched service's
resource type must be gated.
"""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import botocore

# Public doc URL — the freshest source of truth, cited as provenance.
_DOC_URL = (
    "https://docs.aws.amazon.com/config/latest/developerguide/"
    "resource-config-reference.html"
)

# Types confirmed present in the resource-config-reference doc (via the
# aws-documentation MCP) but not yet in the pinned botocore ResourceType enum.
# Each carries the date it was doc-verified. Keep this list minimal — only add a
# type after MCP-verifying it against the doc; the SDK enum covers the rest.
DOC_ADDITIONS: dict[str, str] = {
    # AWS::DSQL::Cluster is listed in the resource-config-reference doc (verified
    # 2026-07-30 via aws-documentation search_table) but is absent from the
    # botocore 1.43.x ResourceType enum — a doc-ahead-of-SDK case.
    "AWS::DSQL::Cluster": "2026-07-30",
}

_OUT = Path(__file__).resolve().parents[2] / "data" / "config-supported-resource-types.json"


def _botocore_config_enum() -> list[str]:
    """Return the ResourceType enum from the pinned botocore config model."""
    base = os.path.join(
        os.path.dirname(botocore.__file__), "data", "config", "2014-11-12"
    )
    model_gz = os.path.join(base, "service-2.json.gz")
    with gzip.open(model_gz) as fh:
        model = json.load(fh)
    enum = model.get("shapes", {}).get("ResourceType", {}).get("enum", [])
    return [v for v in enum if isinstance(v, str) and v.startswith("AWS::")]


def build(harvested: str) -> dict:
    """Assemble the config-supported-resource-types.json payload.

    `harvested` is the ISO date the doc additions were verified; passed in
    (Date.now() is unavailable in some execution contexts) so the output is
    deterministic and re-runnable.
    """
    sdk_enum = _botocore_config_enum()
    supported = sorted(set(sdk_enum) | set(DOC_ADDITIONS))
    return {
        "_provenance": {
            "sdk_source": "botocore config service-2 model — shapes.ResourceType.enum",
            "botocore_version": botocore.__version__,
            "doc_url": _DOC_URL,
            "doc_note": (
                "The public resource-config-reference doc is the freshest source "
                "of truth (updated monthly). Types confirmed in the doc via the "
                "aws-documentation MCP but not yet in the pinned SDK enum are "
                "listed in _doc_additions and unioned into supported."
            ),
            "harvested": harvested,
        },
        "_doc_additions": DOC_ADDITIONS,
        "supported": supported,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--harvested",
        default="2026-07-30",
        help="ISO date the doc additions were MCP-verified (recorded as provenance)",
    )
    args = parser.parse_args()

    payload = build(args.harvested)
    _OUT.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"Wrote {_OUT} — {len(payload['supported'])} Config-supported resource "
        f"types (botocore {botocore.__version__} + {len(DOC_ADDITIONS)} doc "
        f"additions)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
