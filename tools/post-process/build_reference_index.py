#!/usr/bin/env python3
"""
Build the reference-repo anchor index from locally-cloned AWS sample repos.

Preventive control generation is repo-anchored: every emitted SCP / RCP / IAM
policy / permission boundary must trace to a known-good example published by AWS
(AWS Samples / awslabs). This tool walks a set of locally-cloned reference repos,
extracts each example policy, normalizes the facts the skills need to anchor
against (mechanism, governed actions, condition keys, intent), and writes:

    data/reference-repos/index.yaml              # the catalog the skills read
    data/reference-repos/<repo-slug>/examples/   # extracted policy bodies

The pipeline NEVER browses these repos live at generation time — it reads the
committed index. This tool is run once to seed the index and on demand to
refresh it against newer commits.

Licensing: most reference repos are MIT / MIT-0 / Apache-2.0, so the policy body
is vendored verbatim. Repos under a share-alike license (CC-BY-SA) are recorded
*facts-only* — actions and condition keys (uncopyrightable facts) plus a pointer
URL — with no vendored body, to avoid a license conflict with this repo's
Apache-2.0 license. The per-repo `vendor_bodies` flag controls this.

Usage:
    # Seed/refresh the index from a directory of cloned repos:
    python3 tools/post-process/build_reference_index.py --repos-dir /path/to/clones

    # Verify the committed index matches what the tool would produce (CI):
    python3 tools/post-process/build_reference_index.py --repos-dir /path/to/clones --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Repo registry — the anchor library.
#
# Each entry declares how to walk one cloned repo. `vendor_bodies` is False for
# share-alike-licensed repos (facts only, no vendored policy text).
#   slug          : repo name (the clone directory name under --repos-dir)
#   owner         : GitHub org
#   mechanism     : default mechanism for examples from this repo
#   license       : SPDX-ish label (informational; drives vendor_bodies default)
#   vendor_bodies : copy the policy JSON into the index, or facts-only
#   globs         : file patterns to treat as example policy documents
#   md_policy     : if True, extract JSON fenced as ```json in .md files
# ---------------------------------------------------------------------------
REPO_REGISTRY: list[dict] = [
    {
        "slug": "service-control-policy-examples",
        "owner": "aws-samples",
        "mechanism": "SCP",
        "license": "MIT",
        "vendor_bodies": True,
        "globs": ["**/*.json"],
    },
    {
        "slug": "resource-control-policy-examples",
        "owner": "aws-samples",
        "mechanism": "RCP",
        "license": "MIT",
        "vendor_bodies": True,
        "globs": ["**/*.json"],
    },
    {
        "slug": "data-perimeter-policy-examples",
        "owner": "aws-samples",
        "mechanism": "data-perimeter",
        "license": "CC-BY-SA-4.0",
        "vendor_bodies": False,  # share-alike — facts only, no vendored body
        "globs": [
            "service_control_policies/*.json",
            "resource_control_policies/*.json",
            "vpc_endpoint_policies/*.json",
        ],
    },
    {
        "slug": "example-permissions-boundary",
        "owner": "aws-samples",
        "mechanism": "permission-boundary",
        "license": "MIT",
        "vendor_bodies": True,
        "globs": ["policies/*.json"],
    },
    {
        "slug": "iam-access-analyzer-custom-policy-check-samples",
        "owner": "aws-samples",
        "mechanism": "IAM",
        "license": "MIT-0",
        "vendor_bodies": True,
        "globs": ["identity-policies/**/*.md", "resource-policies/**/*.md"],
        "md_policy": True,
    },
    # Guard-DSL sample rules. Its `.guard` files are CloudFormation Guard rules
    # keyed by `resourceType == "AWS::X::Y"`, NOT IAM policy JSON — they anchor
    # BOTH detective Config custom rules (CUSTOM_LAMBDA / CUSTOM_POLICY) AND
    # proactive CFN Guard rules. Harvested by the Guard-specific walker (see
    # `kind: guard`); their anchor signal is the governed resource type, not an
    # IAM action or condition key.
    {
        "slug": "aws-config-custom-policy-rule-samples",
        "owner": "aws-samples",
        "mechanism": "config-rule",
        "license": "MIT",
        "vendor_bodies": True,
        "globs": ["*.guard"],
        "kind": "guard",
    },
]

# Mechanism family per directory hint — a few repos mix SCPs and RCPs in one
# tree (data-perimeter). Directory-name prefixes refine the per-file mechanism.
_DIR_MECHANISM_HINTS = {
    "service_control_policies": "SCP",
    "resource_control_policies": "RCP",
    "vpc_endpoint_policies": "VPCE",
}

ALLOWED_MECHANISMS = {"SCP", "RCP", "IAM", "permission-boundary", "data-perimeter", "VPCE", "config-rule"}

# Condition-key-shaped tokens look like `service:Key` or `aws:Key` or
# `kms:EncryptionContext:foo`. We harvest these from Condition blocks only.
_CONDITION_KEY_RE = re.compile(r"^[a-zA-Z0-9._-]+:[a-zA-Z0-9:/${}*._-]+$")
# IAM action strings: `prefix:Action`, prefix is lowercase service code.
_ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*]+$")
# JSON fenced block inside markdown.
_MD_JSON_BLOCK = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def _repo_root() -> Path:
    """Resolve repo root via tools.paths (single source of truth)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from paths import repo_root  # type: ignore

    return repo_root()


def slugify(text: str) -> str:
    """kebab-case, ascii-only, collapse runs of non-alphanum to single dash."""
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


# Cap on example-id (and therefore example filename) length. Descriptive
# reference-repo slugs reach 160+ chars; nested under
# data/reference-repos/<repo>/examples/ they push the full path toward the
# Windows MAX_PATH (~260) limit on `git clone`/checkout. We bound the id so the
# vendored filename stays short.
MAX_ID_LEN = 48
_ID_HASH_LEN = 6


def shorten_id(base_id: str) -> str:
    """Bound an example id to MAX_ID_LEN characters, deterministically.

    Ids at or under the cap are returned unchanged, so a shortened id is a
    fixed point (running this twice is a no-op) and regeneration is idempotent.
    Longer ids are truncated and given a short hash suffix derived from the
    full id — human readability is preserved by the entry's `intent` field.
    """
    if len(base_id) <= MAX_ID_LEN:
        return base_id
    digest = hashlib.sha1(base_id.encode("utf-8")).hexdigest()[:_ID_HASH_LEN]
    keep = MAX_ID_LEN - _ID_HASH_LEN - 1  # room for the '-' + hash suffix
    return base_id[:keep].rstrip("-") + "-" + digest


def intent_from_path(rel_path: Path) -> str:
    """Derive a human intent string from the repo's directory + file naming.

    The reference repos encode intent in their paths, e.g.
    `Deny-changes-to-security-services/Deny-deletion-of-AWS-Access-Analyzer...json`.
    Turn that into prose: "<file stem with dashes->spaces>".
    """
    stem = rel_path.stem.replace("-", " ").replace("_", " ").strip()
    # Collapse repeated whitespace.
    return re.sub(r"\s+", " ", stem)


def harvest_actions_and_keys(policy: dict) -> tuple[list[str], list[str]]:
    """Extract governed actions and condition keys from an IAM policy document.

    Returns (sorted unique actions, sorted unique condition keys). Actions come
    from Statement[].Action / NotAction. Condition keys come from the operator
    sub-keys of Statement[].Condition (NOT the values).
    """
    actions: set[str] = set()
    keys: set[str] = set()

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        for action_field in ("Action", "NotAction"):
            val = stmt.get(action_field)
            if isinstance(val, str):
                val = [val]
            if isinstance(val, list):
                for a in val:
                    if isinstance(a, str) and _ACTION_RE.match(a):
                        actions.add(a)
        cond = stmt.get("Condition")
        if isinstance(cond, dict):
            for _operator, kv in cond.items():
                if isinstance(kv, dict):
                    for ckey in kv:
                        if isinstance(ckey, str) and _CONDITION_KEY_RE.match(ckey):
                            keys.add(ckey)
    return sorted(actions), sorted(keys)


# CloudFormation resource type inside a Guard rule: `resourceType == "AWS::X::Y"`
# (also matches single quotes and Type == variants some samples use).
_GUARD_RESOURCE_TYPE_RE = re.compile(
    r"""(?:resourceType|Type)\s*==\s*['"](AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)['"]"""
)
# `# Rule-intent : ...` header comment the samples use to describe each rule.
_GUARD_INTENT_RE = re.compile(r"#\s*Rule-intent\s*:\s*(.+)", re.IGNORECASE)


def harvest_guard_resource_types(text: str) -> tuple[list[str], str]:
    """Extract governed CloudFormation resource types + intent from a .guard file.

    Guard rules are keyed on the resource type they evaluate (e.g.
    `AWS::EFS::FileSystem`), not on IAM actions. We store the resource types as
    the anchor's `governed_resource_types` so `best_anchor` can match a control
    to a Guard sample covering the same resource type. The intent comes from the
    `# Rule-intent :` header comment when present, else the first rule name.
    """
    resource_types = sorted({m.group(1) for m in _GUARD_RESOURCE_TYPE_RE.finditer(text)})
    intent_m = _GUARD_INTENT_RE.search(text)
    intent = intent_m.group(1).strip() if intent_m else ""
    return resource_types, intent


def load_policy_documents(path: Path, md_policy: bool) -> list[dict]:
    """Load one or more IAM policy documents from a file.

    JSON files yield one document. Markdown files (md_policy) yield every
    ```json fenced block that parses as a policy document (has a Statement).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    docs: list[dict] = []
    if md_policy and path.suffix == ".md":
        for block in _MD_JSON_BLOCK.findall(text):
            try:
                doc = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(doc, dict) and "Statement" in doc:
                docs.append(doc)
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(doc, dict) and "Statement" in doc:
            docs.append(doc)
    return docs


def mechanism_for(rel_path: Path, default: str) -> str:
    """Refine the per-file mechanism from its directory, falling back to default."""
    for part in rel_path.parts:
        if part in _DIR_MECHANISM_HINTS:
            return _DIR_MECHANISM_HINTS[part]
    return default


def git_commit(repo_path: Path) -> str:
    """Return the pinned HEAD sha of a cloned repo (best-effort)."""
    head = repo_path / ".git" / "HEAD"
    try:
        ref = head.read_text().strip()
    except OSError:
        return "unknown"
    if ref.startswith("ref:"):
        ref_path = repo_path / ".git" / ref.split(" ", 1)[1].strip()
        try:
            return ref_path.read_text().strip()
        except OSError:
            return "unknown"
    return ref  # detached HEAD: HEAD already holds the sha


def build_index(repos_dir: Path, out_dir: Path) -> dict:
    """Walk every registered repo under repos_dir and build the index dict.

    Also writes vendored example bodies under out_dir/<slug>/examples/ for
    repos whose license permits it. Returns the in-memory index structure.
    """
    repos_block: list[dict] = []
    examples_block: list[dict] = []

    for spec in REPO_REGISTRY:
        slug = spec["slug"]
        repo_path = repos_dir / slug
        if not repo_path.is_dir():
            print(f"  skip {slug}: not found under {repos_dir}", file=sys.stderr)
            continue

        commit = git_commit(repo_path)
        repos_block.append(
            {
                "slug": slug,
                "owner": spec["owner"],
                "url": f"https://github.com/{spec['owner']}/{slug}",
                "commit": commit,
                "license": spec["license"],
                "vendor_bodies": spec["vendor_bodies"],
                "mechanism_family": spec["mechanism"],
            }
        )

        vendor_dir = out_dir / slug / "examples"
        if spec["vendor_bodies"]:
            vendor_dir.mkdir(parents=True, exist_ok=True)

        seen_ids: set[str] = set()
        files: list[Path] = []
        for glob in spec["globs"]:
            files.extend(sorted(repo_path.glob(glob)))

        for fpath in files:
            if ".git" in fpath.parts:
                continue
            rel = fpath.relative_to(repo_path)

            # Guard-DSL repos: harvest resource types, not IAM policy documents.
            if spec.get("kind") == "guard":
                text = fpath.read_text(encoding="utf-8", errors="replace")
                resource_types, guard_intent = harvest_guard_resource_types(text)
                # Every Guard anchor must govern at least one resource type.
                if not resource_types:
                    continue
                base_id = shorten_id(slugify(rel.with_suffix("").as_posix()))
                uid, n = base_id, 1
                while uid in seen_ids:
                    n += 1
                    uid = f"{base_id}-{n}"
                seen_ids.add(uid)

                entry = {
                    "id": uid,
                    "repo": slug,
                    "mechanism": spec["mechanism"],
                    "intent": guard_intent or intent_from_path(rel),
                    "governed_actions": [],
                    "condition_keys": [],
                    "governed_resource_types": resource_types,
                    "source_url": f"https://github.com/{spec['owner']}/{slug}/blob/{commit}/{rel.as_posix()}",
                }
                if spec["vendor_bodies"]:
                    body_path = vendor_dir / f"{uid}.guard"
                    body_path.write_text(text, encoding="utf-8")
                    entry["source_path"] = (
                        f"data/reference-repos/{slug}/examples/{uid}.guard"
                    )
                else:
                    entry["source_path"] = None
                examples_block.append(entry)
                continue

            docs = load_policy_documents(fpath, spec.get("md_policy", False))
            for di, doc in enumerate(docs):
                actions, keys = harvest_actions_and_keys(doc)
                # Skip non-policy / empty extractions — every anchor must carry
                # at least one action or condition key.
                if not actions and not keys:
                    continue
                base_id = slugify(rel.with_suffix("").as_posix())
                ex_id = base_id if len(docs) == 1 else f"{base_id}-{di}"
                ex_id = shorten_id(ex_id)
                # Disambiguate any residual collisions.
                uid, n = ex_id, 1
                while uid in seen_ids:
                    n += 1
                    uid = f"{ex_id}-{n}"
                seen_ids.add(uid)

                entry = {
                    "id": uid,
                    "repo": slug,
                    "mechanism": mechanism_for(rel, spec["mechanism"]),
                    "intent": intent_from_path(rel),
                    "governed_actions": actions,
                    "condition_keys": keys,
                    "source_url": f"https://github.com/{spec['owner']}/{slug}/blob/{commit}/{rel.as_posix()}",
                }
                if spec["vendor_bodies"]:
                    body_path = vendor_dir / f"{uid}.json"
                    body_path.write_text(
                        json.dumps(doc, indent=2, sort_keys=False) + "\n",
                        encoding="utf-8",
                    )
                    # Logical, location-independent path so --check (which builds
                    # into a scratch tempdir) produces a byte-identical index.
                    entry["source_path"] = (
                        f"data/reference-repos/{slug}/examples/{uid}.json"
                    )
                else:
                    entry["source_path"] = None  # facts-only (share-alike license)
                examples_block.append(entry)

    examples_block.sort(key=lambda e: (e["repo"], e["id"]))
    repos_block.sort(key=lambda r: r["slug"])
    return {"version": 1, "repos": repos_block, "examples": examples_block}


def dump_yaml(index: dict) -> str:
    return yaml.safe_dump(index, sort_keys=False, width=100, allow_unicode=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repos-dir",
        required=True,
        help="Directory containing the locally-cloned reference repos.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Dry-run: exit 2 if the committed index.yaml differs from rebuild.",
    )
    args = parser.parse_args()

    root = _repo_root()
    out_dir = root / "data" / "reference-repos"
    index_path = out_dir / "index.yaml"
    repos_dir = Path(args.repos_dir).expanduser().resolve()

    if not repos_dir.is_dir():
        print(f"repos-dir not found: {repos_dir}", file=sys.stderr)
        sys.exit(1)

    if args.check:
        # Build into a scratch tree so --check never mutates committed bodies.
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "reference-repos"
            scratch.mkdir(parents=True)
            rebuilt = build_index(repos_dir, scratch)
        if not index_path.exists():
            print("index.yaml missing; run without --check to generate.", file=sys.stderr)
            sys.exit(2)
        on_disk = yaml.safe_load(index_path.read_text())
        if on_disk != rebuilt:
            print("index.yaml is stale — rerun build_reference_index.py.", file=sys.stderr)
            sys.exit(2)
        print(f"index.yaml up to date ({len(rebuilt['examples'])} examples).")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    index = build_index(repos_dir, out_dir)
    index_path.write_text(dump_yaml(index), encoding="utf-8")
    print(
        f"Wrote {index_path} — {len(index['repos'])} repos, "
        f"{len(index['examples'])} examples."
    )


if __name__ == "__main__":
    main()
