"""Published AWS Threat Models: release discovery, pinned downloads and citations.

Only the release root is fixed. Service namespaces and artifact paths come from
AWS's manifest; identity aliases come from the service model's own metadata.
No downloaded model or derived state belongs in the source repository.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.error import URLError
from urllib.request import Request, urlopen

REPOSITORY = "https://github.com/aws/threat-models-for-aws-services"
RELEASE_ROOT = "threat-models-for-aws-services"
RAW_ROOT = "https://raw.githubusercontent.com/aws/threat-models-for-aws-services"
HEAD_URL = "https://api.github.com/repos/aws/threat-models-for-aws-services/git/ref/heads/main"
MAX_BYTES = 32 * 1024 * 1024


class SourceError(ValueError):
    """A required upstream model cannot be safely selected or verified."""


def identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def model_identities(data: dict) -> set[str]:
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        return set()
    names = [metadata.get("name")]
    identifiers = metadata.get("identifiers")
    if isinstance(identifiers, dict):
        for key in ("iam", "fullName", "shortName"):
            value = identifiers.get(key)
            names.extend(value if isinstance(value, list) else [value])
    return {identity(name) for name in names if isinstance(name, str) and identity(name)}


def download(url: str) -> bytes:
    """Bounded, unauthenticated reads; errors never fall back to cached input."""
    try:
        request = Request(url, headers={
            "User-Agent": "service-onboarding-threat-models",
            "Cache-Control": "no-cache",
        })
        with urlopen(request, timeout=30) as response:
            content = response.read(MAX_BYTES + 1)
    except (OSError, URLError) as exc:
        raise SourceError(
            f"Cannot retrieve published AWS Threat Model source {url}: {exc}. "
            "Retry when reachable; cached/local models cannot bypass this gate."
        ) from exc
    if len(content) > MAX_BYTES:
        raise SourceError(f"Published artifact exceeds {MAX_BYTES} bytes: {url}")
    return content


def _json(content: bytes, label: str) -> dict:
    try:
        data = json.loads(content)
    except (ValueError, UnicodeError) as exc:
        raise SourceError(f"Invalid JSON in {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise SourceError(f"{label} must be a JSON object")
    return data


def artifact_ref(ref: object, suffix: str) -> dict:
    if not isinstance(ref, dict):
        raise SourceError("Missing release artifact reference")
    path, digest = ref.get("path"), ref.get("sha256")
    if (
        not isinstance(path, str) or not path.endswith(suffix)
        or not re.fullmatch(r"[a-zA-Z0-9_./-]+", path)
        or PurePosixPath(path).is_absolute()
        or any(p in ("", ".", "..") for p in path.split("/"))
    ):
        raise SourceError(f"Unsafe or unsupported release artifact path: {path!r}")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise SourceError(f"Missing/invalid SHA-256 for {path}")
    return {"path": path, "sha256": digest}


def artifact_url(commit: str, path: str, *, raw: bool = False) -> str:
    prefix = RAW_ROOT if raw else REPOSITORY + "/blob"
    return f"{prefix}/{commit}/{RELEASE_ROOT}/{path}"


def verified_download(commit: str, ref: dict) -> bytes:
    content = download(artifact_url(commit, ref["path"], raw=True))
    if hashlib.sha256(content).hexdigest() != ref["sha256"]:
        raise SourceError(f"SHA-256 mismatch for published {ref['path']}; pipeline cannot run.")
    return content


def report_anchor(alias: str) -> str:
    # GitHub heading anchors remove dots and other punctuation, retaining hyphens.
    return re.sub(r"[^\w\- ]", "", alias.lower()).replace(" ", "-")


def citation_url(source: dict | None, alias: str) -> str:
    """Link verified headings; fall back to report/JSON for known source aliases."""
    if not isinstance(source, dict):
        return ""
    if alias in source.get("report_aliases", []):
        return source.get("report_url", "") + "#" + report_anchor(alias)
    if alias in source.get("model_aliases", []):
        return (source.get("report_url") if source.get("report_status", "verified") == "verified" else "") or source.get("data_url", "")
    return ""


def fetch_latest(service: str) -> tuple[bytes, dict]:
    """Discover main, then read one consistent release at that immutable commit."""
    if not isinstance(service, str) or not identity(service):
        raise SourceError("A requested service name is required.")
    head = _json(download(HEAD_URL), "repository main reference")
    obj = head.get("object")
    commit = obj.get("sha") if isinstance(obj, dict) else None
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise SourceError("Repository main reference has no valid commit SHA")
    manifest_bytes = download(artifact_url(commit, "manifest.json", raw=True))
    manifest = _json(manifest_bytes, "AWS release manifest")
    entries = manifest.get("services")
    if not isinstance(entries, list):
        raise SourceError("AWS release manifest requires services[]")
    seen = set()
    for entry in entries:
        namespace = entry.get("namespace") if isinstance(entry, dict) else None
        if (
            not isinstance(namespace, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", namespace)
            or namespace in seen
        ):
            raise SourceError("AWS release manifest has an invalid or duplicate service namespace")
        seen.add(namespace)
        artifact_ref(entry.get("data"), ".json")

    from validate_threat_model_input import validate_export
    exact = [entry for entry in entries if identity(entry["namespace"]) == identity(service)]
    matches = []
    for entry in exact or entries:
        content = verified_download(commit, artifact_ref(entry["data"], ".json"))
        model = _json(content, entry["data"]["path"])
        if identity(service) not in model_identities(model):
            if exact:
                raise SourceError("Published model metadata does not match its requested namespace")
            continue
        errors = validate_export(model, service)
        if errors:
            raise SourceError("Invalid published AWS Threat Model: " + "; ".join(errors))
        matches.append((entry, content, model))
    if not matches:
        raise SourceError(
            f"No published AWS Threat Model for {service!r}. Available namespaces: "
            f"{', '.join(sorted(seen)) or '(none)'}. "
            "Pipeline cannot run until AWS publishes a matching model."
        )
    if len(matches) != 1:
        raise SourceError(f"Ambiguous service name {service!r}; use an exact published namespace: " + ", ".join(item[0]["namespace"] for item in matches))
    entry, content, model = matches[0]
    # Readable evidence is supplementary: bad/missing reports must not discard
    # a usable, hash-verified JSON model. Never fetch an unsafe manifest path.
    report_ref = None
    report = ""
    report_status, report_error = "verified", ""
    try:
        report_ref = artifact_ref(entry.get("report"), ".md")
        report = verified_download(commit, report_ref).decode("utf-8")
    except (SourceError, UnicodeError) as exc:
        report_status, report_error = "unavailable", str(exc)
    headings = set(re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", report, re.MULTILINE))
    aliases = sorted({row["alias"] for section in ("mitigations", "threats", "implementations")
                      for row in model.get(section, []) if isinstance(row, dict)
                      and isinstance(row.get("alias"), str) and row["alias"] in headings})
    source = {
        "repository": REPOSITORY, "ref": "main", "commit": commit,
        "namespace": entry["namespace"], "release_version": manifest.get("version"),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "manifest_url": artifact_url(commit, "manifest.json"),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "data": artifact_ref(entry["data"], ".json"), "report": report_ref,
        "data_url": artifact_url(commit, entry["data"]["path"]),
        "report_url": artifact_url(commit, report_ref["path"]) if report_ref else "",
        "report_status": report_status, "report_error": report_error,
        "report_aliases": aliases,
        "model_aliases": sorted({row["alias"] for section in ("mitigations", "threats", "implementations")
                                 for row in model.get(section, []) if isinstance(row.get("alias"), str)}),
    }
    from threat_model_integrity import source_findings
    source["findings"] = source_findings(model, source)
    return content, source


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(content)
    try:
        tmp_path.replace(path)
    finally:
        tmp_path.unlink(missing_ok=True)


def save_latest(service: str, workspace: Path) -> dict:
    content, source = fetch_latest(service)
    # Each new run owns its snapshot, even when two runs fetch the same commit.
    # A later fetch must never replace bytes read by an active run.
    parent = (workspace / ".service-approval" / "_sources" / source["commit"]).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=source["namespace"] + "-", dir=parent))
    path = directory / (source["namespace"] + ".json")
    atomic_write(path, content)
    return {"threat_model_file": str(path), "threat_model_source": source,
            "has_custom_threat_model": True}


def check_source(source: object, path: Path) -> list[str]:
    """Offline hook backstop: published provenance and exact downloaded bytes."""
    try:
        if (
            not isinstance(source, dict)
            or source.get("repository") != REPOSITORY or source.get("ref") != "main"
        ):
            raise SourceError(
                "Published AWS Threat Model provenance required. Re-run intake to "
                "fetch the latest model; local exports cannot authorize a pipeline run."
            )
        commit = source.get("commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise SourceError("Threat model source requires a pinned commit SHA")
        namespace = source.get("namespace")
        if not isinstance(namespace, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", namespace):
            raise SourceError("Threat model source requires a service namespace")
        aliases = source.get("report_aliases")
        if not isinstance(aliases, list) or any(not isinstance(alias, str) for alias in aliases):
            raise SourceError("Threat model source requires verified report_aliases[]")
        data_ref = artifact_ref(source.get("data"), ".json")
        status = source.get("report_status", "verified")
        if status not in ("verified", "unavailable"):
            raise SourceError("Invalid readable report status")
        refs = [("data_url", data_ref)]
        if source.get("report") is not None:
            refs.append(("report_url", artifact_ref(source["report"], ".md")))
        elif status != "unavailable" or source.get("report_url"):
            raise SourceError("Missing readable report provenance")
        if status == "unavailable" and (aliases or not source.get("report_error")):
            raise SourceError("Unavailable readable report requires an advisory reason and no verified anchors")
        for key, ref in refs:
            if source.get(key) != artifact_url(commit, ref["path"]):
                raise SourceError(f"Threat model source {key} does not match its pinned artifact")
        if hashlib.sha256(path.read_bytes()).hexdigest() != data_ref["sha256"]:
            raise SourceError("Threat model snapshot changed or is corrupt (SHA-256 mismatch). Re-run intake.")
    except (SourceError, OSError) as exc:
        return [str(exc)]
    return []


def refresh_manifest(manifest: dict, manifest_path: Path) -> dict:
    """Compatibility entry point: resume revalidates the saved snapshot, offline.

    Only fetch_latest/save_latest begin a new run. An upstream update, removal,
    or outage must not invalidate an existing run's original source version.
    """
    from validate_threat_model_input import select_manifest_export
    _, errors = select_manifest_export(manifest, manifest_path)
    if errors:
        raise SourceError("; ".join(errors))
    return manifest["inputs"]["threat_model_source"]
