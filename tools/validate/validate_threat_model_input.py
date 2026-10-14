#!/usr/bin/env python3
"""Require a readable AWS Threat Model export for the requested service.

Hooks validate a pinned published snapshot locally. At pipeline entry/resume,
--refresh also checks the current AWS release; no local export bypasses intake.
It validates the input contract, not the truth of the model's AWS claims.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from threat_model_parse import is_threat_model_shape, is_threat_model_threats_shape
from threat_model_source import model_identities, check_source, refresh_manifest, SourceError


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def validate_export(data: object, service: str) -> list[str]:
    """Validate the consumed export shape and metadata service identity.

    Service identity comes only from metadata, never filenames, description
    prose or cross-service operations (a DSQL model may configure EC2 endpoints).
    Implementations are optional: older exports still supply threats/mitigations.
    """
    if not isinstance(data, dict):
        return ["AWS Threat Model export must be a JSON object."]
    errors = []
    metadata = data.get("metadata")
    if (
        not isinstance(metadata, dict) or not _text(metadata.get("name"))
        or not _identity(metadata["name"])
    ):
        errors.append("AWS Threat Model export requires metadata.name.")
    else:
        if not _text(service) or not _identity(service):
            errors.append("A requested service name is required.")
        elif _identity(service) not in model_identities(data):
            errors.append(
                f"AWS Threat Model is for {metadata['name']!r}, not requested "
                f"service {service!r}. Supply a matching export."
            )

    fields = {
        "entities": ("id",),
        "mitigations": ("id", "alias", "statement"),
        "threats": ("id", "alias", "threatAction"),
    }
    for section, required in fields.items():
        rows = data.get(section)
        if not isinstance(rows, list) or not rows:
            errors.append(f"AWS Threat Model requires non-empty top-level {section}[].")
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                errors.append(f"{section}[{index}] must be an object.")
                continue
            for field in required:
                if not _text(row.get(field)):
                    errors.append(f"{section}[{index}].{field} must be a non-empty string.")
    if not is_threat_model_shape(data) or not is_threat_model_threats_shape(data):
        errors.append(
            "Unsupported AWS Threat Model shape: use an export with top-level "
            "mitigations[] and threats[], not an entity-nested mitigation report."
        )
    if "implementations" in data and (
        not isinstance(data["implementations"], list)
        or any(not isinstance(row, dict) for row in data["implementations"])
    ):
        errors.append("implementations must be an array of objects when supplied.")
    return errors


def _read_json(path: Path) -> tuple[object, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, ValueError) as exc:
        return None, [f"Cannot read AWS Threat Model input {path}: {exc}"]


def select_export(
    service: str,
    input_folder: str | None = None,
    threat_model_file: str | None = None,
    base_dir: Path | None = None,
) -> tuple[Path | None, list[str]]:
    """Choose exactly one matching export; explicit selections never fall back."""
    base = base_dir or Path.cwd()
    if not _text(service) or not _identity(service):
        return None, ["A requested service name is required."]
    if threat_model_file is not None:
        if not _text(threat_model_file):
            return None, ["threat_model_file must be a non-empty file path."]
        path = (base / Path(threat_model_file).expanduser()).resolve()
        data, errors = _read_json(path)
        if not errors:
            errors = validate_export(data, service)
        return (None, errors) if errors else (path, [])
    if not _text(input_folder):
        return None, [
            "AWS Threat Model required. Provide a matching JSON export using "
            "--threat-model-file or an input folder containing the export."
        ]
    folder = (base / Path(input_folder).expanduser()).resolve()
    if not folder.is_dir():
        return None, [f"AWS Threat Model input folder does not exist: {folder}"]
    matches = []
    rejected = []
    for path in sorted(folder.glob("*.json")):
        data, errors = _read_json(path)
        if errors:
            rejected.extend(errors)
            continue
        # Frameworks, SAR maps, and other JSON files are not model candidates.
        if not isinstance(data, dict) or not {"mitigations", "threats"} & data.keys():
            continue
        errors = validate_export(data, service)
        if errors:
            rejected.extend(f"{path.name}: {error}" for error in errors)
        else:
            matches.append(path.resolve())
    if len(matches) == 1:
        return matches[0], []
    if len(matches) > 1:
        return None, [
            "Multiple matching AWS Threat Model exports found. Select one with "
            "--threat-model-file: " + ", ".join(str(path) for path in matches)
        ]
    return None, [
        f"No valid AWS Threat Model export for {service!r} in {folder}. "
        "Supply the service's AWS Threat Model JSON export before running the pipeline.",
        *rejected,
    ]


def workspace_for_manifest(path: Path) -> Path:
    """Resolve relative input paths from the run workspace, not the plugin."""
    for parent in path.resolve().parents:
        if parent.name == ".service-approval":
            return parent.parent
    return Path.cwd()


def select_manifest_export(
    data: object, manifest_path: Path
) -> tuple[Path | None, list[str]]:
    """Reopen the recorded source; a boolean or a generated index is insufficient."""
    if not isinstance(data, dict):
        return None, ["Intake manifest must be a JSON object."]
    service = data.get("service")
    name = service.get("name") if isinstance(service, dict) else service
    if not _text(name):
        return None, ["Intake manifest requires service.name for AWS Threat Model matching."]
    inputs = data.get("inputs")
    if not isinstance(inputs, dict):
        return None, ["Intake manifest requires inputs and an AWS Threat Model file path."]
    selected = inputs.get("threat_model_file")
    if "threat_model_file" not in inputs:
        # Older manifests recorded the source in input_files. Accept only one
        # explicitly recorded export; never rediscover a different file on resume.
        files = inputs.get("input_files")
        recorded = [
            item.get("path") for item in files
            if isinstance(item, dict) and item.get("type") == "threat_model"
            and _text(item.get("path")) and item["path"].lower().endswith(".json")
        ] if isinstance(files, list) else []
        if len(recorded) == 1:
            selected = recorded[0]
    if not _text(selected):
        return None, [
            "AWS Threat Model required: record the selected export in "
            "inputs.threat_model_file. Re-run intake to fetch the latest published model."
        ]
    path, errors = select_export(
        name, threat_model_file=selected, base_dir=workspace_for_manifest(manifest_path)
    )
    if not errors:
        errors = check_source(inputs.get("threat_model_source"), path)
    return (None, errors) if errors else (path, [])


def check_manifest(data: object, manifest_path: Path) -> list[str]:
    return select_manifest_export(data, manifest_path)[1]


def load_run_export(service_root: Path) -> tuple[Path | None, list[str]]:
    manifest = service_root / "00-intake" / "intake-manifest.json"
    data, errors = _read_json(manifest)
    if errors:
        return None, [f"AWS Threat Model prerequisite: intake manifest missing or unreadable: {manifest}"]
    return select_manifest_export(data, manifest)


def check_run(service_root: Path) -> list[str]:
    return load_run_export(service_root)[1]


def check_artifact_prerequisite(file_path: str) -> list[str]:
    """Gate writes under downstream phase directories, leaving intake writable."""
    path = Path(file_path).resolve()
    for parent in path.parents:
        if parent.name != ".service-approval":
            continue
        parts = path.relative_to(parent).parts
        if (
            len(parts) >= 4 and parts[0] == "_staging"
            and re.fullmatch(r"0[1-6]-[a-z-]+", parts[2])
        ):
            return ["Complete intake and promote the validated manifest before downstream writes."]
        if len(parts) >= 3 and re.fullmatch(r"0[1-6]-[a-z-]+", parts[1]):
            return check_run(parent / parts[0])
        break
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--manifest", type=Path, help="Validate a staging or canonical intake manifest")
    mode.add_argument("--slug", help="Revalidate a run in the current workspace")
    parser.add_argument("--service", help="Requested service identifier or full name")
    parser.add_argument("--input-folder")
    parser.add_argument("--threat-model-file")
    parser.add_argument("--refresh", action="store_true", help="Check latest upstream availability before starting/resuming a saved run")
    args = parser.parse_args()
    if args.refresh and not (args.manifest or args.slug):
        parser.error("--refresh requires --manifest or --slug")
    selected = None
    if args.manifest or args.slug:
        if args.service or args.input_folder or args.threat_model_file:
            parser.error("--manifest/--slug read their inputs from the manifest")
        if args.slug:
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", args.slug):
                parser.error("invalid service slug")
            root = (Path.cwd() / ".service-approval").resolve()
            run = (root / args.slug).resolve()
            if not run.is_relative_to(root):
                parser.error("service path escapes .service-approval")
            args.manifest = run / "00-intake" / "intake-manifest.json"
            errors = check_run(run)
        else:
            data, errors = _read_json(args.manifest)
            if not errors:
                errors = check_manifest(data, args.manifest)
    else:
        selected, errors = select_export(
            args.service, args.input_folder, args.threat_model_file
        )
    if not errors and args.refresh:
        data, errors = _read_json(args.manifest)
        if not errors:
            try:
                refresh_manifest(data, args.manifest)
            except SourceError as exc:
                errors = [str(exc)]
    if errors:
        print("AWS THREAT MODEL REQUIRED — pipeline cannot start or resume.", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 2
    if selected:
        print(f"OK: local export structure verified: {selected}. "
              "Pipeline intake must still fetch a published model and record its provenance.")
    else:
        print("OK: published AWS Threat Model prerequisite verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
