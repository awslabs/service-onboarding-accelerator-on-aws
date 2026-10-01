"""Mandatory input gate: real file, correct service, no fallback or resume bypass."""
import json
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from validate_threat_model_input import (
    check_artifact_prerequisite,
    check_manifest,
    check_run,
    select_export,
    validate_export,
)

TOOLS = Path(__file__).resolve().parent


def export(service="dsql"):
    return {
        "metadata": {
            "name": service,
            "identifiers": {"iam": service, "fullName": f"Amazon {service.upper()}"},
        },
        "entities": [{"id": "entity-1", "entityType": "Resource"}],
        "mitigations": [{
            "id": "mitigation-1", "alias": f"Mitigation.{service}.1",
            "statement": "Require access restrictions.",
            # Cross-service configuration must not establish model identity.
            "configurationRequestParameters": [{"service": "ec2", "operation": "CreateVpcEndpoint"}],
        }],
        "threats": [{
            "id": "threat-1", "alias": f"Threat.{service}.1",
            "threatAction": "can access resources outside the intended boundary",
        }],
        "implementations": [],
    }


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def setup_run(tmp_path, service="dsql", staging=False):
    source = write_json(tmp_path / "customer inputs" / "model.json", export(service))
    run = tmp_path / ".service-approval" / ("_staging/ts" if staging else service)
    manifest = write_json(run / "00-intake" / "intake-manifest.json", {
        "service": {"name": service},
        "inputs": {
            "threat_model_file": str(source.relative_to(tmp_path)),
            "has_custom_threat_model": True,
        },
    })
    return source, run, manifest


@pytest.mark.parametrize("service", ["dsql", "lambda", "s3", "future-service"])
def test_matching_services_allowed_without_allowlist(service):
    assert validate_export(export(service), service) == []


def test_identity_uses_declared_name_and_identifiers_not_filename_or_operations(tmp_path):
    model = export()
    model["metadata"]["identifiers"]["fullName"] = "Amazon Aurora DSQL"
    assert validate_export(model, "Amazon Aurora DSQL") == []
    assert validate_export(model, "amazonauroradsql") == []
    assert validate_export(model, "DSQL") == []
    wrong_name = write_json(tmp_path / "ec2-threat-model.json", model)
    _, errors = select_export("ec2", threat_model_file=str(wrong_name))
    assert any("not requested service" in error for error in errors)


@pytest.mark.parametrize("data", [
    None, [], "not a model", {}, {"entities": []},
    {"framework_objectives": [{"id": "1"}]},
    {"entities": [{"mitigations": [{"id": "m1"}]}]},
])
def test_other_inputs_are_not_aws_threat_models(data):
    assert validate_export(data, "dsql")


@pytest.mark.parametrize("section", ["metadata", "entities", "mitigations", "threats"])
@pytest.mark.parametrize("bad", [None, {}, [], "", [None]])
def test_empty_or_malformed_sections_rejected(section, bad):
    data = export()
    data[section] = bad
    assert validate_export(data, "dsql")


@pytest.mark.parametrize("section,field", [
    ("entities", "id"), ("mitigations", "id"), ("mitigations", "alias"),
    ("mitigations", "statement"), ("threats", "id"),
    ("threats", "alias"), ("threats", "threatAction"),
])
def test_empty_record_fields_rejected(section, field):
    data = export()
    data[section][0][field] = " "
    assert validate_export(data, "dsql")


def test_optional_implementations_and_legacy_nested_shape():
    data = export()
    del data["implementations"]
    assert validate_export(data, "dsql") == []
    data["entities"][0]["mitigations"] = []
    assert validate_export(data, "dsql")


def test_discovery_ignores_framework_and_other_service_exports(tmp_path):
    write_json(tmp_path / "a-framework.json", {"framework": {}})
    write_json(tmp_path / "b-other-service.json", export("lambda"))
    source = write_json(tmp_path / "z-model.json", export())
    assert select_export("dsql", str(tmp_path)) == (source, [])


def test_ambiguous_matching_exports_require_selection(tmp_path):
    source = write_json(tmp_path / "a.json", export())
    write_json(tmp_path / "b.json", export())
    path, errors = select_export("dsql", str(tmp_path))
    assert path is None and "Multiple matching" in errors[0]
    assert select_export("dsql", str(tmp_path), str(source)) == (source, [])


@pytest.mark.parametrize("contents", ["{", "[]", '{"framework": {}}'])
def test_invalid_explicit_selection_never_falls_back(tmp_path, contents):
    write_json(tmp_path / "valid.json", export())
    bad = tmp_path / "selected.json"
    bad.write_text(contents)
    path, errors = select_export("dsql", str(tmp_path), str(bad))
    assert path is None and errors


def test_missing_folder_and_missing_explicit_file(tmp_path):
    assert select_export("dsql")[1]
    assert select_export("dsql", str(tmp_path / "missing"))[1]
    assert select_export("dsql", str(tmp_path))[1]
    write_json(tmp_path / "valid.json", export())
    assert select_export("dsql", str(tmp_path), str(tmp_path / "missing.json"))[1]


@pytest.mark.parametrize("staging", [False, True])
def test_manifest_paths_resolve_from_workspace_even_with_different_cwd(tmp_path, monkeypatch, staging):
    _, _, manifest = setup_run(tmp_path, staging=staging)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert check_manifest(json.loads(manifest.read_text()), manifest) == []


@pytest.mark.parametrize("flag", ["no_mcp", "include_unverified", "dry_run", "clean"])
def test_flags_boolean_and_finalized_state_cannot_replace_export(tmp_path, flag):
    _, run, manifest = setup_run(tmp_path)
    data = json.loads(manifest.read_text())
    data["inputs"].pop("threat_model_file")
    data["pipeline_flags"] = {flag: True}
    write_json(manifest, data)
    (run / "pipeline.log").write_text(
        "2026-10-01T00:00:00Z [06-summarize] [pipeline:complete:FINALIZED] done\n"
    )
    assert check_run(run)


def test_resume_reopens_file_and_does_not_discover_replacement(tmp_path):
    source, run, _ = setup_run(tmp_path)
    assert check_run(run) == []
    source.unlink()
    write_json(source.parent / "replacement.json", export())
    assert check_run(run)


def test_legacy_manifest_requires_explicit_recorded_export(tmp_path):
    source, run, manifest = setup_run(tmp_path)
    data = json.loads(manifest.read_text())
    data["inputs"] = {"input_files": [{"path": str(source), "type": "threat_model"}]}
    assert check_manifest(data, manifest) == []
    data["inputs"]["input_files"].append({"path": str(source), "type": "threat_model"})
    assert check_manifest(data, manifest)
    data["inputs"] = {"input_folder": str(source.parent), "has_custom_threat_model": True}
    assert check_manifest(data, manifest)


def test_generated_index_cannot_substitute_for_export(tmp_path):
    _, run, manifest = setup_run(tmp_path)
    from threat_model_parse import build_threat_model_index
    source = write_json(run / "02-research" / "threat-model-index.json",
                        build_threat_model_index(export(), service="dsql"))
    data = json.loads(manifest.read_text())
    data["inputs"]["threat_model_file"] = str(source)
    assert check_manifest(data, manifest)


def test_artifact_gate_allows_intake_and_unrelated_work_but_blocks_downstream(tmp_path):
    assert check_artifact_prerequisite(str(tmp_path / "skills" / "SKILL.md")) == []
    assert check_artifact_prerequisite(str(tmp_path / ".service-approval/_staging/ts/00-intake/intake-manifest.json")) == []
    assert check_artifact_prerequisite(str(tmp_path / ".service-approval/_staging/ts/01-assess/sar-facts.json"))
    target = tmp_path / ".service-approval/dsql/01-assess/sar-facts.json"
    assert check_artifact_prerequisite(str(target))
    setup_run(tmp_path)
    assert check_artifact_prerequisite(str(target)) == []


@pytest.mark.parametrize("tool,path_key", [("Write", "file_path"), ("Edit", "file_path"), ("fs_write", "path")])
def test_pre_write_hook_blocks_before_artifact_exists(tmp_path, tool, path_key):
    target = tmp_path / ".service-approval/dsql/01-assess/sar-facts.json"
    event = {"tool_name": tool, "tool_input": {path_key: str(target)}}
    result = subprocess.run([sys.executable, str(TOOLS / "hook_pre_tool_use.py")],
                            input=json.dumps(event), text=True, capture_output=True, cwd=tmp_path)
    assert result.returncode == 2
    assert "AWS THREAT MODEL REQUIRED" in result.stderr
    assert not target.exists()
    setup_run(tmp_path)
    result = subprocess.run([sys.executable, str(TOOLS / "hook_pre_tool_use.py")],
                            input=json.dumps(event), text=True, capture_output=True, cwd=tmp_path)
    assert result.returncode == 0, result.stderr


def test_post_write_intake_validation_and_integrity_backstop(tmp_path):
    from validate_state import validate_state_file
    from validate_pipeline_integrity import validate_pipeline
    _, run, manifest = setup_run(tmp_path)
    data = json.loads(manifest.read_text())
    data["inputs"]["threat_model_file"] = "missing.json"
    write_json(manifest, data)
    assert validate_state_file(str(manifest))
    assert any(error.startswith("P0 FAIL:") for error in validate_pipeline(tmp_path))
    event = {"tool_name": "Write", "tool_input": {"file_path": str(manifest)}}
    result = subprocess.run([sys.executable, str(TOOLS / "hook_post_tool_use.py")],
                            input=json.dumps(event), text=True, capture_output=True, cwd=tmp_path)
    assert result.returncode == 2
    event["tool_input"]["file_path"] = str(manifest.relative_to(tmp_path))
    result = subprocess.run([sys.executable, str(TOOLS / "hook_post_tool_use.py")],
                            input=json.dumps(event), text=True, capture_output=True, cwd=tmp_path)
    assert result.returncode == 2


def test_factual_check_uses_explicit_model_outside_input_folder(tmp_path):
    from validate_threat_model_facts import find_threat_model_file
    source, run, manifest = setup_run(tmp_path)
    decoy = write_json(tmp_path / "input/a-other-service.json", export("lambda"))
    data = json.loads(manifest.read_text())
    data["inputs"]["input_folder"] = str(decoy.parent)
    write_json(manifest, data)
    assert find_threat_model_file(run) == source
    source.unlink()
    assert find_threat_model_file(run) is None


def test_cli_missing_input_fails_without_creating_state(tmp_path):
    result = subprocess.run([sys.executable, str(TOOLS / "validate_threat_model_input.py"),
                             "--service", "dsql"], text=True, capture_output=True, cwd=tmp_path)
    assert result.returncode == 2
    assert "AWS THREAT MODEL REQUIRED" in result.stderr
    assert not (tmp_path / ".service-approval").exists()


def test_cli_manifest_and_slug_revalidate(tmp_path):
    source, _, manifest = setup_run(tmp_path)
    for mode in (["--manifest", str(manifest)], ["--slug", "dsql"]):
        command = [sys.executable, str(TOOLS / "validate_threat_model_input.py"), *mode]
        assert subprocess.run(command, capture_output=True, cwd=tmp_path).returncode == 0
    source.unlink()
    for mode in (["--manifest", str(manifest)], ["--slug", "dsql"]):
        command = [sys.executable, str(TOOLS / "validate_threat_model_input.py"), *mode]
        assert subprocess.run(command, capture_output=True, cwd=tmp_path).returncode == 2


@pytest.mark.parametrize("script,artifact", [
    ("threat_model_trace.py", "threat-model-trace.json"),
    ("compute-applicability-matrix.py", "applicability-matrix.json"),
])
@pytest.mark.parametrize("missing", [False, True])
def test_slug_consumers_use_recorded_export_and_never_skip(tmp_path, monkeypatch, script, artifact, missing):
    source, run, _ = setup_run(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "input_gate_consumer", TOOLS.parents[1] / "scripts" / script
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.paths, "service_root", lambda slug: run)
    monkeypatch.setattr(sys, "argv", [script, "--slug", "dsql"])
    # These used to choose the first JSON under <run>/input, regardless of type.
    write_json(run / "input" / "a-decoy.json", {"framework_objectives": []})
    if missing:
        source.unlink()
        with pytest.raises(SystemExit) as exc:
            module.main()
        assert exc.value.code == 2
        assert not (run / "04-map" / artifact).exists()
    else:
        module.main()
        assert (run / "04-map" / artifact).exists()
