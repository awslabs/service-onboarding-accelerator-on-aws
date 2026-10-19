"""Live-source contract tests use only synthetic models and a mocked transport."""
import hashlib
import json
from pathlib import Path

import pytest

import threat_model_source as source
from test_validate_threat_model_input import export, setup_run
from validate_threat_model_input import check_run, validate_export

COMMIT = "c" * 40


def release(monkeypatch, names=("future-service",), commit=COMMIT):
    payloads = {source.HEAD_URL: json.dumps({"object": {"sha": commit}}).encode()}
    payloads[f"{source.COMMIT_ROOT}/{commit}"] = json.dumps({"sha": commit}).encode()
    manifest = {"version": "1.1.0", "services": []}
    for name in names:
        model = export(name)
        model["metadata"]["identifiers"] = {
            "fullName": f"Amazon {name.upper()}", "shortName": f"Short {name}",
            "iam": [name, f"{name}-api"],
        }
        data = json.dumps(model).encode()
        report = f"# Service\n\n### Mitigation.{name}.1\n\nExample\n\n### Threat.{name}.1\n".encode()
        # Paths deliberately differ from today's upstream layout.
        entry = {"namespace": name}
        for kind, path, content in (("data", f"models/{name}.json", data), ("report", f"readable/{name}.md", report)):
            entry[kind] = {"path": path, "sha256": hashlib.sha256(content).hexdigest()}
            payloads[source.artifact_url(commit, path, raw=True)] = content
        manifest["services"].append(entry)
    manifest_url = source.artifact_url(commit, "manifest.json", raw=True)
    payloads[manifest_url] = json.dumps(manifest).encode()
    calls = []

    def download(url):
        calls.append(url)
        assert url in payloads, f"Unexpected request: {url}"
        return payloads[url]

    monkeypatch.setattr(source, "download", download)
    return payloads, manifest, calls


def test_new_service_and_changed_paths_need_no_tooling_update(monkeypatch, tmp_path):
    payloads, manifest, calls = release(monkeypatch)
    inputs = source.save_latest("future-service", tmp_path)
    model_path = Path(inputs["threat_model_file"])
    assert model_path.is_relative_to(tmp_path / ".service-approval/_sources" / COMMIT)
    assert json.loads(model_path.read_text())["metadata"]["name"] == "future-service"
    assert source.check_source(inputs["threat_model_source"], model_path) == []
    assert all("/main/" not in url for url in calls if url != source.HEAD_URL)
    assert len(calls) == 5  # main ref, commit existence, manifest, model, report


@pytest.mark.parametrize("name", ["Amazon FUTURE-SERVICE", "Short future-service", "future-service-api", "FUTURE-SERVICE"])
def test_model_metadata_names_and_iam_arrays(monkeypatch, name):
    release(monkeypatch)
    content, provenance = source.fetch_latest(name)
    assert provenance["namespace"] == "future-service"
    assert validate_export(json.loads(content), name) == []


def test_missing_service_blocks_even_with_local_export_or_cached_snapshot(monkeypatch, tmp_path):
    release(monkeypatch)
    local = tmp_path / "input/model.json"
    local.parent.mkdir()
    local.write_text(json.dumps(export("not-published")))
    with pytest.raises(source.SourceError, match="No published AWS Threat Model"):
        source.save_latest("not-published", tmp_path)
    assert not (tmp_path / ".service-approval").exists()


@pytest.mark.parametrize("failure", ["offline", "403 rate limit", "404", "timeout"])
def test_resume_does_not_contact_upstream_but_new_run_requires_retrieval(monkeypatch, tmp_path, failure):
    _, run, manifest = setup_run(tmp_path)
    original = manifest.read_bytes()

    def unavailable(url):
        raise source.SourceError(failure)

    monkeypatch.setattr(source, "download", unavailable)
    assert source.refresh_manifest(json.loads(original), manifest) == json.loads(original)["inputs"]["threat_model_source"]
    with pytest.raises(source.SourceError, match=failure):
        source.save_latest("dsql", tmp_path)
    assert manifest.read_bytes() == original


@pytest.mark.parametrize("mutation", ["bad-json", "hash", "wrong-service", "empty-threats"])
def test_bad_published_content_stops_without_writing(monkeypatch, tmp_path, mutation):
    payloads, manifest, _ = release(monkeypatch)
    entry = manifest["services"][0]
    url = source.artifact_url(COMMIT, entry["data"]["path"], raw=True)
    model = json.loads(payloads[url])
    if mutation == "hash":
        payloads[url] += b" "
    elif mutation == "bad-report":
        payloads[source.artifact_url(COMMIT, entry["report"]["path"], raw=True)] = b"wrong report"
    else:
        if mutation == "wrong-service":
            model = export("different")
        if mutation == "empty-threats":
            model["threats"] = []
        payloads[url] = b"<html>error</html>" if mutation == "bad-json" else json.dumps(model).encode()
        entry["data"]["sha256"] = hashlib.sha256(payloads[url]).hexdigest()
        payloads[source.artifact_url(COMMIT, "manifest.json", raw=True)] = json.dumps(manifest).encode()
    with pytest.raises(source.SourceError):
        source.save_latest("future-service", tmp_path)
    assert not (tmp_path / ".service-approval").exists()


@pytest.mark.parametrize("path", ["../model.json", "/model.json", "https://example.com/m.json", "data//m.json", "data/./m.json", "data/../../m.json", "data/m.json?download=1"])
def test_manifest_cannot_redirect_artifact_downloads(path):
    with pytest.raises(source.SourceError):
        source.artifact_ref({"path": path, "sha256": "a" * 64}, ".json")


def test_ambiguous_friendly_name_requires_namespace(monkeypatch):
    payloads, manifest, _ = release(monkeypatch, ("one", "two"))
    for entry in manifest["services"]:
        url = source.artifact_url(COMMIT, entry["data"]["path"], raw=True)
        model = json.loads(payloads[url])
        model["metadata"]["identifiers"]["fullName"] = "Same Name"
        payloads[url] = json.dumps(model).encode()
        entry["data"]["sha256"] = hashlib.sha256(payloads[url]).hexdigest()
    payloads[source.artifact_url(COMMIT, "manifest.json", raw=True)] = json.dumps(manifest).encode()
    with pytest.raises(source.SourceError, match="Ambiguous"):
        source.fetch_latest("Same Name")
    assert source.fetch_latest("one")[1]["namespace"] == "one"


def test_missing_provenance_and_tampered_snapshot_block_hooks(tmp_path):
    path, run, manifest = setup_run(tmp_path)
    data = json.loads(manifest.read_text())
    data["inputs"].pop("threat_model_source")
    manifest.write_text(json.dumps(data))
    assert any("provenance required" in error for error in check_run(run))
    path, run, manifest = setup_run(tmp_path)
    path.write_text(path.read_text() + " ")
    assert any("SHA-256 mismatch" in error for error in check_run(run))


def test_resume_keeps_original_snapshot_despite_update_or_removal(monkeypatch, tmp_path):
    release(monkeypatch)
    inputs = source.save_latest("future-service", tmp_path)
    run = tmp_path / ".service-approval/future-service/00-intake"
    run.mkdir(parents=True)
    manifest = run / "intake-manifest.json"
    data = {"service": {"name": "future-service"}, "inputs": inputs}
    manifest.write_text(json.dumps(data))
    saved = manifest.read_bytes()
    # Unrelated commit advancement is fine when the model is byte-identical.
    release(monkeypatch, commit="d" * 40)
    assert source.refresh_manifest(data, manifest)["commit"] == COMMIT
    payloads, index, _ = release(monkeypatch)
    entry = index["services"][0]
    url = source.artifact_url(COMMIT, entry["data"]["path"], raw=True)
    payloads[url] += b"\n"
    entry["data"]["sha256"] = hashlib.sha256(payloads[url]).hexdigest()
    payloads[source.artifact_url(COMMIT, "manifest.json", raw=True)] = json.dumps(index).encode()
    assert source.refresh_manifest(data, manifest)["commit"] == COMMIT
    release(monkeypatch, names=())
    assert source.refresh_manifest(data, manifest)["commit"] == COMMIT
    assert manifest.read_bytes() == saved


def test_verified_readable_links_and_normalized_index(monkeypatch):
    from threat_model_parse import build_threat_model_index
    release(monkeypatch, names=("dsql",))
    content, provenance = source.fetch_latest("dsql")
    alias = "Mitigation.dsql.1"
    url = source.citation_url(provenance, alias)
    assert url == source.artifact_url(COMMIT, "readable/dsql.md") + "#mitigationdsql1"
    assert source.report_anchor("Mitigation.DSQL.Cluster.4") == "mitigationdsqlcluster4"
    assert source.citation_url(provenance, "Invented.Alias") == ""
    index = build_threat_model_index(json.loads(content), source=provenance)
    assert index["mitigations"][0]["threat_model_url"] == url
    assert index["mitigations"][0]["reference_links"] == []


def test_fetch_cli_failure_does_not_emit_inputs(monkeypatch, tmp_path, capsys):
    import fetch_threat_model
    release(monkeypatch, names=())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["fetch_threat_model.py", "--service", "dsql"])
    assert fetch_threat_model.main() == 2
    out = capsys.readouterr()
    assert not out.out
    assert "AWS THREAT MODEL REQUIRED" in out.err


def test_refresh_cli_compatibility_flag_is_offline(monkeypatch, tmp_path, capsys):
    import validate_threat_model_input
    release(monkeypatch, names=())
    _, run, manifest = setup_run(tmp_path)
    monkeypatch.setattr("sys.argv", ["validator", "--manifest", str(manifest), "--refresh"])
    assert validate_threat_model_input.main() == 0
    assert "verified" in capsys.readouterr().out


def test_directive_implementations_remain_guidance_and_validate_in_index():
    from jsonschema import Draft202012Validator
    from threat_model_parse import build_threat_model_index
    model = export("future-service")
    model["implementations"] = [{
        "id": "guidance-1", "alias": "Implementation.FUTURE.1",
        "behavior": "DIRECTIVE", "implementationType": "AWS::*::*::GUIDANCE",
        "implementationGuide": {"guidance": {"description": "Review account access regularly."}},
    }]
    index = build_threat_model_index(model)
    row = index["implementations"][0]
    assert row["behavior"] == "DIRECTIVE"
    assert row["guidance"] == "Review account access regularly."
    assert row["actions"] == []
    schema = json.loads((Path(__file__).parents[2] / "schemas/threat-model-index.schema.json").read_text())
    assert list(Draft202012Validator(schema).iter_errors(index)) == []


@pytest.mark.parametrize("field,value", [("namespace", None), ("report_aliases", None), ("report_aliases", [7])])
def test_malformed_provenance_blocks_before_downstream_consumption(tmp_path, field, value):
    path, run, manifest = setup_run(tmp_path)
    data = json.loads(manifest.read_text())
    data["inputs"]["threat_model_source"][field] = value
    manifest.write_text(json.dumps(data))
    assert check_run(run)


@pytest.mark.parametrize("commit", ["0" * 40, "e" * 40])
def test_fabricated_s3_receipt_cannot_authorize_pipeline(tmp_path, commit):
    """Reproduce a locally consistent model/hash/receipt without AWS intake."""
    path, run, manifest = setup_run(tmp_path, service="s3")
    data = json.loads(manifest.read_text())
    receipt = data["inputs"]["threat_model_source"]
    receipt.pop("intake_verification")
    receipt.update(commit=commit, verified=True, publication_verified=True)
    receipt["data_url"] = source.artifact_url(commit, receipt["data"]["path"])
    receipt["report_url"] = source.artifact_url(commit, receipt["report"]["path"])
    manifest.write_text(json.dumps(data))
    assert source.check_source(receipt, path)
    assert any("Verified online intake required" in error for error in check_run(run))


def test_nonexistent_upstream_commit_cannot_issue_verified_intake(monkeypatch, tmp_path):
    release(monkeypatch)
    original = source.download

    def missing_commit(url):
        if url.startswith(source.COMMIT_ROOT):
            raise source.SourceError("404 nonexistent commit")
        return original(url)

    monkeypatch.setattr(source, "download", missing_commit)
    with pytest.raises(source.SourceError, match="nonexistent commit"):
        source.save_latest("future-service", tmp_path)
    assert not (tmp_path / ".service-approval").exists()


def test_upstream_commit_response_must_match_pinned_reference(monkeypatch, tmp_path):
    payloads, _, _ = release(monkeypatch)
    payloads[f"{source.COMMIT_ROOT}/{COMMIT}"] = json.dumps({"sha": "e" * 40}).encode()
    with pytest.raises(source.SourceError, match="does not match"):
        source.save_latest("future-service", tmp_path)


def test_all_zero_upstream_reference_is_rejected(monkeypatch, tmp_path):
    release(monkeypatch, commit="0" * 40)
    with pytest.raises(source.SourceError, match="no valid commit"):
        source.save_latest("future-service", tmp_path)


def test_verified_receipt_cannot_be_reused_for_changed_bytes_or_metadata(monkeypatch, tmp_path):
    release(monkeypatch)
    inputs = source.save_latest("future-service", tmp_path)
    path = Path(inputs["threat_model_file"])
    receipt = inputs["threat_model_source"]
    path.write_bytes(path.read_bytes() + b"\n")
    assert any("SHA-256 mismatch" in e for e in source.check_source(receipt, path))
    # Updating both the local bytes and the locally claimed hash is insufficient.
    receipt["data"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert any("Verified online intake required" in e for e in source.check_source(receipt, path))


def test_intake_seal_cannot_be_copied_to_a_different_snapshot_path(monkeypatch, tmp_path):
    release(monkeypatch)
    inputs = source.save_latest("future-service", tmp_path)
    clone = tmp_path / "copied.json"
    clone.write_bytes(Path(inputs["threat_model_file"]).read_bytes())
    assert source.check_source(inputs["threat_model_source"], clone)


def test_genuine_offline_resume_checks_seal_and_uses_honest_message(monkeypatch, tmp_path, capsys):
    import validate_threat_model_input
    from source_verification import _key_path
    release(monkeypatch)
    inputs = source.save_latest("future-service", tmp_path)
    run = tmp_path / ".service-approval/future-service/00-intake"
    run.mkdir(parents=True)
    manifest = run / "intake-manifest.json"
    manifest.write_text(json.dumps({"service": {"name": "future-service"}, "inputs": inputs}))
    saved = manifest.read_bytes()
    monkeypatch.setattr(source, "download", lambda url: pytest.fail("Resume must remain offline"))
    monkeypatch.setattr("sys.argv", ["validator", "--manifest", str(manifest)])
    assert validate_threat_model_input.main() == 0
    output = capsys.readouterr().out
    assert "snapshot integrity verified" in output
    assert "published AWS Threat Model prerequisite verified" not in output
    assert manifest.read_bytes() == saved
    # Losing the local trust state must not silently authorize an invented receipt.
    _key_path().unlink()
    assert validate_threat_model_input.main() == 2
    assert not _key_path().exists()


def test_concurrent_intakes_share_one_complete_key(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from source_verification import has_verified_intake, seal_verified_intake
    def seal(number):
        snapshot = tmp_path / f"{number}.json"
        snapshot.write_text("{}")
        receipt = {"commit": COMMIT, "number": number}
        seal_verified_intake(receipt, snapshot)
        return receipt, snapshot
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(seal, range(16)))
    assert all(has_verified_intake(receipt, snapshot) for receipt, snapshot in receipts)
