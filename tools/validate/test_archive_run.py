"""Upgrade regressions: retire legacy reports without exempting active runs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_validate_threat_model_input import setup_run
from validate_pipeline_integrity import validate_pipeline
from validate_threat_model_input import check_artifact_prerequisite

REPO = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("archive_run", REPO / "tools/archive_run.py")
archive_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive_module)
archive_run = archive_module.archive_run


def legacy_run(workspace):
    root = workspace / ".service-approval/old-service"
    (root / "00-intake").mkdir(parents=True)
    (root / "00-intake/intake-manifest.json").write_text(
        json.dumps({"service": {"name": "old-service"}, "inputs": {}}))
    (root / "06-summarize").mkdir()
    (root / "06-summarize/SUMMARY-REPORT.md").write_text("# Historical completed report\n")
    (root / "05-recommended-guidance/preventive").mkdir(parents=True)
    (root / "05-recommended-guidance/preventive/old.json").write_text("{}")
    (root / "pipeline.log").write_text(
        "2026-05-01T00:00:00Z [06-summarize] [pipeline:complete:FINALIZED] done\n")
    return root


def test_legacy_archive_preserves_files_and_does_not_block_new_run(tmp_path):
    old = legacy_run(tmp_path)
    original = {str(p.relative_to(old)): p.read_bytes() for p in old.rglob("*") if p.is_file()}
    assert any(e.startswith("P0 FAIL") for e in validate_pipeline(tmp_path))
    destination = archive_run(tmp_path, "old-service")
    assert not old.exists()
    assert {str(p.relative_to(destination / "run")): p.read_bytes()
            for p in (destination / "run").rglob("*") if p.is_file()} == original
    receipt = json.loads((destination / "archive.json").read_text())
    assert receipt["files_sha256"] == {p: hashlib.sha256(b).hexdigest() for p, b in original.items()}
    assert "not validated" in receipt["status"]
    _, active, _ = setup_run(tmp_path, service="lambda")
    (active / "pipeline.log").write_text("\n".join(
        f"2026-10-19T00:00:00Z [01-assess] [mcp:awsknowledge:call] lookup {n}"
        for n in range(10)))
    assert validate_pipeline(tmp_path) == []
    # Archived controls must not trigger the Stop hook's separate cross sweep.
    result = subprocess.run([sys.executable, str(REPO / "tools/validate/hook_stop.py")],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert check_artifact_prerequisite(str(destination / "run/04-map/mapping-results.json"))


def test_active_finalized_run_still_requires_verified_intake_and_current_reporting(tmp_path):
    archive_run_root = legacy_run(tmp_path)
    archive_run(tmp_path, archive_run_root.name)
    _, active, manifest = setup_run(tmp_path, service="lambda")
    (active / "pipeline.log").write_text(
        "2026-10-19T00:00:00Z [06-summarize] [pipeline:complete:FINALIZED] done\n")
    data = json.loads(manifest.read_text())
    data["inputs"]["threat_model_source"].pop("intake_verification")
    manifest.write_text(json.dumps(data))
    assert any(e.startswith("P0 FAIL") for e in validate_pipeline(tmp_path))
    setup_run(tmp_path, service="lambda")
    (active / "04-map").mkdir()
    (active / "04-map/framework-mapping.md").write_text("# Missing current disclosure\n")
    assert any(e.startswith("P14 FAIL") for e in validate_pipeline(tmp_path))


@pytest.mark.parametrize("slug", ["../lambda", "_archive", "lambda/../../input", ""])
def test_archive_refuses_unsafe_slugs(tmp_path, slug):
    with pytest.raises(ValueError, match="Invalid"):
        archive_run(tmp_path, slug)


def test_archive_keeps_shared_snapshots_and_never_overwrites_prior_archive(tmp_path):
    snapshot = tmp_path / ".service-approval/_sources/shared/model.json"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("original snapshot")
    legacy_run(tmp_path)
    first = archive_run(tmp_path, "old-service")
    legacy_run(tmp_path)
    second = archive_run(tmp_path, "old-service")
    assert first != second and (first / "run").exists() and (second / "run").exists()
    assert snapshot.read_text() == "original snapshot"


def test_archive_refuses_symlinked_run_without_touching_target(tmp_path):
    old = legacy_run(tmp_path)
    (old.parent / "alias").symlink_to(old, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        archive_run(tmp_path, "alias")
    assert old.exists()
