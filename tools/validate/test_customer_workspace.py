"""Customer-directory CLI and report regression checks using synthetic inputs."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

from validate_state import check_mapping_results

REPO = Path(__file__).resolve().parents[2]


def assembly():
    spec = importlib.util.spec_from_file_location("customer_assembly", REPO / "scripts/map-assemble.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installed_cli_writes_custom_anchor_in_customer_workspace(tmp_path):
    # No code/manifest symlinks or checkout in the customer's working directory.
    directory = tmp_path / ".service-approval/lambda/04-map"
    directory.mkdir(parents=True)
    parsed = {"framework": {"name": "Synthetic Custom", "total_objectives": 1},
              "framework_objectives": [{"objective_id": "CUSTOM-1", "title": "Synthetic",
                                        "domain": "Example", "specification": "Synthetic requirement."}]}
    (directory / "map-framework-parsed.json").write_text(json.dumps(parsed))
    env = {k: v for k, v in os.environ.items() if k != "SERVICE_APPROVAL_WORKSPACE"}
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/anchor-custom-framework.py"), "--slug", "lambda"],
        cwd=tmp_path, env=env, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads((directory / "custom_to_ccmv4_anchor.json").read_text())
    assert set(output["anchors"]) == {"CUSTOM-1"}


def test_coverage_includes_source_links_without_duplicate_controls():
    validated = {"attack_surface": {"applicable_techniques": [
        {"technique_id": "T1485", "technique_name": "Synthetic source-linked technique",
         "tactic_id": "TA0040", "tactic_name": "Impact", "applicability": "HIGH"},
        {"technique_id": "T1048", "technique_name": "Synthetic unlinked technique",
         "tactic_id": "TA0010", "tactic_name": "Exfiltration", "applicability": "HIGH"},
    ]}}
    controls = [
        {"id": "CTRL-ACC-DET-001", "attack_techniques": [], "mitre_techniques": ["T1485"]},
        {"id": "CTRL-ACC-PRV-001", "attack_techniques": ["T1485"], "mitre_techniques": ["T1485"]},
    ]
    result = assembly().build_attack_coverage(validated, controls)
    assert result["covered_by_controls"] == 1
    assert result["uncovered"] == 1
    assert result["technique_to_controls"]["T1485"] == ["CTRL-ACC-DET-001", "CTRL-ACC-PRV-001"]
    assert [r["technique_id"] for r in result["uncovered_techniques"]] == ["T1048"]


def test_custom_framework_completeness_uses_its_own_size():
    doc = {"framework": {"name": "Synthetic", "total_objectives": 2},
           "framework_mapping": [{"objective_id": "CUSTOM-1", "status": "N/A", "controls": []},
                                 {"objective_id": "CUSTOM-2", "status": "N/A", "controls": []}],
           "controls": []}
    assert not [e for e in check_mapping_results(doc) if "CHECK-S13 framework_mapping" in e]
    doc["framework_mapping"].pop()
    assert any("expected 2" in e for e in check_mapping_results(doc))
    doc["framework_mapping"].append(dict(doc["framework_mapping"][0]))
    assert any("duplicate objective IDs" in e for e in check_mapping_results(doc))
