"""Tests for the deterministic Canopy-factual validator.

A control/decision citing citation.type==canopy must name a mitigation alias
that exists in the Canopy export, and (when it names operations) the gated op
must be one the cited mitigation actually governs. Fabricated or drifted Canopy
citations fail.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_canopy_facts as vcf  # noqa: E402


def _canopy() -> dict:
    """A minimal Canopy-shaped export (top-level mitigations[], entities[] with
    no nested mitigations so is_canopy_shape() detects it)."""
    return {
        "entities": [{"id": "e1", "entityType": "AWS::BedrockAgentCore::Runtime"}],
        "mitigations": [
            {
                "id": "m1",
                "alias": "Mitigation.AGENTCORE.AgentRuntime.1",
                "statement": "Require encryption on runtime creation.",
                "mappings": [{"type": "ENTITY", "id": "e1"}],
                "configurationRequestParameters": [
                    {"service": "bedrock-agentcore", "operation": "CreateAgentRuntime",
                     "paths": [{"path": "$.encryptionKeyArn"}]},
                ],
            }
        ],
        "threats": [
            {"alias": "Threat.AGENTCORE.AgentRuntime.1", "requestParameters": []}
        ],
        "implementations": [
            {
                "id": "i1",
                "alias": "Implementation.AGENTCORE.AgentRuntime.1",
                "behavior": "PREVENTIVE",
                "implementationType": "AWS::ORGANIZATIONS::SERVICE_CONTROL_POLICY",
                "implementationGuide": {
                    "authorization_policy": {
                        "governed_resource_type": "AWS::BedrockAgentCore::Runtime",
                        "governed_iam_permissions": [
                            {"actions": ["bedrock-agentcore:*"],
                             "resources": ["*"], "condition_keys": ["aws:ResourceOrgID"]},
                        ],
                    }
                },
                "mappings": [{"type": "MITIGATION", "id": "m1"}],
            }
        ],
    }


def test_implementation_alias_citation_passes() -> None:
    """A Canopy citation may anchor to an implementations[] alias (the
    Canopy-first-across-all-families behavior), not only a mitigation/threat."""
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-001",
         "plan_actions": ["bedrock-agentcore:*"],
         "citation": {"type": "canopy", "id": "Implementation.AGENTCORE.AgentRuntime.1"}}
    ]}
    assert vcf.check(_canopy(), plan, None) == []


def test_fabricated_implementation_alias_fails() -> None:
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-002",
         "plan_actions": ["bedrock-agentcore:CreateAgentRuntime"],
         "citation": {"type": "canopy", "id": "Implementation.NOPE.1"}}
    ]}
    errors = vcf.check(_canopy(), plan, None)
    assert any("does not exist" in e and "CTRL-ORG-PRV-002" in e for e in errors), errors


def test_valid_canopy_citation_passes() -> None:
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-001",
         "actions": ["bedrock-agentcore:CreateAgentRuntime"],
         "citation": {"type": "canopy", "id": "Mitigation.AGENTCORE.AgentRuntime.1"}}
    ]}
    assert vcf.check(_canopy(), None, mapping) == []


def test_fabricated_alias_fails() -> None:
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-002",
         "actions": ["bedrock-agentcore:CreateAgentRuntime"],
         "citation": {"type": "canopy", "id": "Mitigation.DOES.NOT.EXIST"}}
    ]}
    errors = vcf.check(_canopy(), None, mapping)
    assert any("does not exist" in e and "CTRL-ORG-PRV-002" in e for e in errors), errors


def test_operation_drift_fails() -> None:
    """The cited mitigation governs CreateAgentRuntime; a control claiming a
    DeleteAgentRuntime action under it has drifted."""
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-003",
         "actions": ["bedrock-agentcore:DeleteAgentRuntime"],
         "citation": {"type": "canopy", "id": "Mitigation.AGENTCORE.AgentRuntime.1"}}
    ]}
    errors = vcf.check(_canopy(), None, mapping)
    assert any("not among the operations" in e for e in errors), errors


def test_canopy_citation_without_id_fails() -> None:
    plan = {"decisions": [
        {"control_id": "CTRL-ORG-PRV-004", "decision": "GENERATE_SCP",
         "citation": {"type": "canopy"}}
    ]}
    errors = vcf.check(_canopy(), plan, None)
    assert any("names no mitigation alias" in e for e in errors), errors


def test_non_canopy_citations_ignored() -> None:
    """A reference/service-doc citation is not checked by this validator."""
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-005", "actions": ["bedrock-agentcore:CreateAgentRuntime"],
         "citation": {"type": "reference", "id": "scp-ex"}}
    ]}
    assert vcf.check(_canopy(), None, mapping) == []


def test_no_operations_named_skips_op_check() -> None:
    """A canopy-cited control with a valid alias but no actions[] passes on alias
    existence alone (resource-level mitigations name no operations)."""
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-006", "actions": [],
         "citation": {"type": "canopy", "id": "Mitigation.AGENTCORE.AgentRuntime.1"}}
    ]}
    assert vcf.check(_canopy(), None, mapping) == []


def test_non_canopy_file_is_noop() -> None:
    """If the provided file isn't Canopy-shaped, the check stays quiet."""
    not_canopy = {"foo": "bar"}
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-007", "citation": {"type": "canopy", "id": "x"}}
    ]}
    assert vcf.check(not_canopy, None, mapping) == []


def test_check_service_locates_canopy_via_manifest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    root = tmp_path / ".service-approval" / "agentcore"
    (root / "00-intake").mkdir(parents=True)
    (root / "04-map").mkdir(parents=True)
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "agentcore-canopy.json").write_text(json.dumps(_canopy()))
    (root / "00-intake" / "intake-manifest.json").write_text(json.dumps(
        {"inputs": {"input_folder": "input"}}
    ))
    # A fabricated alias in the mapping must be caught end-to-end.
    (root / "04-map" / "mapping-results.json").write_text(json.dumps(
        {"controls": [
            {"id": "CTRL-ORG-PRV-001", "actions": ["bedrock-agentcore:CreateAgentRuntime"],
             "citation": {"type": "canopy", "id": "NOPE"}}
        ]}
    ))
    errors = vcf.check_service(root)
    assert any("does not exist" in e for e in errors), errors


def test_check_service_no_canopy_is_noop(tmp_path: Path) -> None:
    root = tmp_path / ".service-approval" / "svc"
    (root / "04-map").mkdir(parents=True)
    assert vcf.check_service(root) == []


# --- Field-name reconcile: map citations use source + mitigation_alias --------

def test_map_citation_source_shape_valid_passes() -> None:
    """The map/framework-mapping citation shape (source + mitigation_alias) is
    recognised and passes when the alias exists."""
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-010",
         "actions": ["bedrock-agentcore:CreateAgentRuntime"],
         "citation": {"source": "canopy",
                      "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1"}}
    ]}
    assert vcf.check(_canopy(), None, mapping) == []


def test_map_citation_source_shape_fabricated_alias_fails() -> None:
    """Regression: a source-shaped map citation with a fabricated alias is now
    caught (previously it sailed past the type/id-only reader)."""
    mapping = {"controls": [
        {"id": "CTRL-ORG-PRV-011", "actions": [],
         "citation": {"source": "canopy", "mitigation_alias": "Mitigation.NOPE"}}
    ]}
    errors = vcf.check(_canopy(), None, mapping)
    assert any("does not exist" in e and "CTRL-ORG-PRV-011" in e for e in errors), errors


# --- framework-mapping.json rows (MAPPED checked, UNCERTAIN exempt) -----------

def _fw_mapped(status: str, citation: dict) -> dict:
    return {"framework_mapping": [
        {"objective_id": "IAM-01", "status": status, "coverage": "Partially Covered",
         "controls": [
             {"control_id": "CTRL-ORG-PRV-020", "coverage_level": "Partial Coverage",
              "rationale": "r", "citation": citation}
         ]}
    ]}


def test_fw_mapped_mapped_row_verbatim_statement_passes() -> None:
    cit = {"source": "canopy", "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1",
           "mitigation_statement": "Require encryption on runtime creation."}
    assert vcf.check(_canopy(), None, None, _fw_mapped("MAPPED", cit)) == []


def test_fw_mapped_mapped_row_invented_statement_fails() -> None:
    """A real alias but a statement not present in Canopy is a provenance FAIL."""
    cit = {"source": "canopy", "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1",
           "mitigation_statement": "Delete all runtimes nightly."}
    errors = vcf.check(_canopy(), None, None, _fw_mapped("MAPPED", cit))
    assert any("not found verbatim" in e for e in errors), errors


def test_fw_mapped_verbatim_normalizes_case_and_punctuation() -> None:
    """A legit citation that differs only by case/whitespace/trailing punctuation
    still passes (normalized comparison)."""
    cit = {"source": "canopy", "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1",
           "mitigation_statement": "  require ENCRYPTION on   runtime creation  "}
    assert vcf.check(_canopy(), None, None, _fw_mapped("MAPPED", cit)) == []


def test_fw_mapped_uncertain_row_is_exempt() -> None:
    """UNCERTAIN rows are the honesty escape hatch — not checked even with a bad
    alias/statement."""
    cit = {"source": "canopy", "mitigation_alias": "Mitigation.NOPE",
           "mitigation_statement": "invented"}
    assert vcf.check(_canopy(), None, None, _fw_mapped("UNCERTAIN", cit)) == []


def test_fw_mapped_no_quoted_statement_skips_verbatim() -> None:
    """A MAPPED row with a valid alias but no quoted statement passes on alias
    existence alone (verbatim check applies only when text is quoted)."""
    cit = {"source": "canopy", "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1"}
    assert vcf.check(_canopy(), None, None, _fw_mapped("MAPPED", cit)) == []


def test_assessment_gap_citation_is_not_canopy() -> None:
    """An assessment_gap-sourced citation names no Canopy alias and is out of
    scope for the Canopy-verbatim check."""
    cit = {"source": "assessment_gap", "objective_requirement": "req"}
    assert vcf.check(_canopy(), None, None, _fw_mapped("MAPPED", cit)) == []


def test_check_service_reads_fw_mapped(tmp_path: Path, monkeypatch) -> None:
    """check_service loads map-framework-mapped.json and catches a non-verbatim
    statement end-to-end."""
    monkeypatch.chdir(tmp_path)
    root = tmp_path / ".service-approval" / "agentcore"
    (root / "00-intake").mkdir(parents=True)
    (root / "04-map").mkdir(parents=True)
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "c.json").write_text(json.dumps(_canopy()))
    (root / "00-intake" / "intake-manifest.json").write_text(json.dumps(
        {"inputs": {"input_folder": "input"}}
    ))
    (root / "04-map" / "map-framework-mapped.json").write_text(json.dumps(
        _fw_mapped("MAPPED", {"source": "canopy",
                              "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1",
                              "mitigation_statement": "totally invented text"})
    ))
    errors = vcf.check_service(root)
    assert any("not found verbatim" in e for e in errors), errors


# --- CLI: blocks by default, --advisory demotes to exit 0 ---------------------

def _write_run(tmp_path: Path, fw_mapped: dict) -> Path:
    root = tmp_path / ".service-approval" / "svc"
    (root / "00-intake").mkdir(parents=True)
    (root / "04-map").mkdir(parents=True)
    inp = tmp_path / "input"
    inp.mkdir()
    (inp / "c.json").write_text(json.dumps(_canopy()))
    (root / "00-intake" / "intake-manifest.json").write_text(json.dumps(
        {"inputs": {"input_folder": "input"}}
    ))
    (root / "04-map" / "map-framework-mapped.json").write_text(json.dumps(fw_mapped))
    return root


def test_cli_blocks_on_violation_by_default(tmp_path: Path, monkeypatch) -> None:
    import subprocess
    import sys as _sys
    _write_run(tmp_path, _fw_mapped(
        "MAPPED", {"source": "canopy",
                   "mitigation_alias": "Mitigation.AGENTCORE.AgentRuntime.1",
                   "mitigation_statement": "invented"}))
    script = Path(__file__).resolve().parent / "validate_canopy_facts.py"
    # Default: block (exit 2). --strict is an accepted no-op alias for the default.
    default = subprocess.run([_sys.executable, str(script), "--slug", "svc"],
                             cwd=str(tmp_path), capture_output=True, text=True)
    strict = subprocess.run([_sys.executable, str(script), "--slug", "svc", "--strict"],
                            cwd=str(tmp_path), capture_output=True, text=True)
    # --advisory demotes to exit 0.
    advisory = subprocess.run([_sys.executable, str(script), "--slug", "svc", "--advisory"],
                              cwd=str(tmp_path), capture_output=True, text=True)
    assert default.returncode == 2, default.stderr
    assert strict.returncode == 2, strict.stderr
    assert advisory.returncode == 0, advisory.stderr
