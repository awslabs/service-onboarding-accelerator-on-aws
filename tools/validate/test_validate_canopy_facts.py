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
    }


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
    assert any("no citation.id" in e for e in errors), errors


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
