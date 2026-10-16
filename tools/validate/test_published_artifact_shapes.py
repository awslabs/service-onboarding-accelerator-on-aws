"""Synthetic regressions for formats exercised by the published-model run."""
import copy
import json

import pytest

from threat_model_parse import parse_threat_model_implementations
from validate_config_support import check_artifact
from validate_controls import check_resource_types, check_service_prefix
from validate_controls import _categorize_file
from validate_controls import check_condition_keys, check_sar_condition_keys_14a
from validate_cross import check_lambda_handler_completeness, check_resource_type_consistency
from validate_threat_model_facts import mitigation_operations


@pytest.mark.parametrize("shape", ["list", "legacy", "dict"])
@pytest.mark.parametrize("filename", ["config-rules.json", "config-org-rules.json"])
def test_config_checks_inspect_each_supported_container(tmp_path, shape, filename):
    rule = {"rule_name": "synthetic-rule", "source_type": "CUSTOM_LAMBDA",
            "resource_types": ["AWS::Example::Unsupported"]}
    artifact = ({"rules": [rule]} if shape == "list" else
                {"rules": {"named": rule}} if shape == "dict" else {"named": rule})
    detective = tmp_path / "detective"
    detective.mkdir()
    path = detective / filename
    path.write_text(json.dumps(artifact))
    validated = {"assets": [{"cfn_type": "AWS::Example::Supported"}]}
    assert len(check_resource_types(str(path), artifact, validated)) == 1
    assert len(check_resource_type_consistency(str(tmp_path), validated)) == 1
    assert check_artifact(str(path), {"AWS::Example::Supported"})[0]["status"] == "UNSUPPORTED"
    errors = check_lambda_handler_completeness(str(tmp_path))
    assert len(errors) == 2
    handler = detective / "config-rule-lambdas/synthetic-rule"
    handler.mkdir(parents=True)
    (handler / "handler.py").write_text("def handler(event, context): return {}\n")
    (handler / "requirements.txt").write_text("boto3\n")
    assert check_lambda_handler_completeness(str(tmp_path)) == []
    assert _categorize_file(f"/run/05-recommended-guidance/detective/{filename}") == "config_rules"


@pytest.mark.parametrize("field", ["event_pattern", "EventPattern"])
def test_eventbridge_casing_does_not_bypass_source_check(field):
    rule = {"rule_name": "synthetic", field: {
        "source": ["aws.wrong"], "detail": {"eventSource": ["wrong.amazonaws.com"]}}}
    errors = check_service_prefix("eventbridge-rules.json", {"rules": [rule]},
                                  {"service_prefix": "example"})
    assert len(errors) == 2


def test_explicit_cross_service_events_validate_declared_api_prefix():
    rule = {"rule_name": "dependency", "cross_service": True,
            "monitored_parameters": {"dependency:UpdateThing": ["$.Thing"]},
            "EventPattern": {"source": ["aws.dependency"],
                             "detail": {"eventSource": ["dependency.amazonaws.com"]}}}
    validated = {"service_prefix": "example"}
    assert check_service_prefix("", {"rules": [rule]}, validated) == []
    rule["EventPattern"]["source"] = ["aws.wrong"]
    assert len(check_service_prefix("", {"rules": [rule]}, validated)) == 1
    del rule["monitored_parameters"]
    assert "does not declare" in check_service_prefix("", {"rules": [rule]}, validated)[0]


def test_published_implementation_guides_preserve_operations_and_policy_details():
    guides = [
        {"authorizationPolicy": {"governedResourceType": "AWS::Example::Thing",
          "governedIamPermissions": [{"actions": [{"action": "example:ReadThing"}],
          "resources": [{"resource": "*"}], "conditionKeys": [{"key": "aws:ResourceOrgID",
          "alternatives": [{"key": "aws:ResourceAccount"}]}]}]}},
        {"configRule": {"ruleType": "PERIODIC", "governedApiOperations": [
            {"service": "example", "operation": "GetThing",
             "responseParameters": [{"path": "$.Thing"}]}]}},
        {"cloudtrailEvent": {"monitoredOperations": ["UpdateThing"]}},
        {"cloudformationHook": {"governedResourceProperties": [
            {"resourceType": "AWS::Example::Thing", "properties": [{"path": "$.Encryption"}]}]}},
        {"roleTrustPolicy": {"governedIamPermissions": [
            {"principal": {"AWS": "arn:aws:iam::123456789012:root"},
             "actions": [{"action": "sts:AssumeRole"}]}]}},
        {"declarativePolicy": {"policyType": "example", "governedAttributes": [
            {"attribute": "encryption"}]}},
    ]
    model = {"implementations": [
        {"id": str(i), "alias": f"Implementation.EXAMPLE.{i}", "implementationGuide": guide}
        for i, guide in enumerate(guides)
    ]}
    original = copy.deepcopy(model)
    rows = parse_threat_model_implementations(model)
    assert rows[0]["actions"] == ["example:ReadThing"]
    assert rows[0]["resources"] == ["*"]
    assert rows[0]["condition_keys"] == ["aws:ResourceOrgID", "aws:ResourceAccount"]
    assert rows[0]["governed_resource_type"] == "AWS::Example::Thing"
    assert rows[1]["config_rule_type"] == "PERIODIC"
    assert rows[1]["governed_api_operations"][0]["response_parameters"] == [{"path": "$.Thing"}]
    assert rows[2]["monitored_operations"] == [{"operation": "UpdateThing"}]
    assert rows[3]["governed_resource_properties"][0]["resource_type"] == "AWS::Example::Thing"
    assert rows[4]["authorization_policy"][0]["principal"]["AWS"].endswith(":root")
    assert rows[4]["actions"] == ["sts:AssumeRole"]
    assert rows[5]["policy_type"] == "example"
    assert mitigation_operations(model, "Implementation.EXAMPLE.1") == {"getthing"}
    assert mitigation_operations(model, "Implementation.EXAMPLE.2") == {"updatething"}
    assert model == original


@pytest.mark.parametrize("check", [check_condition_keys, check_sar_condition_keys_14a])
@pytest.mark.parametrize("shape", ["cross_service", "context_only"])
def test_cross_service_keys_require_verification_and_supported_policy_type(check, shape):
    key = {"key": "example:SourceOriginArn", "verified": True,
           "doc_url": "https://docs.aws.amazon.com/example/latest/guide/caller-context.html",
           "usable_in": ["identity-based policies", "service control policies"],
           "not_usable_in": ["resource-based policies"]}
    if shape == "context_only":
        key["policy_types"] = ["identity-based", "SCP"]
        key["not_supported_in"] = key.pop("not_usable_in")
        key.pop("usable_in")
    validated = {"capabilities": {"iam": {shape + "_condition_keys": [key]}}}
    data = {"Statement": [{"Sid": "CallerContext", "Effect": "Deny",
                          "Action": "dependency:Read", "Resource": "*",
                          "Condition": {"ArnNotEquals": {
                              "example:SourceOriginArn": "arn:aws:example:region:account:origin/test"}}}]}
    for filename in ("scp-policy.json", "iam-policy.json", "permission-boundary.json"):
        assert check(f"/run/preventive/{filename}", data, validated) == []
    assert check("/run/preventive/resource-policy.json", data, validated)
    key["verified"] = False
    assert check("/run/preventive/scp-policy.json", data, validated)
    key["verified"] = True
    key["doc_url"] = "https://untrusted.example/claim"
    assert check("/run/preventive/scp-policy.json", data, validated)


@pytest.mark.parametrize("check", [check_condition_keys, check_sar_condition_keys_14a])
@pytest.mark.parametrize("key", ["aws:VpceOrgID", "aws:VpceAccount", "aws:VpceOrgPaths"])
def test_known_endpoint_organization_key_is_not_rejected_by_name(check, key):
    validated = {"capabilities": {"iam": {"condition_keys": [{"key": "example:Setting"}]}}}
    data = {"Statement": [{"Sid": "NetworkPerimeter", "Effect": "Deny",
                          "Action": "example:Read", "Resource": "*",
                          "Condition": {"StringNotEqualsIfExists": {key: "synthetic-policy-value"}}}]}
    assert not check("/run/preventive/resource-policy.json", data, validated)
    data["Statement"][0]["Condition"] = {"StringNotEquals": {"aws:InventedEndpointKey": "x"}}
    assert check("/run/preventive/resource-policy.json", data, validated)
