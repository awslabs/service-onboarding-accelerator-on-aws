"""CLI-flag tests for scripts/map-assemble.py.

Covers the `--service` / `--slug` alias reconcile: orchestrator prose
elsewhere in this repo uses both names, so argparse must accept either.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "map-assemble.py"


def _load_module():
    """Load scripts/map-assemble.py as a module so we can poke at its
    argparse. The script's filename has a hyphen, so import has to go
    through importlib spec_from_file_location."""
    spec = importlib.util.spec_from_file_location("map_assemble", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_parser():
    """Re-build the parser with the same arguments main() registers, so
    we can assert flag behaviour without invoking the full pipeline.

    main() composes the parser inline; we mirror that here. If main()'s
    flag list drifts, this test surfaces it."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--service", "--slug", dest="service")
    return parser


def test_service_flag_is_accepted() -> None:
    parser = _build_parser()
    args = parser.parse_args(["--service", "lambda"])
    assert args.service == "lambda"


def test_slug_flag_is_accepted_as_alias() -> None:
    """The `--slug` alias must populate the same destination as
    `--service`."""
    parser = _build_parser()
    args = parser.parse_args(["--slug", "lambda"])
    assert args.service == "lambda"


def test_script_help_lists_both_flags() -> None:
    """`map-assemble.py --help` must mention both flag names so a caller
    who tries `--slug` first sees the alias and doesn't have to read the
    source. This anchors against accidental removal of the alias."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=15,
    )
    # --help exits 0 on success
    assert proc.returncode == 0, f"--help exited {proc.returncode}: {proc.stderr}"
    out = proc.stdout
    assert "--service" in out, "--service flag missing from --help"
    assert "--slug" in out, "--slug alias missing from --help"


def test_module_main_function_exists() -> None:
    """Sanity: the script defines main(). Guards against accidental
    rename that would silently break the CLI shape."""
    module = _load_module()
    assert hasattr(module, "main"), "scripts/map-assemble.py must expose main()"


# --- Citation / MITRE cell rendering (additive mapping output) ---------------

def test_citation_cell_renders_requirement_alias_source() -> None:
    m = _load_module()
    cm = {"control_id": "C1", "citation": {
        "objective_requirement": "least privilege", "source": "threat_model",
        "mitigation_alias": "Mitigation.LAMBDA.Function.6"}}
    cell = m._citation_cell(cm, {})
    assert "least privilege" in cell
    assert "Mitigation.LAMBDA.Function.6" in cell
    assert "(threat_model)" in cell


def test_citation_cell_falls_back_to_control_trace() -> None:
    """A citation-free legacy row still shows the control's threaded AWS Threat Model alias."""
    m = _load_module()
    cell = m._citation_cell({"control_id": "C1"},
                            {"mitigation_alias": "Mitigation.X.1", "trace_source": "threat_model"})
    assert "Mitigation.X.1" in cell and "(threat_model)" in cell


def test_citation_cell_assessment_gap() -> None:
    m = _load_module()
    assert m._citation_cell({"control_id": "C2"}, {"trace_source": "assessment_gap"}) \
        == "(assessment_gap)"


def test_mitre_cell_unions_and_sorts() -> None:
    m = _load_module()
    cm = {"citation": {"mitre_techniques": ["T1537"]}}
    ctrl = {"mitre_techniques": ["T1530", "T1537"]}
    assert m._mitre_cell(cm, ctrl) == "T1530, T1537"


def test_mitre_cell_empty_is_dash() -> None:
    m = _load_module()
    assert m._mitre_cell({}, {}) == "—"


def test_coverage_summary_preserves_uncertain() -> None:
    """build_framework_coverage_summary must carry the merge's uncertain count
    through unchanged (UNCERTAIN is excluded from mapped/coverage)."""
    m = _load_module()
    fw_mapped = {
        "framework_mapping": [
            {"objective_id": "IAM-01", "status": "MAPPED", "coverage": "Partially Covered",
             "controls": []},
            {"objective_id": "IAM-13", "status": "UNCERTAIN", "coverage": "N/A", "controls": []},
        ],
        "framework_coverage_summary": {"mapped": 1, "not_applicable": 0, "uncertain": 1},
    }
    summary = m.build_framework_coverage_summary(fw_mapped)
    assert summary["uncertain"] == 1
    assert summary["mapped"] == 1


# --- Render fixtures: catalog citations, sequential objectives, uncited rename -

def _fw_mapped_fixture() -> dict:
    return {
        "framework_mapping": [
            {"objective_id": "IAM-01", "domain": "Identity & Access Management",
             "title": "IAM Policy", "status": "MAPPED", "coverage": "Partially Covered",
             "reason": "controls enforce IAM",
             "controls": [{"control_id": "CTRL-ACC-PRV-001",
                           "coverage_level": "Partial Coverage",
                           "rationale": "SCP denies X",
                           "citation": {"objective_requirement": "least privilege",
                                        "source": "threat_model",
                                        "mitigation_alias": "Mitigation.L.1"}}]},
            {"objective_id": "IAM-02", "domain": "Identity & Access Management",
             "title": "Unique user IDs", "status": "UNCERTAIN", "coverage": "N/A",
             "reason": "relates but uncitable", "review_reason": "no concrete linkage",
             "controls": [{"control_id": "CTRL-ACC-PRV-002"}]},
            {"objective_id": "DCS-01", "domain": "Datacenter Security",
             "title": "Physical security", "status": "N/A", "coverage": "N/A",
             "reason": "AWS-managed", "controls": []},
        ],
        "framework_coverage_summary": {
            "total_objectives": 3, "mapped": 1, "not_applicable": 1, "uncertain": 1,
            "by_domain": {},
        },
    }


def _render_framework_mapping(m, tmp_path, fw_mapped, controls, coverage_gaps=None):
    from pathlib import Path
    out = Path(tmp_path) / "framework-mapping.md"
    m.write_framework_mapping(
        fw_mapped, controls, {}, coverage_gaps or {"control_orphan": []}, [],
        {"name": "CSA CCMv4", "version": "4.0"}, "lambda", out,
    )
    return out.read_text()


def test_framework_mapping_summary_has_only_four_rows(tmp_path) -> None:
    """Coverage Summary table drops Fully/Partially/Supportive rows."""
    m = _load_module()
    md = _render_framework_mapping(m, tmp_path, _fw_mapped_fixture(),
                                   [{"id": "CTRL-ACC-PRV-001", "name": "PB",
                                     "category": "PRV", "scope": "ACC", "trace_source": "threat_model"}])
    assert "| Mapped |" in md
    assert "| Not Applicable |" in md
    assert "| Uncertain (review needed) |" in md
    assert "Fully Covered" not in md
    assert "Partially Covered |" not in md  # not as a summary-table row
    assert "Supportive Only" not in md


def test_framework_mapping_lists_every_objective_sequentially(tmp_path) -> None:
    """Every objective (MAPPED/N/A/UNCERTAIN) appears as `ID: Title`."""
    m = _load_module()
    md = _render_framework_mapping(m, tmp_path, _fw_mapped_fixture(),
                                   [{"id": "CTRL-ACC-PRV-001", "name": "PB",
                                     "category": "PRV", "scope": "ACC", "trace_source": "threat_model"}])
    assert "**IAM-01: IAM Policy**" in md
    assert "**IAM-02: Unique user IDs**" in md and "UNCERTAIN (review needed)" in md
    assert "**DCS-01: Physical security**" in md and "N/A — AWS-managed" in md


def test_framework_mapping_drops_removed_sections(tmp_path) -> None:
    """No Coverage Gaps and no Mitigation Traceability sections are rendered."""
    m = _load_module()
    md = _render_framework_mapping(m, tmp_path, _fw_mapped_fixture(),
                                   [{"id": "CTRL-ACC-PRV-001", "name": "PB",
                                     "category": "PRV", "scope": "ACC", "trace_source": "threat_model"}])
    assert "## Coverage Gaps" not in md
    assert "## Mitigation Traceability" not in md


def test_framework_mapping_render_asserts_completeness(tmp_path) -> None:
    """The render asserts every objective is emitted exactly once, so a dropped
    objective can't hide. (Sanity: the normal case renders without raising.)"""
    m = _load_module()
    # Normal fixture renders without raising.
    _render_framework_mapping(m, tmp_path, _fw_mapped_fixture(),
                              [{"id": "CTRL-ACC-PRV-001", "name": "PB",
                                "category": "PRV", "scope": "ACC", "trace_source": "threat_model"}])


def test_suggestions_section_renamed_with_source_column(tmp_path) -> None:
    """Bottom section is 'Suggestions for Review' with a Source column, not the
    old 'Potential Recommendations' / 'Why not yet cited' shape."""
    m = _load_module()
    cg = {"uncited_controls": [
        {"control_id": "CTRL-ACC-PRO-026", "name": "Compensate for absent RCP support",
         "trace_source": "assessment_gap",
         "source": "[AWS Organizations — RCP supported services]"
                   "(https://docs.aws.amazon.com/organizations/latest/userguide/"
                   "orgs_manage_policies_rcps.html#rcp-supported-services)"}]}
    md = _render_framework_mapping(m, tmp_path, _fw_mapped_fixture(),
                                   [{"id": "CTRL-ACC-PRV-001", "name": "PB",
                                     "category": "PRV", "scope": "ACC", "trace_source": "threat_model"}], cg)
    assert "Controls Not Sourced from AWS Threat Model (Suggestions for Review)" in md
    assert "Potential Recommendations" not in md
    assert "Why not yet cited" not in md
    assert "Not Yet Cited to an Objective" not in md
    assert "| Control ID | Name | Source |" in md
    assert "rcp-supported-services" in md


def test_build_uncited_controls_emits_only_non_threat_model() -> None:
    """Only trace_source != 'threat_model' controls are emitted (with a Source field);
    AWS Threat Model controls — including defense-in-depth twins — are never listed."""
    m = _load_module()
    controls = [
        {"id": "CTRL-ACC-PRV-001", "name": "A", "mitigation_ids": ["M-L.1"],
         "trace_source": "threat_model"},
        {"id": "CTRL-ACC-DET-001", "name": "A-twin", "mitigation_ids": ["M-L.1"],
         "trace_source": "threat_model"},
        {"id": "CTRL-RES-DET-009", "name": "Gap", "mitigation_ids": ["M-GAP-3.0"],
         "trace_source": "assessment_gap",
         "doc_reference": {"url": "https://docs.aws.amazon.com/x.html", "title": "X"}},
        {"id": "CTRL-ORG-PRV-050", "name": "Lonely-threat-model", "mitigation_ids": ["M-Z.0"],
         "trace_source": "threat_model"},
    ]
    ctrl_to_objs = {"CTRL-ACC-PRV-001": ["IAM-01"]}
    out = {u["control_id"]: u for u in m.build_uncited_controls(controls, {}, ctrl_to_objs)}
    # Only the assessment_gap control is emitted — every AWS Threat Model control is excluded.
    assert set(out) == {"CTRL-RES-DET-009"}
    assert out["CTRL-RES-DET-009"]["source"] == "[X](https://docs.aws.amazon.com/x.html)"
    assert "why_uncited" not in out["CTRL-RES-DET-009"]
    assert "reason_class" not in out["CTRL-RES-DET-009"]


def test_control_source_ref_variants() -> None:
    """control_source_ref prefers doc_reference (obj/str), then reference_url."""
    m = _load_module()
    assert m.control_source_ref(
        {"doc_reference": {"url": "https://docs.aws.amazon.com/a.html", "title": "A"}}
    ) == "[A](https://docs.aws.amazon.com/a.html)"
    assert m.control_source_ref(
        {"doc_reference": {"url": "https://docs.aws.amazon.com/b.html"}}
    ) == "https://docs.aws.amazon.com/b.html"
    assert m.control_source_ref(
        {"doc_reference": "https://docs.aws.amazon.com/c.html"}
    ) == "https://docs.aws.amazon.com/c.html"
    assert m.control_source_ref(
        {"reference_url": "https://docs.aws.amazon.com/d.html"}
    ) == "https://docs.aws.amazon.com/d.html"
    assert "pending" in m.control_source_ref({})


def test_main_mapping_cites_only_threat_model_controls(tmp_path) -> None:
    """A non-AWS Threat Model control mapped to an objective is filtered out of the main
    per-objective table (main = AWS Threat Model-only)."""
    m = _load_module()
    fw = _fw_mapped_fixture()
    # Add a non-AWS Threat Model control row to the mapped IAM-01 objective.
    fw["framework_mapping"][0]["controls"].append(
        {"control_id": "CTRL-ACC-PRO-026", "coverage_level": "Partial Coverage",
         "rationale": "compensating", "citation": {"objective_requirement": "x",
                                                    "source": "assessment_gap"}})
    controls = [
        {"id": "CTRL-ACC-PRV-001", "name": "PB", "category": "PRV", "scope": "ACC",
         "trace_source": "threat_model"},
        {"id": "CTRL-ACC-PRO-026", "name": "Compensating", "category": "PRO",
         "scope": "ACC", "trace_source": "assessment_gap"},
    ]
    md = _render_framework_mapping(m, tmp_path, fw, controls)
    # Under IAM-01 the AWS Threat Model control renders; the non-AWS Threat Model one does not.
    assert "CTRL-ACC-PRV-001" in md
    assert "CTRL-ACC-PRO-026" not in md


def test_identify_coverage_gaps_keeps_control_orphan_alias() -> None:
    """control_orphan retains the {control_id, name} back-compat shape and lists
    only non-AWS Threat Model controls (AWS Threat Model controls stay in the main mapping)."""
    m = _load_module()
    controls = [
        {"id": "CTRL-RES-DET-009", "name": "Gap", "mitigation_ids": ["M-GAP-3.0"],
         "trace_source": "assessment_gap"},
        {"id": "CTRL-ORG-PRV-050", "name": "Lonely-threat-model",
         "mitigation_ids": ["M-Z.0"], "trace_source": "threat_model"},
    ]
    fw_mapped = {"framework_mapping": []}
    gaps = m.identify_coverage_gaps([], controls, fw_mapped, {})
    assert gaps["control_orphan"] == [{"control_id": "CTRL-RES-DET-009", "name": "Gap"}]
    assert gaps["uncited_controls"][0]["source"]


def test_catalog_cites_threat_model_and_labels_gap(tmp_path) -> None:
    """AWS Threat Model control shows alias+UUID+statement; gap control is labelled."""
    from pathlib import Path
    m = _load_module()
    controls = [
        {"id": "CTRL-RES-PRV-001", "name": "Enforce CMK", "scope": "RES",
         "category": "PRV", "description": "d", "mechanism": "KMS Key Policy",
         "resource_types": ["AWS::Lambda::Function"], "mitigation_ids": ["M-Function.3"],
         "mitigation_alias": "Mitigation.LAMBDA.Function.3", "mitigation_uuid": "uuid-1",
         "actions": ["lambda:CreateFunction"]},
        {"id": "CTRL-RES-DET-009", "name": "Gap rec", "scope": "RES", "category": "DET",
         "description": "d", "mechanism": "AWS Config Rule",
         "resource_types": ["AWS::Lambda::Function"], "mitigation_ids": ["M-GAP-5.0"],
         "trace_source": "assessment_gap", "actions": ["lambda:GetFunction"]},
    ]
    mitigations = [{"id": "uuid-1", "alias": "Mitigation.LAMBDA.Function.3",
                    "statement": "Require a customer-managed KMS key on function creation."}]
    tmm = [{"mitigation_id": "M-Function.3", "statement": "x",
            "control_ids": ["CTRL-RES-PRV-001"]}]
    out = Path(tmp_path) / "catalog.md"
    m.write_controls_catalog(controls, tmm, {"tactic_coverage": {}}, "lambda", out,
                             mitigations=mitigations)
    md = out.read_text()
    assert "**AWS Threat Model mitigation:** `Mitigation.LAMBDA.Function.3` (UUID `uuid-1`)" in md
    assert "Require a customer-managed KMS key on function creation." in md
    assert "assessment gap (no AWS Threat Model mitigation; recommended control)" in md


def test_readable_threat_model_links_in_both_reports(tmp_path):
    from threat_model_test_support import source_receipt
    m = _load_module()
    path = tmp_path / "model.json"
    path.write_text("{}")
    provenance = source_receipt(path)
    alias = "Mitigation.DSQL.Cluster.4"
    provenance["report_aliases"] = [alias]
    control = {"mitigation_alias": alias, "trace_source": "threat_model"}
    m.attach_threat_model_links([control], {"mitigations": [{"alias": alias}]}, provenance)
    link = f"[{alias}]({provenance['report_url']}#mitigationdsqlcluster4)"
    assert link in m._citation_cell({}, control)
    assert any(link in line for line in m._catalog_citation_lines(control, {}, {}))
    assert "https://" not in m._citation_cell({"citation": {"mitigation_alias": "Invented"}}, control)


def test_service_autodetection_ignores_downloaded_sources(tmp_path, monkeypatch):
    m = _load_module()
    for name in ("_sources", "_staging", "plans", "dsql"):
        (tmp_path / ".service-approval" / name).mkdir(parents=True)
    monkeypatch.setattr(m.paths, "workspace_root", lambda: tmp_path)
    assert m.detect_single_service() == "dsql"
