"""Regression reproductions for broken references, pairing, loss and disclosure."""
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from threat_model_integrity import (
    build_run_audit, check_reporting, disposition_errors, identity_errors,
    repair_citations, repair_control_identity, source_findings, write_audit,
)
from threat_model_source import SourceError, check_source, save_latest
from threat_model_test_support import source_receipt
from validate_threat_model_input import validate_export, check_run
from test_threat_model_source import release, COMMIT

REPO = Path(__file__).parents[2]


def script(name):
    spec = importlib.util.spec_from_file_location('integrity_' + name, REPO / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def model():
    data = json.loads((REPO / 'tools/validate/fixtures/threat_model_minimal.json').read_text())
    data['metadata']['name'] = 'lambda'
    # Opposite ordering: a lexical UUID sort must not select a primary.
    data['mitigations'][0]['id'] = '00000000-0000-0000-0000-000000000000'
    data['mitigations'][1]['id'] = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    return data


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def run(tmp_path, data=None):
    data = data or model()
    root = tmp_path / '.service-approval/lambda'
    snapshot = write(tmp_path / '.service-approval/_sources/model.json', data)
    source = source_receipt(snapshot, 'lambda', report_aliases=[
        r['alias'] for section in ('mitigations', 'threats', 'implementations')
        for r in data.get(section, [])])
    write(root / '00-intake/intake-manifest.json', {'service':{'name':'lambda'}, 'inputs':{'threat_model_file':str(snapshot),'threat_model_source':source}})
    return root, source


def controls(data):
    out = []
    for i, row in enumerate(data['mitigations']):
        c = {'id':f'CTRL-RES-PRV-{i+1:03}', 'mitigation_alias':row['alias'], 'mitigation_ids':[f'M-Resource.{i}']}
        repair_control_identity(c, data)
        out.append(c)
    return out


def test_broken_reference_is_advisory_and_control_is_identified(tmp_path):
    data = model()
    linked = data['mitigations'][1]
    for relation in linked['mappings']:
        if relation['type'] == 'THREAT': relation['id'] = 'missing-uuid'
    root, source = run(tmp_path, data)
    assert validate_export(data, 'lambda') == []
    assert check_run(root) == []
    write(root / '04-map/map-controls-generated.json', {'controls':controls(data)})
    audit = write_audit(root)
    broken = [f for f in audit['findings'] if f['check'] == 'broken_reference']
    assert len(broken) == 1
    assert broken[0]['target'] == 'missing-uuid'
    assert broken[0]['affected_controls'] == ['CTRL-RES-PRV-002']
    assert script('threat_model_trace').build_trace_index(data)[linked['id']]['mitre_techniques'] == []


def test_no_threat_or_mitre_mapping_is_not_itself_a_defect(tmp_path):
    root, source = run(tmp_path)
    assert source_findings(model(), source) == []


@pytest.mark.parametrize('problem', ['missing', 'unsafe', 'hash', 'offline', 'encoding'])
def test_unusable_readable_report_does_not_block_usable_model(monkeypatch, tmp_path, problem):
    import threat_model_source as src
    payloads, manifest, _ = release(monkeypatch)
    entry = manifest['services'][0]
    report_url = src.artifact_url(COMMIT, entry['report']['path'], raw=True)
    if problem == 'missing':
        del entry['report']
    elif problem == 'unsafe':
        entry['report']['path'] = '../outside.md'
    elif problem == 'hash':
        payloads[report_url] = b'wrong bytes'
    elif problem == 'encoding':
        import hashlib
        payloads[report_url] = b'\xff'
        entry['report']['sha256'] = hashlib.sha256(b'\xff').hexdigest()
    else:
        original = src.download
        def download(url):
            if url == report_url: raise SourceError('report unavailable')
            return original(url)
        monkeypatch.setattr(src, 'download', download)
    payloads[src.artifact_url(COMMIT, 'manifest.json', raw=True)] = json.dumps(manifest).encode()
    inputs = save_latest('future-service', tmp_path)
    source = inputs['threat_model_source']
    assert source['report_status'] == 'unavailable'
    assert source['report_aliases'] == []
    assert any(f['check'] == 'readable_report_unavailable' for f in source['findings'])
    assert check_source(source, Path(inputs['threat_model_file'])) == []
    assert src.citation_url(source, 'Mitigation.future-service.1') == source['data_url']


def test_missing_anchor_warns_and_links_to_readable_report(monkeypatch, tmp_path):
    import hashlib
    import threat_model_source as src
    payloads, manifest, _ = release(monkeypatch)
    ref = manifest['services'][0]['report']
    payloads[src.artifact_url(COMMIT, ref['path'], raw=True)] = b'# A report with no alias headings'
    ref['sha256'] = hashlib.sha256(b'# A report with no alias headings').hexdigest()
    payloads[src.artifact_url(COMMIT, 'manifest.json', raw=True)] = json.dumps(manifest).encode()
    source = save_latest('future-service', tmp_path)['threat_model_source']
    assert any(f['check'] == 'missing_report_anchor' for f in source['findings'])
    assert src.citation_url(source, 'Mitigation.future-service.1') == source['report_url']
    assert src.citation_url(source, 'made-up') == ''


def test_new_runs_do_not_overwrite_each_others_snapshots(monkeypatch, tmp_path):
    release(monkeypatch)
    first = save_latest('future-service', tmp_path)
    first_path = Path(first['threat_model_file'])
    first_path.write_text('tampered')
    second = save_latest('future-service', tmp_path)
    assert second['threat_model_file'] != first['threat_model_file']
    assert first_path.read_text() == 'tampered'
    assert check_source(first['threat_model_source'], first_path)


def test_primary_identity_pairs_and_factual_validation():
    from validate_threat_model_facts import check
    data = model()
    c = {'id':'CTRL-RES-PRV-001', 'mitigation_aliases':[m['alias'] for m in reversed(data['mitigations'])],
         'mitigation_alias':data['mitigations'][1]['alias'], 'mitigation_uuid':data['mitigations'][0]['id']}
    assert identity_errors({'controls':[c]}, data)
    assert check(data, None, {'controls':[c]})
    trace = script('threat_model_trace')
    trace.thread_controls([c], data)
    pairs = {m['alias']:m['id'] for m in data['mitigations']}
    assert c['mitigation_uuid'] == pairs[c['mitigation_alias']]
    assert c['mitigation_uuids'] == [pairs[a] for a in c['mitigation_aliases']]
    assert c['threat_model_repairs']
    assert check(data, None, {'controls':[c]}) == []
    first = copy.deepcopy(c)
    trace.thread_controls([c], data)
    assert first == c


def test_framework_citation_uuid_repair_is_recorded():
    data = model()
    doc = {'framework_mapping':[{'controls':[{'control_id':'CTRL-RES-PRV-001', 'citation':{
        'source':'threat_model','mitigation_alias':data['mitigations'][0]['alias'],'mitigation_uuid':'wrong'}}]}]}
    repairs = repair_citations(doc, data)
    assert len(repairs) == 1 and repairs[0]['auto_fixed']
    assert not identity_errors(doc, data)


def test_dedup_preserves_all_source_pairs():
    data = model()
    cs = controls(data)
    merged, remap = script('map-assemble').dedup_controls(cs)
    assert len(merged) == 1
    assert len(merged[0]['mitigation_references']) == 2
    assert set(merged[0]['mitigation_aliases']) == {m['alias'] for m in data['mitigations']}
    assert not identity_errors({'controls':merged}, data)


@pytest.mark.parametrize('field', ['alias', 'id'])
def test_ambiguous_source_identity_is_reported_not_guessed(tmp_path, field):
    data = model()
    data['mitigations'][1][field] = data['mitigations'][0][field]
    root, source = run(tmp_path, data)
    findings = source_findings(data, source)
    assert any(f['check'] == 'duplicate_identity' for f in findings)
    c = {'mitigation_alias':data['mitigations'][0]['alias'], 'mitigation_uuid':'arbitrary'}
    repair_control_identity(c, data)
    assert 'mitigation_uuid' not in c
    assert all(m['status'] == 'ambiguous_source' for m in build_run_audit(root)['mitigations'])


def test_source_mitigation_lost_before_map_is_reported(tmp_path):
    data = model()
    root, _ = run(tmp_path, data)
    normalized = [{'id':f'M-Resource.{i}', 'alias':m['alias'], 'source_uuid':m['id']} for i,m in enumerate(data['mitigations'])]
    write(root / '02-research/research.json', {'existing_mitigations': normalized[:1]})
    write(root / '03-validate/validated.json', {'existing_mitigations': normalized[:1]})
    write(root / '04-map/map-controls-generated.json', {'controls':controls(data)[:1]})
    audit = build_run_audit(root)
    missing = [f for f in audit['findings'] if f['check'] == 'mitigation_missing']
    assert len(missing) == 2
    assert audit['mitigations'][1]['status'] == 'unresolved'
    assert any(f['check'] == 'mitigation_unresolved' for f in audit['findings'])


@pytest.mark.parametrize('status', ['manual_guidance', 'not_applicable', 'unresolved'])
def test_explicit_dispositions_are_accounted_and_visible(tmp_path, status):
    data = model()
    root, _ = run(tmp_path, data)
    mit = data['mitigations'][1]
    d = {'mitigation_alias':mit['alias'], 'mitigation_uuid':mit['id'], 'mitigation_id':'M-Resource.1',
         'status':status, 'rationale':'A documented service-specific decision.', 'guidance':'Review account access manually.'}
    write(root / '04-map/map-controls-generated.json', {'controls':controls(data)[:1], 'mitigation_dispositions':[d]})
    assert disposition_errors([d], data) == []
    audit = write_audit(root)
    assert audit['mitigations'][1]['status'] == status
    assert d['rationale'] in (root / 'threat-model-integrity.md').read_text()
    assert bool([f for f in audit['findings'] if f['check'] == 'mitigation_unresolved']) == (status == 'unresolved')
    d['mitigation_uuid'] = 'wrong'
    assert disposition_errors([d], data)


def test_findings_and_repairs_cannot_be_hidden_or_stale(tmp_path):
    root, _ = run(tmp_path)
    cs = controls(model())
    cs[0]['mitigation_uuid'] = 'wrong'
    repairs = repair_control_identity(cs[0], model())
    state = write(root / '04-map/map-controls-generated.json', {'controls':cs[:1], '_metadata':{'threat_model_repairs':repairs}})
    for name in ('04-map/controls-catalog.md','04-map/framework-mapping.md','06-summarize/SUMMARY-REPORT.md'):
        p = root / name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('# Report\n\nOriginal body.\n')
    audit = write_audit(root)
    assert audit['findings'] and audit['repairs']
    assert not check_reporting(root)
    original = (root / '04-map/framework-mapping.md').read_text()
    write_audit(root)
    assert original == (root / '04-map/framework-mapping.md').read_text()
    (root / '04-map/framework-mapping.md').write_text('# Report\nNo issues.')
    assert check_reporting(root)
    write_audit(root)
    write(state, {'controls':controls(model())})
    assert any('stale' in error for error in check_reporting(root))


def test_audit_migrates_banners_to_one_framework_appendix(tmp_path):
    from threat_model_integrity import BEGIN, END, report_block
    root, _ = run(tmp_path)
    write(root / '04-map/map-controls-generated.json', {'controls': controls(model())})
    for name in ('04-map/controls-catalog.md', '04-map/framework-mapping.md', '06-summarize/SUMMARY-REPORT.md'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'# Report\n\n{BEGIN}\nOld banner\n{END}\n\nBody\n\n## Citations not found in AWS Threat Models\n\nCitation review.\n')
    audit = write_audit(root)
    framework = (root / '04-map/framework-mapping.md').read_text()
    assert framework.rstrip().endswith(report_block(audit))
    assert framework.index('Citation review.') < framework.index(BEGIN)
    for name in ('04-map/controls-catalog.md', '06-summarize/SUMMARY-REPORT.md'):
        assert BEGIN not in (root / name).read_text()
    assert not check_reporting(root)


def test_ordering_correct_pairs_is_not_an_identity_repair():
    data = model()
    c = controls(data)[0]
    pairs = [{'alias': m['alias'], 'uuid': m['id']} for m in reversed(data['mitigations'])]
    c['mitigation_aliases'] = [p['alias'] for p in pairs]
    c['mitigation_uuids'] = [p['uuid'] for p in pairs]
    c['mitigation_references'] = pairs
    assert not identity_errors(c, data)
    assert repair_control_identity(c, data) == []
    assert not identity_errors(c, data)


def test_input_ignore_rules_keep_only_shipped_defaults(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)], check=True)
    (tmp_path / '.gitignore').write_text((REPO / '.gitignore').read_text())
    for path in ('input/customer.xlsx','input/customer.md','input/customer.docx','input/nested/model.json',
                 'input-dsql/data.json','input_lambda/file.pdf','inputs/customer.csv','runs/dsql/input.json'):
        assert subprocess.run(['git','-c','core.excludesFile=/dev/null','check-ignore','-q',path],cwd=tmp_path).returncode == 0, path
    for path in ('input/CCMv4-sample.xlsx','input/sar-slugs.json'):
        assert subprocess.run(['git','-c','core.excludesFile=/dev/null','check-ignore','-q',path],cwd=tmp_path).returncode == 1, path


def test_known_wrong_pair_is_an_authoring_error_even_if_disclosed(tmp_path):
    root, _ = run(tmp_path)
    cs = controls(model())
    cs[0]['mitigation_uuid'] = 'wrong'
    write(root / '04-map/map-controls-generated.json', {'controls':cs})
    report = root / '06-summarize/SUMMARY-REPORT.md'
    report.parent.mkdir(); report.write_text('# Summary\n')
    write_audit(root)
    assert any('THREAT_MODEL-IDENTITY' in e for e in check_reporting(root))


def test_typed_citation_uuid_is_also_validated():
    data = model()
    doc = {'citation':{'type':'threat_model','id':data['mitigations'][0]['alias'],'mitigation_uuid':'wrong'}}
    assert identity_errors(doc, data)
    repair_citations(doc, data)
    assert not identity_errors(doc, data)


def test_complete_map_assembly_repairs_and_discloses(tmp_path, monkeypatch):
    data = model()
    root, source = run(tmp_path, data)
    # Force a source advisory while keeping the source hash valid.
    manifest_path = root / '00-intake/intake-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['inputs']['threat_model_source'] = source_receipt(
        Path(manifest['inputs']['threat_model_file']), 'lambda', report_aliases=[])
    write(manifest_path, manifest)
    cs = controls(data)
    for i, c in enumerate(cs):
        c.update(name='Same synthetic control',scope='RES',category='PRV',mechanism='SCP',
                 description='Synthetic control.',security_rationale='Synthetic rationale.',
                 actions=[],parameters_controlled=[],resource_types=['AWS::Lambda::Function'])
    cs[0]['mitigation_uuid'] = 'wrong'
    mits = [{'id':f'M-Resource.{i}', 'alias':m['alias'], 'source_uuid':m['id'], 'statement':m['statement']}
            for i,m in enumerate(data['mitigations'])]
    write(root / '03-validate/validated.json', {'service':'lambda','existing_mitigations':mits,'attack_surface':{'applicable_techniques':[]}})
    write(root / '04-map/map-controls-generated.json', {'service':'lambda','controls':cs})
    write(root / '04-map/map-framework-parsed.json', {'framework':{'name':'Synthetic'},'framework_objectives':[{'objective_id':'IAM-01'}]})
    fw = {'framework_mapping':[{'objective_id':'IAM-01','title':'Test objective','domain':'Identity','status':'MAPPED',
                               'coverage':'Partially Covered','controls':[{'control_id':c['id'],'coverage_level':'Partial Coverage',
                               'rationale':'Synthetic rationale','citation':{'source':'threat_model','mitigation_alias':c['mitigation_alias'],
                               'mitigation_uuid':'wrong'}} for c in cs]}]}
    write(root / '04-map/map-framework-mapped.json', fw)
    monkeypatch.chdir(tmp_path)
    module = script('map-assemble')
    monkeypatch.setattr(module.paths, 'service_root', lambda slug: root)
    monkeypatch.setattr(module.paths, 'phase_dir', lambda slug, phase: root / {'map':'04-map','validate':'03-validate'}[phase])
    monkeypatch.setattr(sys, 'argv', ['map-assemble', '--slug', 'lambda'])
    assert module.main() == 0
    out = json.loads((root / '04-map/mapping-results.json').read_text())
    assert len(out['controls']) == 1
    intermediate = json.loads((root / '04-map/map-framework-mapped.json').read_text())
    assert {c['control_id'] for row in intermediate['framework_mapping'] for c in row['controls']} == {c['id'] for c in cs}
    assert not identity_errors(out, data)
    assert not identity_errors(json.loads((root / '04-map/map-framework-mapped.json').read_text()), data)
    assert not check_reporting(root)
    audit = json.loads((root / 'threat-model-integrity.json').read_text())
    assert audit['repairs'] and audit['findings']
    assert 'Source advisory' in (root / '04-map/controls-catalog.md').read_text()


def test_entity_alias_without_report_heading_does_not_create_spurious_warning(tmp_path):
    data = model()
    data['entities'][0]['alias'] = 'Entity.LAMBDA.Function'
    root, source = run(tmp_path, data)
    assert source_findings(data, source) == []


def test_resume_never_attempts_any_download(monkeypatch, tmp_path):
    import threat_model_source as source
    root, _ = run(tmp_path)
    manifest_path = root / '00-intake/intake-manifest.json'
    def unexpected_download(url):
        raise AssertionError('Resume attempted network access')
    monkeypatch.setattr(source, 'download', unexpected_download)
    saved = json.loads(manifest_path.read_text())
    assert source.refresh_manifest(saved, manifest_path) == saved['inputs']['threat_model_source']


def test_mitigation_internal_id_is_not_interchangeable_with_source_uuid():
    data = model()
    row = data['mitigations'][0]
    disposition = {'mitigation_alias':row['alias'], 'mitigation_uuid':row['id'],
                   'mitigation_id':'M-Wrong.0', 'status':'not_applicable', 'rationale':'Documented reason.'}
    normalized = [{'id':'M-Resource.0', 'alias':row['alias'], 'source_uuid':row['id']}]
    assert disposition_errors([disposition], data, normalized)
    disposition['mitigation_id'] = 'M-Resource.0'
    assert not disposition_errors([disposition], data, normalized)
