"""Import only selected synthetic records, never the private evidence bundle.
Usage: python3 scripts/import-evidence.py /path/to/siem-comparison-results
Verifies original export hashes, event multisets, record selection, and totals.
"""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('source', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':'))
def ents(row):
    e = row.get('entities', [])
    return json.loads(e) if isinstance(e, str) else e
def endpoint(row, role):
    return next((e.get('value') for e in ents(row) if e.get('role') == role), None)
for name in ['beacon', 'signature', 'scan', 'transfer', 'benign-transfer']:
    comparison = json.loads((args.source / 'comparisons' / f'{name}.json').read_text())
    bundle = args.source / 'pipeline-evidence' / comparison['bundle']
    output = bundle / 'output'
    manifest = json.loads((output / 'export-manifest.json').read_text())
    for filename, meta in manifest['files'].items():
        assert hashlib.sha256((output / filename).read_bytes()).hexdigest() == meta['sha256'], filename
    def rows(filename):
        return [json.loads(line) for line in (output / filename).read_text().splitlines() if line.strip()]
    baseline, source, findings = rows('suricata-alerts.jsonl'), rows('source-eve.jsonl'), rows('cernity-findings.jsonl')
    def events(records):
        return Counter(canonical({k:v for k,v in r.items() if k != '@timestamp'}) for r in records)
    assert events(baseline) == events(source)
    f = comparison['filter']
    a = [r for r in baseline if r.get('src_ip') == f['src_ip'] and (not f['dest_ip'] or r.get('dest_ip') == f['dest_ip'])]
    b = [r for r in findings if endpoint(r, 'src') == f['src_ip'] and (not f['dest_ip'] or endpoint(r, 'dst') == f['dest_ip']) and (not f['detector_id'] or r.get('detector_id') == f['detector_id'])]
    assert a == comparison['suricata_matching_records'] and b == comparison['cernity_matching_records']
    for key, value in {
        'matching_flows':sum(r.get('event_type') == 'flow' for r in a),
        'matching_alerts':sum(r.get('event_type') == 'alert' for r in a),
        'matching_b_documents':len(b),
        'matching_b_unique_ids':len({r['finding_id'] for r in b}),
        'matching_toserver_bytes':sum(r.get('flow', {}).get('bytes_toserver', 0) for r in a if r.get('event_type') == 'flow')
    }.items():
        assert comparison['summary'][key] == value, (name, key)
    selected_b = json.loads((args.source / 'comparisons' / f'{name}-cernity.json').read_text())
    finding = next(r for r in b if r['finding_id'] == selected_b['finding_id'] and r['revision'] == selected_b['revision'])
    selected_a = json.loads((args.source / 'comparisons' / f'{name}-suricata.json').read_text())
    record = next(r for r in a if all(r.get(k) == v for k,v in selected_a.items()))
    alert = next((r for r in a if r.get('event_type') == 'alert'), None)
    excerpts = []
    for r in b:
        excerpts.append({k:(ents(r) if k == 'entities' else v) for k,v in r.items() if k in ['finding_id','revision','detector_id','category','severity','confidence','state','enrichment_state','entities','mitre','evidence_refs','community_id','first_seen','last_seen']})
    report = json.loads((bundle / 'report.json').read_text())
    completion = report.get('completion', {}).get('state')
    assert completion == comparison['verification']['saved_completion']
    data = {
        'bundle':comparison['bundle'], 'filter':f, 'summary':comparison['summary'],
        'completion':completion, 'replay':comparison['verification']['replay'],
        'provenance':{'export_hashes_verified':True, 'baseline_matches_source_except_ingestion_timestamp':True,
                      'source_export_sha256':manifest['files']['source-eve.jsonl']['sha256'],
                      'baseline_export_sha256':manifest['files']['suricata-alerts.jsonl']['sha256'],
                      'finding_export_sha256':manifest['files']['cernity-findings.jsonl']['sha256'],
                      'selection':'Original exported document bodies; not SIEM UI screenshots or search-result wrappers. Only selected synthetic records are included.'},
        'suricata':record, 'cernity':finding, 'additional_alert':alert,
        'cernity_matching_records':b, 'suricata_excerpt':selected_a,
        'cernity_excerpt':next(r for r in excerpts if r['finding_id'] == finding['finding_id'] and r['revision'] == finding['revision'])
    }
    (root / 'public/evidence' / f'{name}.json').write_text(json.dumps(data, indent=2) + '\n')
    print(f'{name}: export hashes, source equivalence, selections and counts verified')
# Older DNS captures have no export manifest or qualified completion metadata.
# Preserve their lower assurance instead of inventing verification/completion states.
for name, bundle_name, src in [('dns', 'synthetic-dns-tunnel', '10.0.0.9'), ('fqdn', 'synthetic-fqdn-beacon', '10.0.0.5')]:
    output = args.source / 'pipeline-evidence' / bundle_name / 'output'
    read = lambda filename: [json.loads(l) for l in (output / filename).read_text().splitlines() if l.strip()]
    a, s, b = read('suricata-alerts.jsonl'), read('source-eve.jsonl'), read('cernity-findings.jsonl')
    assert events(a) == events(s)
    record = next(r for r in a if r.get('event_type') == 'dns' and r.get('src_ip') == src)
    finding = b[0]
    assert any(e.get('value') == src for e in ents(finding))
    data = {
        'bundle':bundle_name, 'completion':'not established in legacy bundle',
        'filter':{'src_ip':src}, 'summary':{'baseline_records':len(a), 'baseline_alerts':sum(r.get('event_type') == 'alert' for r in a), 'finding_documents':len(b)},
        'provenance':{'export_hashes_verified':False, 'baseline_matches_source_except_ingestion_timestamp':True,
            'limitation':'No contemporaneous export manifest or qualified completion/replay metadata. Current local file hashes establish file identity only.',
            'baseline_export_sha256':hashlib.sha256((output/'suricata-alerts.jsonl').read_bytes()).hexdigest(),
            'finding_export_sha256':hashlib.sha256((output/'cernity-findings.jsonl').read_bytes()).hexdigest()},
        'suricata':record, 'cernity':finding, 'additional_alert':None, 'cernity_matching_records':b,
        'suricata_excerpt':record,
        'cernity_excerpt':{k:(ents(finding) if k=='entities' else v) for k,v in finding.items()}
    }
    (root/'public/evidence'/f'{name}.json').write_text(json.dumps(data,indent=2)+'\n')
    print(f'{name}: original records selected; baseline/source match; legacy assurance retained')

# A reproducible inventory of optional fields actually present in the saved findings.
from collections import defaultdict
inventory = []; detector_counts = Counter(); field_counts = Counter()
for output in sorted((args.source/'pipeline-evidence').glob('*/output')):
    path = output/'cernity-findings.jsonl'
    if not path.exists():
        continue
    records = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    detectors = Counter(r.get('detector_id','unknown') for r in records)
    detector_counts.update(detectors)
    for record in records:
        for field in ['geo','intel','iocs','summary']:
            if record.get(field):field_counts[field] += 1
    inventory.append({'bundle':output.parent.name,'documents':len(records),'detectors':dict(detectors)})
(root/'public/evidence/inventory.json').write_text(json.dumps({'scope':'All cernity-findings.jsonl exports in the 15 available historical bundles; overlapping runs are not independent trials.', 'bundles':inventory,'detector_counts':dict(detector_counts),'nonempty_context_fields':dict(field_counts)},indent=2)+'\n')
