"""Check generated routes/anchors and that displayed evidence equals the saved JSON.
Run after npm run build. No browser or running deployment required.
"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit, unquote
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.links=[]; self.ids=set(); self.h1=0; self.titles=0; self.blocks=[]; self.pre=None
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if 'id' in attrs:
            assert attrs['id'] not in self.ids, f'duplicate id {attrs["id"]}'
            self.ids.add(attrs['id'])
        self.h1 += tag=='h1'; self.titles += tag=='title'
        for attr in ['href','src']:
            if attr in attrs:self.links.append(attrs[attr])
        if tag=='pre':self.pre=[]
    def handle_data(self, value):
        if self.pre is not None:self.pre.append(value)
    def handle_endtag(self, tag):
        if tag=='pre' and self.pre is not None:
            self.blocks.append(''.join(self.pre));self.pre=None

pages={}
for file in DIST.rglob('*.html'):
    page=Page();page.feed(file.read_text());pages[file]=page
    assert page.h1==1 and page.titles==1, f'{file}: heading/title count'
for file,page in pages.items():
    for link in page.links:
        u=urlsplit(link)
        if u.scheme or u.netloc:continue
        target=(DIST/unquote(u.path).lstrip('/') if u.path.startswith('/') else file.parent/unquote(u.path)) if u.path else file
        if target.is_dir() or not target.suffix:target=target/'index.html'
        assert target.exists(),f'{file}: broken link {link}'
        if u.fragment and target in pages:
            assert unquote(u.fragment) in pages[target].ids,f'{file}: missing anchor {link}'

# Parse syntax-highlighted code back into JSON. Exact record equality detects
# accidental reconstruction, decoded string fields, truncation, and number changes.
proof=pages[DIST/'proof/index.html']
shown=[]
for block in proof.blocks:
    try:shown.append(json.loads(block))
    except json.JSONDecodeError:pass
for name in ['beacon','signature','scan','transfer','benign-transfer','dns','fqdn']:
    path=ROOT/'public/evidence'/f'{name}.json'
    saved=json.loads(path.read_text())
    for side in ['suricata','cernity']:
        assert saved[side] in shown,f'{name}: original {side} body missing or altered'
    assert isinstance(saved['cernity']['entities'],str),f'{name}: original entities type changed'
    assert saved['cernity'] in saved['cernity_matching_records']
    assert (DIST/'evidence'/f'{name}.json').read_bytes()==path.read_bytes()

# Detector-stage coverage page: every displayed source record and finding must be an unmodified
# element of its capture, and every capture download byte-identical. Same anti-fabrication guard.
det_page=DIST/'proof/detection/index.html'
det_detectors=0
if det_page in pages:
    det_shown=[]
    for block in pages[det_page].blocks:
        try:det_shown.append(json.loads(block))
        except json.JSONDecodeError:pass
    model=json.loads((ROOT/'src/content/proof/captures.json').read_text())
    for svc in model['services']:
        cap=json.loads((ROOT/'public/evidence/detector-stage'/f"{svc['service']}.json").read_text())
        recs,finds=cap['suricata_baseline']['records'],cap['cernity']['findings']
        deliv_by_id={r['finding_id']:r for r in cap['cernity'].get('delivered',[])}
        for d in svc['detectors']:
            assert d['finding'] in finds,f"{svc['service']}/{d['detector_id']}: finding not in capture"
            assert d['finding'] in det_shown,f"{svc['service']}/{d['detector_id']}: displayed candidate altered/missing"
            if d['source_record'] is not None:
                assert d['source_record'] in recs,f"{svc['service']}/{d['detector_id']}: source record not in capture"
                assert d['source_record'] in det_shown,f"{svc['service']}/{d['detector_id']}: displayed source altered/missing"
            # delivered SIEM document (ES _index/_id/_source) must equal what the real forwarder produced
            if d.get('delivered') and d.get('siem'):
                cap_es=deliv_by_id[d['finding']['finding_id']]['siem']['elasticsearch']
                assert d['siem']['elasticsearch']==cap_es,f"{svc['service']}/{d['detector_id']}: siem doc drift vs capture"
                assert d['siem']['elasticsearch'] in det_shown,f"{svc['service']}/{d['detector_id']}: displayed SIEM doc altered/missing"
            det_detectors+=1
        assert (DIST/'evidence/detector-stage'/f"{svc['service']}.json").read_bytes()== \
            (ROOT/'public/evidence/detector-stage'/f"{svc['service']}.json").read_bytes()

# Documentation shell blocks are parsed, not executed; they contain deployment
# instructions that must never be run just to test a marketing site.
blocks=0
for file in (ROOT/'src/content/docs').glob('*.md'):
    for shell in re.findall(r'```bash\n(.*?)\n```',file.read_text(),re.S):
        result=subprocess.run(['bash','-n'],input=shell,text=True,capture_output=True)
        assert result.returncode==0,f'{file}: {result.stderr}'
        blocks+=1

inventory=json.loads((ROOT/'public/evidence/inventory.json').read_text())
assert len(inventory['bundles'])==15
assert not inventory['nonempty_context_fields'], 'Update the integration evidence claims: context is now present'
assert not {'ndpi_risk','ja4_rarity','server_fp_rarity','slips_ml','slips_intel'} & set(inventory['detector_counts']), 'Update the missing-integration claims'
print(f'PASS: {len(pages)} pages, local assets/links/anchors, 14 original displayed records, '
      f'{det_detectors} detector-stage captures (displayed == unmodified capture), evidence downloads, '
      f'inventory claims, and {blocks} shell blocks.')
