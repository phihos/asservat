#!/usr/bin/env python3
"""Offline consistency gate for UX/domain/interface design; no runtime claims."""
import json,re
from pathlib import Path
from urllib.parse import urldefrag
import yaml
from jsonschema import Draft202012Validator
ROOT=Path(__file__).resolve().parents[1]
def read(path):return yaml.safe_load((ROOT/path).read_text())
ux=read('docs/ux/surfaces.yaml');domain=read('docs/domain/model.yaml');api=read('docs/interfaces/browser-openapi.yaml');operations=read('docs/interfaces/operations.yaml')['operations'];tools=read('specs/contracts/mcp-tools.json')['tools']
screens=ux['screens'];ids={s['id'] for s in screens};entities={e['name'] for e in domain['entities']}
assert len(ids)==len(screens)==len({s['surface_id'] for s in screens})
assert len(entities)==len(domain['entities'])
assert all(s['entity'] in entities for s in screens)
assert all(s['route']=='#/'+s['id'] for s in screens)
assert all(set(s['personas'])<= {'maintainer','recipient','approver','admin'} and s['personas'] for s in screens)
assert all(s['states']==['normal','loading','empty','denied','expired','offline','quota'] for s in screens)
assert all(set(steps)<=ids for steps in ux['journeys'].values())
js=(ROOT/'design/ui/screens.js').read_text();js_data=json.loads(js.split('=',1)[1].strip().rstrip(';'));assert js_data==screens
app=(ROOT/'design/ui/app.js').read_text();assert set(re.findall(r"case '([^']+)':",app))==ids
for target in re.findall(r"link\('([^']+)'",app):assert target in ids,target
for script in (ROOT/'design/ui').glob('*.js'):
 assert not re.search(r'\b(fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage)\s*[.(]',script.read_text())
for rel in domain['relations']:assert rel['source'] in entities and rel['target'] in entities
for ent in domain['entities']:
 assert ent['authority'] and ent['storage'] and ent['boundary']
 assert len({f['name'] for f in ent['fields']})==len(ent['fields'])
 assert all(f['type'] for f in ent['fields'])
methods={'get','post','put','patch','delete'}
apiops={op['operationId']:(p,m,op) for p,item in api['paths'].items() for m,op in item.items() if m in methods}
assert len(apiops)==len(operations)==len({o['operation'] for o in operations})
for op in operations:assert apiops[op['operation']][0]==op['path']
for t in tools:
 n=t['name'];assert api['components']['schemas']['McpInput_'+n]==t['inputSchema'];assert api['components']['schemas']['McpOutput_'+n]==t['outputSchema']
 assert next(o for o in operations if o['operation']==n)['transport']==['browser','mcp']
 assert apiops[n][2]['x-effect']==('read' if t['annotations'].get('readOnlyHint',False) else 'command')
assert set(api['components']['schemas']['ConfigSubmitInput']['properties']['kind']['enum'])=={'DebugPolicy','EvidenceRecipe','CaptureProfile'}
for name,(_,method,op) in apiops.items():
 if op['x-effect']=='command':assert method=='post' and any(p['name']=='Idempotency-Key' and p['required'] for p in op['parameters'])
 if method=='post':assert any(p['name']=='X-CSRF-Token' and p['required'] for p in op['parameters'])
registry={json.loads(p.read_text())['$id']:json.loads(p.read_text()) for p in (ROOT/'specs/contracts').glob('*.schema.json')}
refs=0
def walk(value):
 global refs
 if isinstance(value,dict):
  if '$ref' in value:
   doc,fragment=urldefrag(value['$ref']);target=registry[doc] if doc else api
   if fragment:
    assert fragment.startswith('/')
    for bit in fragment[1:].split('/'):target=target[bit.replace('~1','/').replace('~0','~')]
   refs+=1
  for v in value.values():walk(v)
 elif isinstance(value,list):
  for v in value:walk(v)
walk(api)
for schema in api['components']['schemas'].values():Draft202012Validator.check_schema(schema)
assert api['openapi']=='3.1.1'
print(f"PASS: {len(screens)} screens, {len(ux['journeys'])} journeys, {len(entities)} domain entities, {len(operations)} browser operations, {len(tools)} MCP schema pairs, {refs} resolved references.")
