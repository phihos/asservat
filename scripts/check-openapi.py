import json,yaml
from pathlib import Path
from openapi_spec_validator import validate
root=Path(__file__).resolve().parents[1]
spec=yaml.safe_load((root/'docs/interfaces/browser-openapi.yaml').read_text())
# Bundle local canonical contracts solely for offline validation, preserving schema semantics.
ids={}
for p in (root/'specs/contracts').glob('*.schema.json'):
 value=json.loads(p.read_text());name='Contract_'+p.stem.replace('.','_').replace('-','_');ids[value['$id']]=name
 spec['components']['schemas'][name]=value

def bundle(v):
 if isinstance(v,dict):
  if '$ref' in v:
   doc,_,frag=v['$ref'].partition('#')
   if doc in ids:v['$ref']='#/components/schemas/'+ids[doc]+frag
  # Schema identifiers would change the base of rewritten fragment references.
  v.pop('$id',None)
  for x in v.values():bundle(x)
 elif isinstance(v,list):
  for x in v:bundle(x)
bundle(spec)
validate(spec)
auth=yaml.safe_load((root/'docs/interfaces/browser-auth-openapi.yaml').read_text())
# The auth protocol reuses the exact public Session wire shape. Resolve this
# local reference explicitly so validation never fetches a remote schema.
auth['paths']['/auth/refresh']['post']['responses']['200']['content']['application/json']['schema']=spec['components']['schemas']['Session']
validate(auth)
print('PASS: OpenAPI 3.1.1 specification validation with all canonical references bundled locally.')
