from pathlib import Path
import json,copy,os
from jsonschema import Draft202012Validator,FormatChecker
from referencing import Registry,Resource
root=Path(os.environ['ASSERVAT_GATE_MIRROR']);base='https://asservat.io/spec/v1/'
schemas=[json.loads(p.read_text()) for p in (root/'specs/contracts').glob('*.schema.json')]
r=Registry().with_resources([(s['$id'],Resource.from_contents(s)) for s in schemas]);s=next(s for s in schemas if s['$id']==base+'owner-bootstrap-selection.schema.json')
def valid(ref,v):return Draft202012Validator({'$ref':s['$id']+ref},registry=r,format_checker=FormatChecker()).is_valid(v)
peer={'clusterID':'20000000-0000-4000-8000-000000000001','roots':['cHVibGlj']}
p={'format':'asservat-owner-bootstrap-plan/v1','pkiMount':'owner-pki','connections':4,'concurrency':2,'peers':[peer,copy.deepcopy(peer)]}
assert valid('#/$defs/plan',p),'same-cluster logical peers rejected'
for k in ['permissionRootID','token','processEpoch','privatePayloadDigest']:
 v=copy.deepcopy(p);v[k]='forbidden';assert not valid('#/$defs/plan',v),k
for count in [0,17]:
 v=copy.deepcopy(p);v['peers']=[peer]*count;assert not valid('#/$defs/plan',v),count
f=Draft202012Validator(s['properties']['initialFormat'])
for v in ['asservat-initial-installer/v1','asservat-initial-installer/v2']:assert f.is_valid(v)
for v in ['','asservat-initial-installer/v3','caller']:assert not f.is_valid(v)
assert FormatChecker().conforms('2026-10-13T00:00:00Z','date-time')
assert not FormatChecker().conforms('not-a-time','date-time')
print('owner bootstrap schema: 15 closed selection, initial batch and actual-format assertions passed')
