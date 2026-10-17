from pathlib import Path
import json,copy
from jsonschema import Draft202012Validator,FormatChecker,ValidationError
from referencing import Registry,Resource
root=Path('/home/phil/Projekte/asservat'); stage=Path(__file__).parent
schemas={}
for p in (root/'specs/contracts').glob('*.json'):
 q=stage/'changes/specs/contracts'/p.name
 d=json.loads((q if q.exists() else p).read_text())
 if '$id' in d: schemas[d['$id']]=d
for p in (stage/'changes/specs/contracts').glob('*.json'):
 d=json.loads(p.read_text());Draft202012Validator.check_schema(d);schemas[d['$id']]=d
registry=Registry().with_resources((k,Resource.from_contents(v)) for k,v in schemas.items())
def valid(v): Draft202012Validator(schemas['https://asservat.io/spec/v1/initial-preparation-private.schema.json'],registry=registry,format_checker=FormatChecker()).validate(v)
u='12345678-1234-4234-8234-123456789abc'
empty=dict(format='asservat-initial-preparation-private/v1',installationID=u,requestID=u)
full=dict(empty,rootUID=u,planDigest='ab'*32,probe=dict(anchorOperationID=u,anchor=dict(uid=u,resourceVersion='1'),issue=dict(id=u,audience='https://api.example.test',startedAt='2026-10-12T10:00:00Z',until='2026-10-12T10:00:05Z',expiresBefore='2026-10-12T10:10:05Z',response=dict(token='x'*32,expiresAt='2026-10-12T10:10:00Z'))))
valid(empty);valid(full)
changes=[lambda x:x.update(unknown='secret'),lambda x:x.pop('rootUID'),lambda x:x['probe'].pop('anchor'),lambda x:x['probe']['issue'].update(startedAt='not-a-date'),lambda x:x['probe']['issue'].update(audience='bad audience'),lambda x:x['probe']['issue']['response'].update(token='too-short'),lambda x:x['probe']['issue']['response'].update(expiresAt='2026-10-12T10:10:00+01:00'),lambda x:x['probe']['issue']['response'].update(token='a'*8193)]
for change in changes:
 x=copy.deepcopy(full);change(x)
 try:valid(x)
 except ValidationError:pass
 else:raise AssertionError('invalid private state accepted')

sql=copy.deepcopy(full);sql['sql']={'operationID':u,'secret':{'name':'credentials-sql','uid':u}};valid(sql)
claim=copy.deepcopy(sql);claim['sql'].pop('secret');valid(claim)
changes=[lambda x:x.pop('probe'),lambda x:x['probe'].pop('issue'),lambda x:x['probe']['issue'].pop('response'),lambda x:x['sql'].update(password='forbidden'),lambda x:x['sql']['secret'].update(uid='wrong'),lambda x:x['sql'].update(operationID='wrong')]
for change in changes:
 x=copy.deepcopy(sql);change(x)
 try:valid(x)
 except ValidationError:pass
 else:raise AssertionError('invalid SQL private state accepted')
print('PASS: four bounded private state shapes and fourteen invalid schema cases; original timing/order/current authority remains runtime checked.')

# Exercise the newly added installer reference and its conditional prerequisites
# separately from unchanged required public fields in the full installer schema.
preparer=schemas['https://asservat.io/spec/v1/initial-preparer.schema.json']
part={'type':'object','properties':{'sqlMaterial':preparer['properties']['sqlMaterial']},'allOf':preparer['allOf']}
refvalidator=Draft202012Validator(part,registry=registry,format_checker=FormatChecker())
ref={'sqlMaterial':{'name':'sql-material','uid':u},'services':{},'plan':{'privateState':{}}}
refvalidator.validate(ref)
for change in [lambda x:x.pop('services'),lambda x:x['plan'].pop('privateState'),lambda x:x['sqlMaterial'].update(uid='invalid'),lambda x:x['sqlMaterial'].update(password='forbidden')]:
 x=copy.deepcopy(ref);change(x)
 try:refvalidator.validate(x)
 except ValidationError:pass
 else:raise AssertionError('invalid SQL material reference accepted')
print('PASS: explicit SQL material reference clause and four rejected prerequisite/reference shapes.')

provider=dict(profileDigest='ab'*32,parent=dict(accessor='original-parent',issuedAt='2026-10-12T10:00:00Z',expiresAt='2026-10-12T10:10:00Z'))
state=copy.deepcopy(sql);state['providers']=provider;valid(state)
issue=dict(id=u,startedAt='2026-10-12T10:00:05Z',until='2026-10-12T10:00:10Z',expiresBefore='2026-10-12T10:10:00Z',response=dict(token='original-token',accessor='original-accessor',issuedAt='2026-10-12T10:00:06Z',expiresAt='2026-10-12T10:09:00Z'))
provider['wrap']=copy.deepcopy(issue);valid(state)
provider['unwrap']=copy.deepcopy(issue);valid(state)
provider['projection']=dict(operationID=u,secret=dict(name='credentials',uid=u));valid(state)
for change in [lambda x:x.pop('sql'),lambda x:x['sql'].pop('secret'),lambda x:x['providers'].pop('wrap'),lambda x:x['providers']['wrap'].pop('response'),lambda x:x['providers']['unwrap'].pop('response'),lambda x:x['providers']['parent'].update(expiresAt='invalid'),lambda x:x['providers']['wrap']['response'].update(token='x'*1025),lambda x:x['providers'].update(issuerToken='forbidden')]:
 x=copy.deepcopy(state);change(x)
 try:valid(x)
 except ValidationError:pass
 else:raise AssertionError('invalid provider progress accepted')
print('PASS: four finite provider progress shapes and eight rejected provider progress shapes.')
material=dict(format='asservat-initial-provider-material/v1',installationID=u,requestID=u,issuerToken='original',storage=dict(accessKeyID='original',secretAccessKey='original',sessionToken=''),storageUseUntil='2026-10-12T10:10:00Z')
mv=Draft202012Validator(schemas['https://asservat.io/spec/v1/initial-provider-material.schema.json'],registry=registry,format_checker=FormatChecker());mv.validate(material)
for change in [lambda x:x.update(issuerToken='x'*1025),lambda x:x.update(storageUseUntil='not-a-date'),lambda x:x.update(storageUseUntil='2026-10-12T10:00:00+01:00'),lambda x:x.update(password='forbidden'),lambda x:x['storage'].update(secretAccessKey='')]:
 x=copy.deepcopy(material);change(x)
 try:mv.validate(x)
 except ValidationError:pass
 else:raise AssertionError('invalid provider material accepted')
print('PASS: finite provider material and five rejected secret/date shapes, with FormatChecker.')
profile=dict(format='asservat-initial-provider-profile/v1',material=dict(name='provider-material',uid=u),issuerPolicy='issuer',wrapRole='wrap-role',wrapPolicy='encrypt',unwrapRole='unwrap-role',unwrapPolicy='decrypt')
pv=Draft202012Validator(schemas['https://asservat.io/spec/v1/initial-provider-profile.schema.json'],registry=registry,format_checker=FormatChecker());pv.validate(profile)
for change in [lambda x:x.update(issuerPolicy='*'),lambda x:x['material'].update(uid='invalid'),lambda x:x.update(issuerToken='forbidden')]:
 x=copy.deepcopy(profile);change(x)
 try:pv.validate(x)
 except ValidationError:pass
 else:raise AssertionError('invalid public provider profile accepted')
print('PASS: explicit bounded provider profile and three rejected profile shapes; distinct role/policy names additionally checked at runtime.')
part={'type':'object','properties':{'providers':preparer['properties']['providers']},'allOf':preparer['allOf'],'dependentRequired':preparer['dependentRequired']}
prereq=Draft202012Validator(part,registry=registry,format_checker=FormatChecker())
selected=dict(providers=profile,sqlMaterial=dict(name='sql-material',uid=u),services={},plan=dict(privateState={}))
prereq.validate(selected)
for change in [lambda x:x.pop('services'),lambda x:x.pop('sqlMaterial'),lambda x:x['plan'].pop('privateState')]:
 x=copy.deepcopy(selected);change(x)
 try:prereq.validate(x)
 except ValidationError:pass
 else:raise AssertionError('provider prerequisites missing')
print('PASS: provider selection requires services, original SQL material and private state.')
