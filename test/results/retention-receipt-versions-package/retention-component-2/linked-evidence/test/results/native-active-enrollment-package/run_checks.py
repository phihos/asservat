from pathlib import Path
import hashlib,json,os,subprocess,sys,time
r=Path('/home/phil/Projekte/asservat');s=Path('/home/phil/.cache/asservat-build/planning/native-active-enrollment-20261012')
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
bases=json.loads((s/'base.json').read_text());deps=json.loads((s/'dependencies.json').read_text());payload=json.loads((s/'payload-hashes.json').read_text());inputs=json.loads((s/'check-inputs.json').read_text())
def check():return {'bases':[p for p,v in bases.items() if h(r/p)!=v], 'dependencies':[p for p,v in deps.items() if h(r/p)!=v], 'payload':[p for p,v in payload.items() if h(s/'changes'/p)!=v], 'check_inputs':[p for p,v in inputs.items() if h(s/p)!=v]}
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(s/'tmp'))
steps=[('before',['go','test','-overlay',str(s/'overlay-before.json'),'-race','./internal/application/evidence','-run','^TestContextRuntimeActiveEnrollmentAvoidsUnusedOwnerClaim$','-count=1','-timeout=60s','-v']),('after',['go','test','-overlay',str(s/'overlay-after.json'),'-race','./internal/application/evidence','-run','^Test(ContextRuntime|ActiveContextEnrollment|WorkerCurrent|WorkerPending|WorkerOwner|NativePreparation)','-count=1','-timeout=90s','-v']),('vet',['go','vet','-overlay',str(s/'overlay-after.json'),'./internal/application/evidence'])]
for name,cmd in steps:
 before=check();assert not any(before.values()),before
 started=time.monotonic()
 with (s/'evidence'/f'{name}.log').open('w') as log:
  try:p=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240);code=p.returncode
  except subprocess.TimeoutExpired:code=124
 after=check();out=(s/'evidence'/f'{name}.log').read_text()
 report={'phase':name,'command':cmd,'exit':code,'seconds':round(time.monotonic()-started,3),'before':before,'after':after,'payload':payload,'dependencies_count':len(deps),'environment':{k:env[k] for k in ('GOMAXPROCS','GOFLAGS','TMPDIR')}}
 (s/'evidence'/f'{name}.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);print(out,flush=True)
 expected=(code==1 and 'already active preparation used enrollment or missed original first batch' in out and 'synthetic enrollment owner must not be used' in out and '--- FAIL: TestContextRuntimeActiveEnrollmentAvoidsUnusedOwnerClaim' in out) if name=='before' else code==0
 if not expected or any(after.values()):sys.exit(1)
