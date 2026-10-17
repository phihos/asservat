from pathlib import Path
import hashlib,json,os,subprocess,sys,time
r=Path('/home/phil/Projekte/asservat');s=Path('/home/phil/.cache/asservat-build/planning/native-phase-diagnostic-20261012')
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
bases=json.loads((s/'base.json').read_text());deps=json.loads((s/'dependencies.json').read_text());payload=json.loads((s/'payload-hashes.json').read_text())
def check():return {'bases':[p for p,v in bases.items() if h(r/p)!=v], 'dependencies':[p for p,v in deps.items() if h(r/p)!=v], 'payload':[p for p,v in payload.items() if h(s/'changes'/p)!=v]}
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(s/'tmp'))
steps=[('focused',['go','test','-overlay',str(s/'overlay.json'),'-race','./test/integration','-run','^TestNativePhaseDiagnostic','-count=1','-timeout=60s','-v']),('vet',['go','vet','-overlay',str(s/'overlay.json'),'./test/integration'])]
for name,cmd in steps:
 before=check();assert not any(before.values()),before
 started=time.monotonic()
 with (s/'evidence'/f'{name}.log').open('w') as log:
  try:p=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180);code=p.returncode
  except subprocess.TimeoutExpired:code=124
 after=check();out=(s/'evidence'/f'{name}.log').read_text()
 report={'phase':name,'command':cmd,'exit':code,'seconds':round(time.monotonic()-started,3),'before':before,'after':after,'payload':payload,'dependencies_count':len(deps),'environment':{k:env[k] for k in ('GOMAXPROCS','GOFLAGS','TMPDIR')}}
 (s/'evidence'/f'{name}.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);print(out,flush=True)
 if code!=0 or any(after.values()):sys.exit(1)
