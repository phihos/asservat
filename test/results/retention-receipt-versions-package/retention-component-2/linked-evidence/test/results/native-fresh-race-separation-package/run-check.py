#!/usr/bin/env python3
import hashlib,json,os,pathlib,signal,subprocess,sys,time
S=pathlib.Path(__file__).resolve().parent
R=pathlib.Path('/home/phil/Projekte/asservat')
E=S/'evidence'; E.mkdir(exist_ok=True)
T=S/'tmp'; T.mkdir(exist_ok=True)
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((S/'manifest.json').read_text())
deps=json.loads((S/'dependencies.json').read_text())
def snapshot():
 changes=[]
 for rel,want in deps.items():
  p=R/rel; got=digest(p) if p.exists() else None
  if got!=want: changes.append({'path':rel,'expected':want,'actual':got})
 for x in manifest:
  p=R/x['path']; got=digest(p) if p.exists() else None
  if got!=x['base_sha256']: changes.append({'base':x['path'],'actual':got})
  payload=S/'files'/x['path']; got=digest(payload) if payload.exists() else None
  if got!=x['sha256']: changes.append({'payload':x['path'],'actual':got})
 return {'dependencies':len(deps),'changes':changes,'manifest_sha256':digest(S/'manifest.json'),'dependencies_sha256':digest(S/'dependencies.json'),'overlay_sha256':digest(S/'overlay.json')}
initial=snapshot(); (E/'before.json').write_text(json.dumps(initial,indent=2)+'\n')
if initial['changes']: sys.exit(3)
env=os.environ.copy(); env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(T))
# No service selectors or fixture environment may run through this helper.
steps=[('compile',['go','test','-overlay',str(S/'overlay.json'),'./test/integration','-run','^$','-count=1','-timeout=60s']),('vet',['go','vet','-overlay',str(S/'overlay.json'),'./test/integration'])]
results=[]; outcome=0
for name,cmd in steps:
 before=snapshot()
 if before['changes']: outcome=3; break
 started=time.monotonic()
 with (E/(name+'.log')).open('w') as log:
  p=subprocess.Popen(cmd,cwd=R,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'step':name,'pid':p.pid,'command':cmd}),flush=True)
  timed_out=False
  try: rc=p.wait(timeout=240)
  except subprocess.TimeoutExpired:
   timed_out=True; os.killpg(p.pid,signal.SIGTERM)
   try: rc=p.wait(timeout=10)
   except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); rc=p.wait()
 after=snapshot()
 result={'step':name,'command':cmd,'exit':rc,'timed_out':timed_out,'elapsed_seconds':round(time.monotonic()-started,3),'before':before,'after':after}
 results.append(result); (E/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps({'step':name,'exit':rc,'elapsed_seconds':result['elapsed_seconds'],'changes':len(after['changes'])}),flush=True)
 if rc or timed_out or after['changes']: outcome=rc if rc>0 else 3; break
(E/'after.json').write_text(json.dumps(snapshot(),indent=2)+'\n')
print(json.dumps({'terminal':outcome,'steps':len(results)}),flush=True)
sys.exit(outcome)
