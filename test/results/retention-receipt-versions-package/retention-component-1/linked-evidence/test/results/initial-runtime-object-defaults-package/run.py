from pathlib import Path
import hashlib,json,os,subprocess,time
C=Path(__file__).resolve().parent
L=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((C/'manifest.json').read_text());deps=json.loads((C/'dependencies.json').read_text())
def verify():
 bad=[]
 for r,h in deps.items():
  if not (L/r).is_file() or sha(L/r)!=h:bad.append('dependency:'+r)
 for x in manifest:
  p=L/x['path'];base=sha(p) if p.is_file() else None
  if base!=x['base_sha256']:bad.append('base:'+x['path'])
  if sha(C/'source'/x['path'])!=x['payload_sha256']:bad.append('payload:'+x['path'])
 return bad
assert not verify(),verify()
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR='/home/phil/.cache/asservat-build/tmp')
pkg='./internal/adapters/kubernetes'
commands=[('before',['go','test','-overlay='+str(C/'before-overlay.json'),'-race','-count=1','-timeout=180s','-run','^TestInitialRuntimeDeploymentDefaultsPreserveOriginalIdentity$',pkg]),('after',['go','test','-overlay='+str(C/'overlay.json'),'-race','-count=1','-timeout=180s','-run','^Test(InitialRuntime|OwnerWorkload|HubWorkerWorkload|ConfigurationLaunch)',pkg]),('compile',['go','test','-overlay='+str(C/'overlay.json'),'-run','^$',pkg,'./internal/bootstrap','./test/integration']),('vet',['go','vet','-overlay='+str(C/'overlay.json'),pkg,'./internal/bootstrap','./test/integration'])]
results={'manifest_sha256':sha(C/'manifest.json'),'dependencies_sha256':sha(C/'dependencies.json'),'commands':[]}
terminal=0
for name,cmd in commands:
 print('START',name,flush=True);start=time.monotonic()
 with (C/(name+'.log')).open('w') as f:r=subprocess.run(cmd,cwd=L,env=env,stdout=f,stderr=subprocess.STDOUT)
 row={'name':name,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start};results['commands'].append(row);print('TERMINAL',name,r.returncode,flush=True)
 if name=='before':
  log=(C/'before.log').read_text()
  if r.returncode!=1 or 'builder omitted explicit Always restart policy' not in log:
   terminal=1;break
 elif r.returncode:
  terminal=r.returncode;break
results.update(source_changes=verify(),paths=len(manifest),dependencies=len(deps))
if results['source_changes']:terminal=1
results['terminal_exit']=terminal
(C/'result.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results),flush=True)
raise SystemExit(terminal)
