from pathlib import Path
import hashlib, json, os, subprocess, time
CHECK=Path(__file__).resolve().parent
LIVE=Path('/home/phil/Projekte/asservat')
sha=lambda b: hashlib.sha256(b).hexdigest()
manifest=json.loads((CHECK/'manifest.json').read_text())
deps=json.loads((CHECK/'dependencies.json').read_text())
def verify():
 bad=[]
 for x in manifest:
  p=CHECK/'source'/x['path'];b=LIVE/x['path']
  if sha(p.read_bytes())!=x['payload_sha256']:bad.append('payload:'+x['path'])
  actual=sha(b.read_bytes()) if b.is_file() else None
  if actual!=x['base_sha256']:bad.append('base:'+x['path'])
 for r,d in deps.items():
  p=LIVE/r
  if not p.is_file() or sha(p.read_bytes())!=d:bad.append('dependency:'+r)
 return bad
before=verify()
if before:raise SystemExit('SOURCE CHANGED BEFORE: '+str(before))
env=os.environ.copy();env.update({'GOMAXPROCS':'2','GOFLAGS':'-p=2','TMPDIR':'/home/phil/.cache/asservat-build/tmp'})
Path(env['TMPDIR']).mkdir(exist_ok=True,parents=True)
overlay='-overlay='+str(CHECK/'overlay.json')
commands=[('compile',['go','test',overlay,'-run','^$','-vet=off','./cmd/asservat','./internal/contracts','./internal/adapters/kubernetes','./internal/adapters/postgres','./internal/bootstrap','./test/integration']),('race',['go','test',overlay,'-race','-count=1','-v','-timeout=90s','-run','^(TestConfigurationRoleInstaller|TestConfigurationInstallerGenerated|TestProvisionedHubWorker)','./internal/bootstrap','./internal/adapters/kubernetes']),('vet',['go','vet',overlay,'./cmd/asservat','./internal/bootstrap','./internal/adapters/kubernetes'])]
result={'manifest_sha256':sha((CHECK/'manifest.json').read_bytes()),'dependencies_sha256':sha((CHECK/'dependencies.json').read_bytes()),'commands':[]}
terminal=0
for phase,cmd in commands:
 print('START',phase,flush=True);start=time.monotonic()
 with (CHECK/(phase+'.log')).open('w') as log:r=subprocess.run(cmd,cwd=LIVE,env=env,stdout=log,stderr=subprocess.STDOUT)
 result['commands'].append({'phase':phase,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start});print('TERMINAL',phase,r.returncode,flush=True)
 terminal=terminal or r.returncode
 if phase=='compile' and r.returncode:break
result.update(terminal_exit=terminal,source_changes=verify(),checked_payloads=len(manifest),checked_dependencies=len(deps))
if result['source_changes']:result['terminal_exit']=1
(CHECK/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
raise SystemExit(result['terminal_exit'])
