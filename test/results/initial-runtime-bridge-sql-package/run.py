from pathlib import Path
import hashlib,json,os,subprocess,time
CHECK=Path(__file__).resolve().parent
LIVE=Path('/home/phil/Projekte/asservat')
sha=lambda b:hashlib.sha256(b).hexdigest()
deps=json.loads((CHECK/'dependencies.json').read_text())
def verify():
 bad=[]
 for kind in ['before','after']:
  for v in json.loads((CHECK/kind/'manifest.json').read_text()):
   p=CHECK/kind/'source'/v['path'];b=LIVE/v['path']
   if sha(p.read_bytes())!=v['payload_sha256']:bad.append(kind+':payload:'+v['path'])
   if (sha(b.read_bytes()) if b.is_file() else None)!=v['base_sha256']:bad.append(kind+':base:'+v['path'])
 for p,d in deps.items():
  if not (LIVE/p).is_file() or sha((LIVE/p).read_bytes())!=d:bad.append('dependency:'+p)
 return bad
bad=verify()
if bad:raise SystemExit('CHANGED BEFORE: '+str(bad))
env=os.environ.copy();env.update({'GOMAXPROCS':'2','GOFLAGS':'-p=2','TMPDIR':'/home/phil/.cache/asservat-build/tmp'})
commands=[]
for kind in ['before','after']:
 commands.append((kind+'-compile',['go','test','-overlay='+str(CHECK/kind/'overlay.json'),'-run','^$','./internal/adapters/postgres','./internal/application/fleet','./test/integration']))
commands.append(('after-vet',['go','vet','-overlay='+str(CHECK/'after/overlay.json'),'./internal/adapters/postgres','./internal/application/fleet','./test/integration']))
result={'dependencies_sha256':sha((CHECK/'dependencies.json').read_bytes()),'manifest_sha256':{k:sha((CHECK/k/'manifest.json').read_bytes()) for k in ['before','after']},'commands':[]}
terminal=0
for phase,cmd in commands:
 print('START',phase,flush=True);start=time.monotonic()
 with (CHECK/(phase+'.log')).open('w') as log:r=subprocess.run(cmd,cwd=LIVE,env=env,stdout=log,stderr=subprocess.STDOUT)
 result['commands'].append({'phase':phase,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start});print('TERMINAL',phase,r.returncode,flush=True)
 terminal=terminal or r.returncode
 if r.returncode:break
result.update(terminal_exit=terminal,source_changes=verify(),checked_payloads=8,checked_dependencies=len(deps))
if result['source_changes']:result['terminal_exit']=1
(CHECK/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result),flush=True)
raise SystemExit(result['terminal_exit'])
