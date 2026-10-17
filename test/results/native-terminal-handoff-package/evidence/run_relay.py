from pathlib import Path
import os,json,hashlib,subprocess,time,sys
r=Path('/home/phil/Projekte/asservat');s=Path('/home/phil/.cache/asservat-build/planning/native-terminal-handoff-20261012')
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
bases=json.loads((s/'bases.json').read_text())
payload={str(p.relative_to(s/'changes')):h(p) for p in sorted((s/'changes').rglob('*')) if p.is_file()}
for p in payload:
 if p not in bases:bases[p]=h(r/p)
(s/'bases.json').write_text(json.dumps(bases,indent=2)+'\n');(s/'payload-hashes.json').write_text(json.dumps(payload,indent=2)+'\n')
deps={}
for prefix in ['internal','api','migrations','test/integration','web/dist']:
 for p in sorted((r/prefix).rglob('*')):
  if p.is_file():deps[str(p.relative_to(r))]=h(p)
for name in ['go.mod','go.sum']:deps[name]=h(r/name)
(s/'dependencies.json').write_text(json.dumps(deps,indent=2)+'\n')
before={'internal/transport/native/terminal_handoff_test.go':s/'changes/internal/transport/native/terminal_handoff_test.go','internal/transport/native/terminal_handoff_compat_test.go':s/'before/internal/transport/native/terminal_handoff_compat_test.go'}
(s/'overlay-before.json').write_text(json.dumps({'Replace':{str(r/p):str(v) for p,v in before.items()}},indent=2)+'\n')
(s/'overlay-after.json').write_text(json.dumps({'Replace':{str(r/p):str(s/'changes'/p) for p in payload if p.endswith('.go')}},indent=2)+'\n')
beforehash=h(s/'before/internal/transport/native/terminal_handoff_compat_test.go')
def check():
 return {'bases':[p for p,v in bases.items() if h(r/p)!=v], 'dependencies':[p for p,v in deps.items() if h(r/p)!=v], 'payload':[p for p,v in payload.items() if h(s/'changes'/p)!=v], 'before_helper':h(s/'before/internal/transport/native/terminal_handoff_compat_test.go')!=beforehash}
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(s/'tmp'))
steps=[
 ('before-current-relay',['go','test','-overlay',str(s/'overlay-before.json'),'-race','./internal/transport/native','-run','^TestNativeJoinedWaitsForExactSQLClosureBeyondIdleDelay$','-count=1','-timeout=30s','-v']),
 ('after-current-relay',['go','test','-overlay',str(s/'overlay-after.json'),'-race','./internal/transport/native','-run','^TestNative(JoinedWaitsForExactSQLClosureBeyondIdleDelay|HandoffRejectsUnacknowledgedClosure)$','-count=1','-timeout=60s','-v'])
]
for name,cmd in steps:
 beforecheck=check();assert not any(beforecheck.values()),beforecheck
 start=time.time()
 with (s/'evidence'/f'{name}.log').open('w') as log:p=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT)
 aftercheck=check();out=(s/'evidence'/f'{name}.log').read_text()
 report={'phase':name,'command':cmd,'exit':p.returncode,'seconds':round(time.time()-start,3),'before':beforecheck,'after':aftercheck,'payloadSHA256':h(s/'payload-hashes.json'),'dependencySHA256':h(s/'dependencies.json'),'dependenciesCount':len(deps),'environment':{k:env[k] for k in ['GOMAXPROCS','GOFLAGS','TMPDIR']}}
 (s/'evidence'/f'{name}.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);print(out[-12000:],flush=True)
 expected=(p.returncode!=0 and 'worker Joined while old SQL operation remained routeable' in out) if name.startswith('before') else p.returncode==0
 if not expected or any(aftercheck.values()):sys.exit(1)
