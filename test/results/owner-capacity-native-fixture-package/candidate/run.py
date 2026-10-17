from pathlib import Path
import hashlib,json,os,subprocess,time,signal
s=Path(__file__).resolve().parent;r=Path('/home/phil/Projekte/asservat')
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
deps=json.loads((s/'dependencies.json').read_text());payload=json.loads((s/'payload.json').read_text());bases=json.loads((s/'bases.json').read_text())
with (s/'evidence/started').open('x'):pass
def checks():
 return {'live':[p for p,v in deps.items() if h(r/p)!=v],'bases':[p for p,v in bases.items() if h(r/p)!=v],'payload':[p for p,v in payload.items() if h(s/'files'/p)!=v]}
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(s/'tmp'))
overlay=['-overlay',str(s/'overlay.json')]
pkgs=['./test/integration']
steps=[('compile',['go','test',*overlay,'-vet=off','-run','^$','-count=1',*pkgs]),('vet',['go','vet',*overlay,*pkgs])]

for name,command in steps:
 before=checks();assert not any(before.values()),before
 start=time.monotonic()
 with (s/'evidence'/f'{name}.log').open('x') as log:
  p=subprocess.Popen(command,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'phase':name,'pid':p.pid}),flush=True)
  try:code=p.wait(timeout=240)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   code=124
 after=checks();report={'command':command,'exit':code,'seconds':round(time.monotonic()-start,3),'before':before,'after':after}
 with (s/'evidence'/f'{name}.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report),flush=True)
 if code!=0 or any(after.values()):raise SystemExit(1)
