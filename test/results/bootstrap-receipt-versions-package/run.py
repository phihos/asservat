import hashlib,json,os,shutil,signal,subprocess,tempfile,time
from pathlib import Path
c=Path(__file__).resolve().parent;r=Path('/home/phil/Projekte/asservat');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
m=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'args.json').read_text());inventory=set(json.loads((c/'inventory.json').read_text()));dirs=json.loads((c/'linked-directories.json').read_text());sqlc=Path('/home/phil/.cache/asservat-build/bin/sqlc');python='/home/phil/.cache/asservat-build/spec-venv/bin/python'
assert not (c/'result.json').exists();assert shutil.disk_usage('/home/phil').free>32*(1<<30)
def check():
 names=set(subprocess.check_output(['rg','--files','-g','!**/node_modules/**',*args],cwd=r,text=True).splitlines())
 return {'deps':[p for p,h in deps.items() if sha(r/p)!=h],'inventory':sorted(names^inventory),'payload':[x['path'] for x in m if sha(c/'files'/x['path'])!=x['payload']],'bases':[x['path'] for x in m if sha(r/x['path'])!=x['base']],'directories':[p for p,e in dirs.items() if not (r/p).is_dir() or sorted(x.name for x in (r/p).iterdir())!=e]}
assert not any(check().values()),check()
tmp=Path(tempfile.mkdtemp(prefix='asservat-bootstrap-receipts-',dir='/home/phil/.cache/asservat-build'));mirror=tmp/'mirror';build=tmp/'build';build.mkdir()
env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(build),PYTHONDONTWRITEBYTECODE='1')
report={'native':False,'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'scratch':str(tmp),'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'runner':sha(Path(__file__)),'phases':[],'sqlcSHA256':sha(sqlc)}
def phase(name,cmd,cwd,expected=0):
 assert not any(check().values()),check();start=time.monotonic();log=c/(name+'.log')
 with log.open('x') as out:
  p=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'phase':name,'pid':p.pid}),flush=True)
  try:code=p.wait(timeout=600)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   code=124
 raw=log.read_text();entry={'name':name,'command':cmd,'exit':code,'expected':expected,'seconds':round(time.monotonic()-start,3),'hashes':check(),'logSHA256':sha(log),'passes':sum(l.lstrip().startswith('--- PASS:') for l in raw.splitlines()),'topPasses':sum(l.startswith('--- PASS:') for l in raw.splitlines())};report['phases'].append(entry);print(json.dumps(entry),flush=True)
 assert code==expected and not any(entry['hashes'].values()),name
 if name=='before-bootstrap':
  assert '[build failed]' not in raw and 'unexpected immutable-version decision' in raw and raw.count('--- FAIL: TestBootstrapCurrentAuditRequiresImmutableVersion/')==2
 return raw
code=1;baseline={};changed=[]
try:
 for rel in deps:
  dest=mirror/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(r/rel,dest)
 for rel in dirs:(mirror/rel).mkdir(parents=True,exist_ok=True)
 for x in m:
  dest=mirror/x['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],dest)
 baseline={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()}
 pkgs=['./internal/domain/audit','./internal/adapters/postgres','./internal/application/audit','./internal/application/fleet','./internal/adapters/objectstore','./internal/bootstrap','./test/integration']
 phase('compile',['go','test','-vet=off','-run=^$','-count=1',*pkgs],mirror)
 phase('before-bootstrap',['go','test','-race','-vet=off','-overlay',str(c/'before-overlay.json'),'-run=^TestBootstrapCurrentAuditRequiresImmutableVersion$','-count=1','-timeout=120s','-v','./internal/domain/audit'],r,1)
 phase('affected-races',['go','test','-race','-vet=off','-count=1','-timeout=300s','-v',*pkgs[:5]],mirror)
 phase('vet',['go','vet',*pkgs],mirror)
 phase('sql-check',['make','sql-check','PYTHON='+python,'ASSERVAT_BUILD_TMP='+str(build),'SQLC='+str(sqlc)],mirror)
 phase('canonical',['make','spec-check','architecture-check','design-check','go-architecture-check','PYTHON='+python],mirror)
 code=0
except Exception as e:report['error']=repr(e)
finally:
 current={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()};allowed=set(changed);report['mirrorDrift']=[p for p in baseline.keys()|current.keys() if p not in allowed and baseline.get(p)!=current.get(p)]
 report['finalHashes']=check();shutil.rmtree(tmp);report['scratchRemoved']=not tmp.exists()
 if report['mirrorDrift'] or any(report['finalHashes'].values()):code=1
 report['exit']=code;(c/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'exit':code,'error':report.get('error'),'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
