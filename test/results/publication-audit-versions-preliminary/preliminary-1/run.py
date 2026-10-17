import hashlib,json,os,shutil,signal,subprocess,tempfile,time
from pathlib import Path
c=Path(__file__).resolve().parent;r=Path('/home/phil/Projekte/asservat');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
m=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'args.json').read_text());sqlc=Path('/home/phil/.cache/asservat-build/bin/sqlc')
assert not (c/'result.json').exists();assert shutil.disk_usage('/home/phil').free>32*(1<<30)
tmp=Path(tempfile.mkdtemp(prefix='asservat-publication-',dir='/home/phil/.cache/asservat-build'));mirror=tmp/'mirror';build=tmp/'build';build.mkdir()
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(build),PYTHONDONTWRITEBYTECODE='1')
report={'native':False,'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'scratch':str(tmp),'manifest':sha(c/'manifest.json'),'runner':sha(Path(__file__)),'phases':[],'sqlcSHA256':sha(sqlc)}
def check():
 names=set(subprocess.check_output(['rg','--files','-g','!**/node_modules/**',*args],cwd=r,text=True).splitlines())-{'docs/implementation-progress.md'}
 return {'deps':[p for p,h in deps.items() if sha(r/p)!=h],'inventory':sorted(names^set(deps)),'payload':[x['path'] for x in m if sha(c/'files'/x['path'])!=x['payload']],'bases':[x['path'] for x in m if sha(r/x['path'])!=x['base']]}
def phase(name,cmd,cwd,expected=0):
 assert not any(check().values()),check();start=time.monotonic();log=c/(name+'.log')
 with log.open('x') as out:
  p=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
  try:code=p.wait(timeout=300)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   code=124
 raw=log.read_text();entry={'name':name,'command':cmd,'exit':code,'expected':expected,'seconds':round(time.monotonic()-start,3),'hashes':check(),'logSHA256':sha(log),'passes':sum(l.lstrip().startswith('--- PASS:') for l in raw.splitlines()),'topPasses':sum(l.startswith('--- PASS:') for l in raw.splitlines())};report['phases'].append(entry);print(json.dumps(entry),flush=True)
 assert code==expected and not any(entry['hashes'].values()),name
 if name=='before':
  assert '[build failed]' not in raw and 'historical or nonmatching receipt authorized current publication' in raw and raw.count('--- FAIL: TestAcceptedPublicationRequiresRetainedIntentReceipt/')==18,raw[-500:]
  assert raw.count('--- FAIL: TestContextEffectReceiptsRequireImmutableVersions/')==4
 return raw
code=1
try:
 assert not any(check().values()),check()
 for rel in deps:
  dest=mirror/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(r/rel,dest)
 for x in m:
  dest=mirror/x['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],dest)
 baseline={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()}
 assert phase('sqlc-version',[str(sqlc),'version'],mirror).strip()=='v1.31.1'
 phase('sqlc-generate',[str(sqlc),'generate'],mirror)
 changed=[p for p,h in baseline.items() if p.startswith('internal/adapters/postgres/custodydb/') and sha(mirror/p)!=h];assert changed==['internal/adapters/postgres/custodydb/publication.sql.go'],changed
 for rel in changed:
  dest=c/'generated'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(mirror/rel,dest)
 report['generated']=[{'path':p,'base':deps[p],'payload':sha(mirror/p)} for p in changed]
 pkgs=['./internal/domain/audit','./internal/adapters/postgres','./internal/application/audit','./internal/application/evidence','./internal/bootstrap','./test/integration']
 phase('compile',['go','test','-vet=off','-run=^$','-count=1',*pkgs],mirror)
 phase('before',['go','test','-race','-vet=off','-overlay',str(c/'before-overlay.json'),'-run=^(TestContextEffectReceiptsRequireImmutableVersions|TestAcceptedPublicationRequiresRetainedIntentReceipt)$','-count=1','-timeout=120s','-v','./internal/domain/audit','./internal/adapters/postgres'],r,1)
 phase('affected-races',['go','test','-race','-vet=off','-count=1','-timeout=180s','-v',*pkgs[:4]],mirror)
 phase('vet',['go','vet',*pkgs],mirror)
 current={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()};allowed=set(changed);drift=[p for p in baseline.keys()|current.keys() if p not in allowed and baseline.get(p)!=current.get(p)];assert not drift,drift
 code=0
except Exception as e:report['error']=repr(e)
finally:
 report['finalHashes']=check();shutil.rmtree(tmp);report['scratchRemoved']=not tmp.exists();report['exit']=code;(c/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'exit':code,'error':report.get('error'),'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
