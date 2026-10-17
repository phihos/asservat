from pathlib import Path
import hashlib,json,os,shutil,signal,subprocess,tempfile,time
c=Path(__file__).parent;live=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='b277d178169280d3f6b2911afc2202a947c8d3b18fe65c1aa79caf7a9d042f60'
assert sha(c/'dependencies.json')=='8378137e6a0f5515d7e82b89bb397e0f666535edbc10cd96c213b7eb92f53157'
manifest=json.loads((c/'manifest.json').read_text())['paths'];deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text());inventory=set(json.loads((c/'inventory.json').read_text()));dirs=json.loads((c/'linked-directories.json').read_text())
metadata={name:sha(c/name) for name in ["run.py","manifest.json","dependencies.json","dependency-args.json","inventory.json","linked-directories.json","freeze.json"]}
def verify():
 actual=set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())
 return {'metadata':[name for name,h in metadata.items() if sha(c/name)!=h], 'payloads':[r['path'] for r in manifest if sha(c/'files'/r['path'])!=r['sha256']], 'bases':[r['path'] for r in manifest if sha(live/r['path'])!=r['base']], 'dependencies':[p for p,h in deps.items() if sha(live/p)!=h], 'inventory':sorted(actual^inventory), 'directories':[p for p,v in dirs.items() if not (live/p).is_dir() or sorted(q.name for q in (live/p).iterdir())!=v]}
assert not (c/'result.json').exists()
r={'started':time.time(),'runner':sha(Path(__file__)),'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'before':verify(),'metadata':metadata,'phases':[],'native':False,'runtime_enablement':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
if any(r['before'].values()):
 with (c/'preflight-failure.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 raise SystemExit(2)
free=shutil.disk_usage('/tmp').free;assert free>=4*1024**3
scratch=Path(tempfile.mkdtemp(prefix='asservat-fleet-contention-component-',dir='/tmp'));tmp=scratch/'go-tmp';tmp.mkdir();mirror=scratch/'mirror';r['scratch']=str(scratch);r['tmp_free_before']=free
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_'):del env[k]
packages=['./internal/domain/fleet','./internal/application/fleet','./internal/adapters/postgres','./internal/bootstrap','./cmd/asservat','./test/integration']
def race(packages,selector=None):
 cmd=['go','test','-race','-vet=off','-count=1','-timeout=6m','-v',*packages]
 if selector:cmd.append('-run='+selector)
 return cmd
phases=[
 ('compile',['go','test','-vet=off','-run=^$','-count=1',*packages],0,0),
 ('application-before',race(['./internal/application/fleet'],'^TestTrustObserverOnlyUnchangedPersistenceContentionSkipsFence$'),1,0),
 ('application-domain-races',race(['./internal/application/fleet','./internal/domain/fleet']),0,2),
 ('postgres-races',race(['./internal/adapters/postgres'],'^Test(FleetObservationContention|OwnerIdentitySQLPrerequisite)'),0,4),
 ('bootstrap-races',race(['./internal/bootstrap'],'^TestConfigurationRuntimeContentionInvalidatesPendingAndActiveNotices$'),0,1),
 ('vet',['go','vet',*packages],0,0),
 ('go-architecture',['make','go-architecture-check','PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'],0,0),
 ('canonical',['make','spec-check','architecture-check','design-check','PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'],0,0),
]
code=2;mirror_hashes={};target='internal/application/fleet/trust_observer.go'
try:
 probe=scratch/'write-probe'
 with probe.open('xb') as f:f.write(bytes(1024**2));f.flush();os.fsync(f.fileno())
 probe.unlink()
 for rel in deps:
  p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for row in manifest:
  p=mirror/row['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/row['path'],p)
 for rel in dirs:(mirror/rel).mkdir(parents=True,exist_ok=True)
 mirror_hashes={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
 with (c/'mirror-manifest.json').open('x') as f:json.dump(mirror_hashes,f,indent=2);f.write('\n')
 for name,cmd,expected,minimum in phases:
  check=verify()
  if any(check.values()):r['phase_preflight']=check;code=2;break
  shutil.copyfile(live/target if name=='application-before' else c/'files'/target,mirror/target)
  log=c/'evidence'/(name+'.log');start=time.time();stop=None
  with log.open('x') as f:
   process=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'phase':name,'pid':process.pid,'started':start}),flush=True)
   while process.poll() is None:
    if time.time()-start>600:stop='600-second infrastructure ceiling'
    elif log.stat().st_size>32*1024**2:stop='32MiB output bound'
    elif shutil.disk_usage('/tmp').free<256*1024**2:stop='scratch below 256MiB'
    if stop:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=10)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
     break
    time.sleep(.5)
  output=log.read_text();top=sum(line.startswith('--- PASS:') for line in output.splitlines());named=sum(line.lstrip().startswith('--- PASS:') for line in output.splitlines());required=top>=minimum
  if name=='application-before':required='failed persistence changed fencing classification' in output and 'FAIL: TestTrustObserverOnlyUnchangedPersistenceContentionSkipsFence' in output and '[build failed]' not in output and 'panic:' not in output
  mirror_file_set=sorted({p.relative_to(mirror).as_posix() for p in mirror.rglob('*') if p.is_file()} ^ set(mirror_hashes))
  entry={'mirror_file_set':mirror_file_set,'name':name,'command':cmd,'exit':process.returncode,'expected_exit':expected,'seconds':time.time()-start,'stop_reason':stop,'log_sha256':sha(log),'hashes':verify(),'required_checks_present':required,'top_level_pass':top,'named_pass':named}
  r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=0 if not stop and process.returncode==expected and required and not any(entry['hashes'].values()) and not mirror_file_set else 124 if stop else process.returncode or 2
  if code:break
except Exception as e:r['runner_error']=repr(e);code=2
finally:
 if (mirror/target).exists():shutil.copyfile(c/'files'/target,mirror/target)
 r['mirror_changed']=[p for p,h in mirror_hashes.items() if sha(mirror/p)!=h]
 r['mirror_file_set']=sorted({p.relative_to(mirror).as_posix() for p in mirror.rglob('*') if p.is_file()} ^ set(mirror_hashes))
 shutil.rmtree(scratch)
 r.update(exit=code,ended=time.time(),after=verify(),scratch_removed=not scratch.exists())
 with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] and not r['mirror_file_set'] else 2)
