from pathlib import Path
import hashlib,json,os,shutil,signal,subprocess,tempfile,time
c=Path(__file__).parent
live=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='c0843d5bff32a156af35d392009a2b94338375b38f9f26ac5d1c004dca29f300'
assert sha(c/'dependencies.json')=='56c191bd6685f980841e7e43ef8e4cdc55df450b2ebd6cf5caf8a966264cb764'
manifest=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text())
def verify():
 inventory=set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())
 return {'payloads':[x['path'] for x in manifest if sha(c/'files'/x['path'])!=x['payload_sha256']], 'bases':[x['path'] for x in manifest if sha(live/x['path'])!=x['base_sha256']], 'dependencies':[p for p,v in deps.items() if sha(live/p)!=v], 'inventory':sorted(inventory^set(deps))}
assert not (c/'result.json').exists()
r={'started':time.time(),'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'runner':sha(Path(__file__)),'before':verify(),'phases':[],'native':False,'runtime_enablement':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
if any(r['before'].values()):
 with (c/'preflight-failure.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 raise SystemExit(2)
free=shutil.disk_usage('/tmp').free
assert free>=4*1024**3,'less than 4GiB free /tmp'
scratch=Path(tempfile.mkdtemp(prefix='asservat-owner-continuation-',dir='/tmp'));tmp=scratch/'go-tmp';tmp.mkdir();mirror=scratch/'mirror'
r['scratch']=str(scratch);r['tmp_free_before']=free
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_'):del env[k]
phases=[
 ('selectors',['python', 'scripts/test-initial-bootstrap-selection.py'],9),
 ('compile',['go','test','-vet=off','-run=^$','./test/integration','./cmd/asservat'],0),
 ('fixture-bounds',['go','test','-vet=off','-count=1','-timeout=1m','-v','-run=^TestInitialBootstrapAggregateDeadlineSelection$','./test/integration'],1),
 ('original-owner-races',['go','test','-race','-vet=off','-count=1','-timeout=4m','-v','-run=^(TestOwnerBootstrap|TestProviderOwnerInstallation)','./internal/adapters/kubernetes'],1),
 ('vet',['go','vet','./test/integration','./internal/adapters/kubernetes','./internal/bootstrap','./cmd/asservat'],0),
 ('go-architecture',['make','go-architecture-check','PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'],0),
]
code=2;mirror_hashes={}
try:
 probe=scratch/'write-probe'
 with probe.open('xb') as f:f.write(bytes(1024**2));f.flush();os.fsync(f.fileno())
 probe.unlink()
 for rel in deps:
  p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for x in manifest:
  p=mirror/x['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],p)
 mirror_hashes={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
 with (c/'mirror-manifest.json').open('x') as f:json.dump(mirror_hashes,f,indent=2);f.write('\n')
 for name,cmd,minimum in phases:
  check=verify()
  if any(check.values()):r['phase_preflight']=check;code=2;break
  start=time.time();stop_reason=None;log=c/'evidence'/(name+'.log')
  with log.open('x') as f:
   p=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'phase':name,'pid':p.pid,'started':start}),flush=True)
   while p.poll() is None:
    if time.time()-start>600:stop_reason='600-second infrastructure ceiling'
    elif log.stat().st_size>32*1024**2:stop_reason='32MiB output bound'
    elif shutil.disk_usage('/tmp').free<256*1024**2:stop_reason='scratch below 256MiB'
    if stop_reason:
     os.killpg(p.pid,signal.SIGTERM)
     try:p.wait(timeout=10)
     except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
     break
    time.sleep(.5)
  output=log.read_text();top=sum(line.startswith('--- PASS:') for line in output.splitlines());named=sum(line.lstrip().startswith('--- PASS:') for line in output.splitlines())
  required=('Ran 9 tests' in output and '\nOK\n' in output) if name=='selectors' else top>=minimum
  entry={'name':name,'command':cmd,'exit':p.returncode,'seconds':time.time()-start,'stop_reason':stop_reason,'log_sha256':sha(log),'hashes':verify(),'required_checks_present':required,'top_level_pass':top,'named_pass':named}
  r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=0 if not stop_reason and p.returncode==0 and required and not any(entry['hashes'].values()) else (124 if stop_reason else p.returncode or 2)
  if code:break
except Exception as e:r['runner_error']=repr(e);code=2
finally:
 r['mirror_changed']=[p for p,v in mirror_hashes.items() if sha(mirror/p)!=v]
 shutil.rmtree(scratch)
 r.update(exit=code,ended=time.time(),after=verify(),scratch_removed=not scratch.exists())
 with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] else 2)
