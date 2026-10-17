from pathlib import Path
import hashlib,json,os,shutil,signal,subprocess,tempfile,time
c=Path(__file__).parent
live=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='ad86f1ff0754ca0c768415517c8115dfd96b79427916b476138e3539b1ac2408'
assert sha(c/'dependencies.json')=='363d320c4f0fe2edb96383ce175492d01f4c93f9e9c3a990bce2de02f65106a1'
manifest=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text());extra=json.loads((c/'native-dependencies.json').read_text())
assert set(extra)=={'sqlc.yaml'}
all_deps=deps|extra

def verify():
 inventory=set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())
 return {'payloads':[x['path'] for x in manifest if sha(c/'files'/x['path'])!=x['payload_sha256']], 'bases':[x['path'] for x in manifest if sha(live/x['path'])!=x['base_sha256']], 'dependencies':[p for p,v in all_deps.items() if sha(live/p)!=v], 'inventory':sorted(inventory^set(deps))}

assert not (c/'result.json').exists()
r={'started':time.time(),'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'native_dependencies':sha(c/'native-dependencies.json'),'runner':sha(Path(__file__)),'before':verify(),'phases':[],'runtime_enablement':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
if any(r['before'].values()):
 with (c/'preflight-failure.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 raise SystemExit(2)
free=shutil.disk_usage('/tmp').free
assert free>=4*1024**3,'less than 4GiB free /tmp'
scratch=Path(tempfile.mkdtemp(prefix='asservat-owner-prerequisite-',dir='/tmp'));tmp=scratch/'go-tmp';tmp.mkdir();mirror=scratch/'mirror'
r['scratch']=str(scratch);r['tmp_free_before']=free
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_'):del env[k]
pattern='^TestInitialInstallationWithRealServices$/^owner-identity-roles-constructor-(expired-source|bridge-contention)$'
phases=[
 ('compile',['go','test','-vet=off','-run=^$','./internal/adapters/postgres','./test/integration'],0),
 ('diagnostic-before',['go','test','-count=1','-vet=off','-timeout=60s','-v','-run=^TestOwnerIdentitySQLPrerequisiteErrorsStaySanitized$','./internal/adapters/postgres'],0),
 ('postgres-race',['go','test','-race','-count=1','-timeout=90s','-v','-run=^TestOwnerIdentity(SQLPrerequisite|RolesKeepSeparateAuthority|OperationSQL)','./internal/adapters/postgres'],4),
 ('vet',['go','vet','./internal/adapters/postgres','./test/integration'],0),
 ('actual-sql',['python3','scripts/test-custody.py','--run',pattern],0),
]
code=2;mirror_hashes={}
try:
 probe=scratch/'write-probe'
 with probe.open('xb') as f:f.write(bytes(1024**2));f.flush();os.fsync(f.fileno())
 probe.unlink()
 for rel in all_deps:
  p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for x in manifest:
  p=mirror/x['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],p)
 (mirror/'test/results').mkdir(exist_ok=True)
 mirror_hashes={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
 with (c/'mirror-manifest.json').open('x') as f:json.dump(mirror_hashes,f,indent=2);f.write('\n')
 for name,cmd,minimum in phases:
  check=verify()
  if any(check.values()):r['phase_preflight']=check;code=2;break
  target='internal/adapters/postgres/owner_identity_roles.go'
  if name=='diagnostic-before':shutil.copyfile(live/target,mirror/target)
  else:shutil.copyfile(c/'files'/target,mirror/target)
  phase_env=env.copy()
  if name=='actual-sql':phase_env['ASSERVAT_INITIAL_INSTALLATION']='1'
  start=time.time();stop_reason=None;log=c/'evidence'/(name+'.log')
  with log.open('x') as f:
   p=subprocess.Popen(cmd,cwd=mirror,env=phase_env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
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
  required=top>=minimum;expected_exit=0;native_check=None
  if name=='diagnostic-before':
   expected_exit=1;required='fixed diagnostic/sentinel mismatch' in output and 'panic:' not in output and '[build failed]' not in output and 'FAIL: TestOwnerIdentitySQLPrerequisiteErrorsStaySanitized' in output
  if name=='actual-sql':
   native_dir=c/'evidence'/'native';native_dir.mkdir()
   for out in (mirror/'test/results').glob('*'):
    if out.is_file():shutil.copyfile(out,native_dir/out.name)
   report=json.loads((native_dir/'custody-environment.json').read_text())
   required_names={'TestInitialInstallationWithRealServices/owner-identity-roles-constructor-expired-source','TestInitialInstallationWithRealServices/owner-identity-roles-constructor-bridge-contention'}
   native_check={'testExit':report.get('testExit'),'cleanupFailures':report.get('cleanupFailures'),'sourceUnchangedDuringTest':report.get('sourceUnchangedDuringTest'),'source_count':len(report.get('sourceHashes',{})),'passedTestNames':report.get('passedTestNames',[]),'required_present':required_names.issubset(set(report.get('passedTestNames',[])))}
   required=native_check['testExit']==0 and native_check['cleanupFailures']==[] and native_check['sourceUnchangedDuringTest'] is True and native_check['required_present']
  entry={'name':name,'command':cmd,'exit':p.returncode,'expected_exit':expected_exit,'seconds':time.time()-start,'stop_reason':stop_reason,'log_sha256':sha(log),'hashes':verify(),'required_checks_present':required,'top_level_pass':top,'named_pass':named,'native':native_check}
  r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=0 if not stop_reason and p.returncode==expected_exit and required and not any(entry['hashes'].values()) else (124 if stop_reason else p.returncode or 2)
  if code:break
except Exception as e:r['runner_error']=repr(e);code=2
finally:
 if (mirror/'internal/adapters/postgres/owner_identity_roles.go').exists():shutil.copyfile(c/'files/internal/adapters/postgres/owner_identity_roles.go',mirror/'internal/adapters/postgres/owner_identity_roles.go')
 r['mirror_changed']=[p for p,v in mirror_hashes.items() if sha(mirror/p)!=v]
 if (mirror/'test/results').exists():
  recovery=c/'evidence'/'native-recovery'
  if not (c/'evidence'/'native').exists():
   recovery.mkdir()
   for out in (mirror/'test/results').glob('*'):
    if out.is_file():shutil.copyfile(out,recovery/out.name)
 shutil.rmtree(scratch)
 r.update(exit=code,ended=time.time(),after=verify(),scratch_removed=not scratch.exists())
 with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] else 2)
