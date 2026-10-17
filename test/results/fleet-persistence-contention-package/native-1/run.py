from pathlib import Path
import hashlib,json,os,shutil,signal,subprocess,tempfile,time
c=Path(__file__).parent;live=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='b277d178169280d3f6b2911afc2202a947c8d3b18fe65c1aa79caf7a9d042f60'
assert sha(c/'dependencies.json')=='8378137e6a0f5515d7e82b89bb397e0f666535edbc10cd96c213b7eb92f53157'
manifest=json.loads((c/'manifest.json').read_text())['paths'];deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text());inventory=set(json.loads((c/'inventory.json').read_text()));dirs=json.loads((c/'linked-directories.json').read_text())
metadata={name:sha(c/name) for name in ["run.py","manifest.json","dependencies.json","dependency-args.json","inventory.json","linked-directories.json","freeze.json","required-tests.json","expected-native-sources.json"]}
def verify():
 actual=set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())
 return {'metadata':[name for name,h in metadata.items() if sha(c/name)!=h], 'payloads':[r['path'] for r in manifest if sha(c/'files'/r['path'])!=r['sha256']], 'bases':[r['path'] for r in manifest if sha(live/r['path'])!=r['base']], 'dependencies':[p for p,h in deps.items() if sha(live/p)!=h], 'inventory':sorted(actual^inventory), 'directories':[p for p,v in dirs.items() if not (live/p).is_dir() or sorted(q.name for q in (live/p).iterdir())!=v]}
assert not (c/'result.json').exists()
r={'started':time.time(),'runner':sha(Path(__file__)),'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'before':verify(),'metadata':metadata,'phases':[],'native':True,'runtime_enablement':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
if any(r['before'].values()):
 with (c/'preflight-failure.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 raise SystemExit(2)
free=shutil.disk_usage('/tmp').free;assert free>=4*1024**3
home_free=shutil.disk_usage('/home/phil').free;assert home_free>=32*1024**3
scratch=Path(tempfile.mkdtemp(prefix='asservat-fleet-contention-native-',dir='/tmp'));tmp=scratch/'go-tmp';tmp.mkdir();mirror=scratch/'mirror';r['scratch']=str(scratch);r['tmp_free_before']=free;r['home_free_before']=home_free
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_'):del env[k]
env['ASSERVAT_INITIAL_INSTALLATION']='1'
pattern='^TestInitialInstallationWithRealServices$/^owner-identity-roles-(constructor-(expired-source|bridge-contention)|observation-(contention(-changed|-expired|-final-(change|renewed|recovery|expired))?|unknown-commit))$'
phases=[('actual-sql',['python3','scripts/test-custody.py','--fleet','--run',pattern],0,0)]
allowed_outputs={'test/results/fleet.log','test/results/fleet-environment.json','test/results/fleet-postgres.log'}
required_tests=set(json.loads((c/'required-tests.json').read_text()))
expected_native=json.loads((c/'expected-native-sources.json').read_text())
def native_sources():
 names={'go.mod','go.sum','sqlc.yaml','scripts/test-custody.py'}
 for folder,suffixes in [('cmd',{'.go'}),('internal',{'.go','.json'}),('migrations',{'.sql','.go'}),('test/fixtures',{'.sql'}),('test/integration',{'.go'})]:
  names.update(p.relative_to(mirror).as_posix() for p in (mirror/folder).rglob('*') if p.is_file() and p.suffix in suffixes)
 return {rel:sha(mirror/rel) for rel in sorted(names)}
code=2;mirror_hashes={};report=None;stop=None
try:
 probe=scratch/'write-probe'
 with probe.open('xb') as f:f.write(bytes(1024**2));f.flush();os.fsync(f.fileno())
 probe.unlink()
 for rel in deps:
  p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for row in manifest:
  p=mirror/row['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/row['path'],p)
 for rel in dirs:(mirror/rel).mkdir(parents=True,exist_ok=True)
 (mirror/'test/results').mkdir(parents=True,exist_ok=True)
 assert all(not (mirror/p).exists() for p in allowed_outputs)
 mirror_hashes={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
 assert native_sources()==expected_native
 assert {p:mirror_hashes[p] for p in expected_native}==expected_native
 with (c/'mirror-manifest.json').open('x') as f:json.dump(mirror_hashes,f,indent=2);f.write('\n')
 for name,cmd,expected,minimum in phases:
  check=verify()
  if any(check.values()):r['phase_preflight']=check;code=2;break
  log=c/'evidence'/(name+'.log');start=time.time();stop=None
  with log.open('x') as f:
   process=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'phase':name,'pid':process.pid,'started':start}),flush=True)
   while process.poll() is None:
    if time.time()-start>600:stop='600-second infrastructure ceiling'
    elif log.stat().st_size>32*1024**2:stop='32MiB output bound'
    elif shutil.disk_usage('/tmp').free<256*1024**2:stop='scratch below 256MiB'
    if stop:
     os.killpg(process.pid,signal.SIGINT)
     try:process.wait(timeout=60)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
     break
    time.sleep(.5)
  output=log.read_text();top=sum(line.startswith('--- PASS:') for line in output.splitlines());named=sum(line.lstrip().startswith('--- PASS:') for line in output.splitlines());required=top>=minimum
  native_dir=c/'evidence/native';native_dir.mkdir()
  for rel in sorted(allowed_outputs):
   if (mirror/rel).is_file():shutil.copyfile(mirror/rel,native_dir/Path(rel).name)
  report=json.loads((native_dir/'fleet-environment.json').read_text())
  native={'source_map_matches_expected':report.get('sourceHashes')==expected_native,'source_map_matches_final_mirror':native_sources()==expected_native,'testExit':report.get('testExit'),'cleanupFailures':report.get('cleanupFailures'),'sourceUnchangedDuringTest':report.get('sourceUnchangedDuringTest'),'source_count':len(report.get('sourceHashes',{})),'passedTestNames':report.get('passedTestNames',[]),'required_present':required_tests.issubset(set(report.get('passedTestNames',[])))}
  required=native['testExit']==0 and native['cleanupFailures']==[] and native['sourceUnchangedDuringTest'] is True and native['required_present'] and native['source_map_matches_expected'] and native['source_map_matches_final_mirror']
  mirror_file_set=sorted({p.relative_to(mirror).as_posix() for p in mirror.rglob('*') if p.is_file() and p.relative_to(mirror).as_posix() not in allowed_outputs} ^ set(mirror_hashes))
  entry={'native':native,'mirror_file_set':mirror_file_set,'name':name,'command':cmd,'exit':process.returncode,'expected_exit':expected,'seconds':time.time()-start,'stop_reason':stop,'log_sha256':sha(log),'hashes':verify(),'required_checks_present':required,'top_level_pass':top,'named_pass':named}
  r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=0 if not stop and process.returncode==expected and required and not any(entry['hashes'].values()) and not mirror_file_set else 124 if stop else process.returncode or 2
  if code:break
except Exception as e:r['runner_error']=repr(e);code=2
finally:
 recovery=c/'evidence/native-recovery'
 if not (c/'evidence/native').exists():
  recovery.mkdir()
  for rel in sorted(allowed_outputs):
   if (mirror/rel).is_file():shutil.copyfile(mirror/rel,recovery/Path(rel).name)
 r['mirror_changed']=[p for p,h in mirror_hashes.items() if sha(mirror/p)!=h]
 r['mirror_file_set']=sorted({p.relative_to(mirror).as_posix() for p in mirror.rglob('*') if p.is_file() and p.relative_to(mirror).as_posix() not in allowed_outputs} ^ set(mirror_hashes))
 cleanup_confirmed=isinstance(report,dict) and report.get('cleanupFailures')==[] and stop is None
 r['cleanup_confirmed']=cleanup_confirmed
 if cleanup_confirmed:shutil.rmtree(scratch)
 else:r['retained_scratch']=str(scratch)
 r.update(exit=code,ended=time.time(),after=verify(),scratch_removed=not scratch.exists())
 with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] and not r['mirror_file_set'] and r['cleanup_confirmed'] else 2)
