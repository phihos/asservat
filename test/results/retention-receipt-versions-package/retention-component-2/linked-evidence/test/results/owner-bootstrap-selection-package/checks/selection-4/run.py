from pathlib import Path
import hashlib,json,subprocess,os,time,signal,tempfile,shutil
c=Path(__file__).parent;live=Path('/home/phil/Projekte/asservat');h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert h(c/'dependencies.json')=='494e03d3011f21ad979eadc01d147dbc57f46a71320b4f9aaaa2a5bfc83609b4'
m=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text());prior=json.loads((c/'prior-evidence.json').read_text());variants=json.loads((c/'variants-manifest.json').read_text())
assert h(c/'manifest.json')=='aecfde0acb4ecef312d3abdad903e225f97dfc7905284a16a7a5a08f67f730d3'
def verify():
 inventory=set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())
 return {'payloads':[x['path'] for x in m if h(c/'files'/x['path'])!=x['payload_sha256']], 'bases':[x['path'] for x in m if h(live/x['path'])!=x['base_sha256']], 'dependencies':[p for p,v in deps.items() if h(live/p)!=v], 'inventory':sorted(inventory^set(deps)), 'prior_evidence':[p for p,v in prior['files'].items() if h(Path(p))!=v], 'variants':[p for p,v in variants.items() if h(c/p)!=v]}
assert not (c/'result.json').exists()
r={'manifest':h(c/'manifest.json'),'dependencies':h(c/'dependencies.json'),'runner':h(Path(__file__)),'started':time.time(),'before':verify(),'phases':[],'native':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'prior_freeze_failure':'/home/phil/.cache/asservat-build/planning/owner-bootstrap-selection-20261013/checks/selection-1/freeze-infrastructure-failure.json'}
if any(r['before'].values()):(c/'preflight-failure.json').write_text(json.dumps(r,indent=2)+'\n');raise SystemExit(2)
free=shutil.disk_usage('/tmp').free
assert free>=4*1024**3, 'less than4GiB free in /tmp'
owned_tmp=Path(tempfile.mkdtemp(prefix='asservat-owner-bootstrap-selection-4-scratch-',dir='/tmp'));mirror=owned_tmp/'mirror';tmp=owned_tmp/'go-tmp';tmp.mkdir()
r['tmpdir']=str(owned_tmp);r['tmpdir_free_before']=free
python='/home/phil/.cache/asservat-build/spec-venv/bin/python'
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp))
for k in list(env):
 if k.startswith('ASSERVAT_'):del env[k]
overlay=str(c/'overlay.json');packages=['./internal/contracts','./internal/adapters/kubernetes','./internal/adapters/postgres','./internal/bootstrap']
phases=[
 ('compile',['go','test','-vet=off','-overlay',overlay,'-run=^$','-count=1',*packages],600,0,live),
 ('before-selection',['go','test','-race','-vet=off','-overlay',str(c/'before-overlay.json'),'-count=1','-timeout=60s','-v','./internal/adapters/kubernetes','-run=^TestOwnerBootstrapProjectionRejectsCallerPermissionRootBeforeClaim$'],600,1,live),
 ('bootstrap-race',['go','test','-race','-vet=off','-overlay',overlay,'-count=1','-timeout=180s','-v','./internal/contracts','./internal/adapters/kubernetes','-run=^TestOwnerBootstrap'],600,0,live),
 ('affected-race',['go','test','-race','-vet=off','-overlay',overlay,'-count=1','-timeout=180s','-v','./internal/adapters/kubernetes','-run=^(TestProviderOwnerProjectionOperation|TestProviderOwnerNativeObjectReaders|TestProviderOwnerAuditRead|TestProviderOwnerInstallation)'],600,0,live),
 ('vet',['go','vet','-overlay',overlay,*packages],600,0,live),
 ('go-architecture',['make','go-architecture-check','PYTHON='+python],600,0,mirror),
 ('schemas',[python,str(c/'schema-regressions.py')],60,0,mirror),
 ('contracts',['make','spec-check','architecture-check','design-check','PYTHON='+python],180,0,mirror)]
code=1
try:
 probe=owned_tmp/'fsync-probe'
 with probe.open('xb') as f:f.write(bytes(1048576));f.flush();os.fsync(f.fileno())
 probe.unlink()
 for rel in deps:
  p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for x in m:
  p=mirror/x['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],p)
 mirror_hashes={p.relative_to(mirror).as_posix():h(p) for p in mirror.rglob('*') if p.is_file()}
 (c/'mirror-manifest.json').write_text(json.dumps(mirror_hashes,indent=2)+'\n')
 for name,cmd,maximum,expected,cwd in phases:
  check=verify()
  if any(check.values()):r['phase_preflight']=check;code=2;break
  started=time.time();timeout=False;log=c/'evidence'/(name+'.log')
  with log.open('x') as f:
   pe=env.copy();pe['ASSERVAT_GATE_MIRROR']=str(mirror)
   p=subprocess.Popen(cmd,cwd=cwd,env=pe,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'phase':name,'pid':p.pid,'started':started}),flush=True)
   try:
    while p.poll() is None:
     if time.time()-started>maximum:raise subprocess.TimeoutExpired(cmd,maximum)
     if log.stat().st_size>32*1024**2 or shutil.disk_usage('/tmp').free<256*1024**2:
      r['resource_stop']='log32MiB or tmpfs256MiB reserve';raise subprocess.TimeoutExpired(cmd,maximum)
     time.sleep(.5)
   except subprocess.TimeoutExpired:
    timeout=True;os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  txt=log.read_text();entry={'name':name,'command':cmd,'exit':p.returncode,'expected_exit':expected,'timed_out':timeout,'seconds':time.time()-started,'log_sha256':h(log),'hashes':verify(),'pass_entries':sum(x.lstrip().startswith('--- PASS:') for x in txt.splitlines())}
  required=json.loads((c/'required-tests.json').read_text()).get(name,[])
  entry['missing_required_passes']=[test for test in required if expected==0 and ('--- PASS: '+test+' (') not in txt]
  if expected==1:entry['intended_assertion']='caller permission root reached original projection claim' in txt and '--- FAIL: TestOwnerBootstrapProjectionRejectsCallerPermissionRootBeforeClaim' in txt and '[build failed]' not in txt
  r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=0 if not timeout and p.returncode==expected and (expected!=1 or entry['intended_assertion']) and not any(entry['hashes'].values()) and not entry['missing_required_passes'] else (124 if timeout else p.returncode or 2)
  if code:break
 r['mirror_changed']=[p for p,v in mirror_hashes.items() if h(mirror/p)!=v]
except Exception as e:
 r['runner_error']=repr(e);code=2;raise
finally:
 shutil.rmtree(owned_tmp)
 r.update(exit=code,ended=time.time(),after=verify(),tmpdir_removed=not owned_tmp.exists())
 with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print(json.dumps(r,indent=2),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r.get('mirror_changed') else 2)
