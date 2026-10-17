from pathlib import Path
import hashlib,json,os,signal,subprocess,time,tempfile,shutil
repo=Path('/home/phil/Projekte/asservat');stage=Path(__file__).resolve().parent;checkpoint=stage/'checkpoint-v1';changes=stage/'changes-v4'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
manifest=json.loads((stage/'manifest-v4.json').read_text());deps=json.loads((checkpoint/'dependencies.json').read_text());payload={x['path']:x['payload'] for x in manifest};bases={x['path']:x['base'] for x in manifest}
free=shutil.disk_usage('/tmp').free
if free<4*1024**3:raise SystemExit('requires 4 GiB tmpfs free')
out=stage/'checkpoint-v4';out.mkdir(exist_ok=False);scratch=Path(tempfile.mkdtemp(prefix='asservat-initial-versioned-audit-build-',dir='/tmp'))
print(json.dumps({'evidence':str(out),'scratch':str(scratch),'freeBefore':free}),flush=True)
(out/'reboot.json').write_text(json.dumps({'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'interruptedHandle':45687,'priorTerminal':'unknown; handle absent after confirmed reboot','priorTmpEvidence':'lost; no test verdict retained','nonSourceExclusion':'core.4751 is absent from frozen source set; metadata inspected, contents untouched; its timestamp predates this reboot','payloadManifestSHA256':sha(stage/'manifest-v4.json')},indent=2)+'\n')
for name in ['dependencies.json']:shutil.copyfile(checkpoint/name,out/name)
shutil.copyfile(stage/'manifest-v4.json',out/'manifest.json')
before=(changes/'internal/bootstrap/initial_installer_audit.go').read_text();assert before.count('return objectstore.NewVersionedAudit(')==1;(out/'before-audit.go.txt').write_text(before.replace('return objectstore.NewVersionedAudit(','return objectstore.New('))
shutil.copyfile(__file__,out/'runner.py')
files=out/'files';files.mkdir()
for rel in payload:
 p=files/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(changes/rel,p)
replace={str(repo/rel):str(files/rel) for rel in payload};(out/'overlay.json').write_text(json.dumps({'Replace':replace},indent=2)+'\n');replace[str(repo/'internal/bootstrap/initial_installer_audit.go')]=str(out/'before-audit.go.txt');(out/'before-overlay.json').write_text(json.dumps({'Replace':replace},indent=2)+'\n')
mirror=scratch/'mirror';mirror.mkdir()
for rel in deps:
 if rel in payload:continue
 p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(repo/rel,p)
for rel in payload:
 p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(files/rel,p)
(mirror/'test/results').symlink_to(repo/'test/results',target_is_directory=True)
(mirror/'web/node_modules').symlink_to(repo/'web/node_modules',target_is_directory=True)
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(scratch))
for name in list(env):
 if name.startswith('ASSERVAT_') and ('FIXTURE' in name or 'NATIVE' in name):del env[name]
reports=[]
def check():
 actual=set(subprocess.check_output(['rg','--files','-g','!web/node_modules/**','-g','!test/results/**','-g','!core.4751'],cwd=repo,text=True).splitlines())
 return {'dependencies':[k for k,v in deps.items() if sha(repo/k)!=v],'bases':[k for k,v in bases.items() if sha(repo/k)!=v],'payload':[k for k,v in payload.items() if sha(files/k)!=v or sha(changes/k)!=v],'fileSet':sorted(actual^set(deps))}
def phase(name,cmd,expected=0,marker=None):
 before=check()
 if any(before.values()):raise RuntimeError('preflight '+str(before))
 start=time.monotonic()
 with (out/(name+'.log')).open('x') as log:
  p=subprocess.Popen(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);print(json.dumps({'phase':name,'pid':p.pid}),flush=True)
  try:code=p.wait(timeout=900)
  except subprocess.TimeoutExpired:
   os.killpg(p.pid,signal.SIGTERM)
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
   code=124
 after=check();logtext=(out/(name+'.log')).read_text();count=logtext.count(marker) if marker else None
 report={'phase':name,'command':cmd,'exit':code,'expectedExit':expected,'seconds':round(time.monotonic()-start,3),'before':before,'after':after,'markerCount':count,'topLevelPass':sum(x.startswith('--- PASS:') for x in logtext.splitlines()),'namedPass':sum(x.lstrip().startswith('--- PASS:') for x in logtext.splitlines()),'skips':sum('--- SKIP:' in x for x in logtext.splitlines())};reports.append(report);(out/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
 if code!=expected or any(after.values()) or marker and count!=4:raise RuntimeError('phase failed '+name)
status=1
try:
 overlay=['-overlay',str(out/'overlay.json')];packages=['./internal/contracts','./internal/adapters/providerconfig','./internal/adapters/kubernetes','./internal/bootstrap','./test/integration']
 phase('compile',['go','test',*overlay,'-vet=off','-run','^$',*packages])
 phase('before-version-optional',['go','test','-overlay',str(out/'before-overlay.json'),'-vet=off','-count=1','-timeout=120s','-v','-run','^TestInitialInstallerRequiresVersionBeforeAuditReceipt$','./internal/bootstrap'],1,'missing immutable version produced a usable initial receipt')
 phase('race',['go','test',*overlay,'-race','-vet=off','-count=1','-timeout=5m','-v','-run','^TestInitialInstaller','./internal/bootstrap'])
 phase('vet',['go','vet',*overlay,*packages])
 py='/home/phil/.cache/asservat-build/spec-venv/bin/python'
 phase('go-architecture',[py,str(mirror/'scripts/check-go-architecture.py')])
 phase('spec',[py,str(mirror/'scripts/check-specs.py')])
 status=0
except Exception as e:
 print(str(e),flush=True);(out/'failure.txt').write_text(str(e)+'\n')
finally:
 shutil.rmtree(scratch)
 result={'terminal':status,'phases':reports,'finalHashes':check(),'payloads':len(payload),'dependencies':len(deps),'scratchRemoved':not scratch.exists(),'freeAfter':shutil.disk_usage('/tmp').free}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'terminal':status,'evidence':str(out),'scratchRemoved':not scratch.exists(),'resultSHA256':sha(out/'result.json')}),flush=True)
raise SystemExit(status)
