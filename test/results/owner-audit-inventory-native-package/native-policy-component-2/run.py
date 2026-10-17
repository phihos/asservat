import hashlib,json,os,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
assert sys.argv[1:]==['--parent-slot-allocated']
c=Path(__file__).resolve().parent;r=Path('/home/phil/Projekte/asservat')
assert not (c/'started.json').exists() and not (c/'result.json').exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
m=json.loads((c/'manifest.json').read_text())['files'];d=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'args.json').read_text())
pins={p:sha(c/p) for p in ['manifest.json','dependencies.json','args.json','prior-evidence.json','run.py']}
def check():
 names=set(subprocess.check_output(['rg','--files','-g','!**/node_modules/**',*args],cwd=r,text=True).splitlines())
 return {'pins':[p for p,v in pins.items() if sha(c/p)!=v],'payload':[x['path'] for x in m if sha(c/'files'/x['path'])!=x['payload']],'bases':[x['path'] for x in m if sha(r/x['path'])!=x['base']],'dependencies':[p for p,v in d.items() if sha(r/p)!=v],'inventory':sorted(names^set(d))}
def events(log,action):
 found=[]
 for line in log.read_text().splitlines():
  try:event=json.loads(line)
  except json.JSONDecodeError:continue
  if event.get('Action')==action and event.get('Test'):found.append(event['Test'])
 return found
report={'pins':pins,'native':False,'priorEvidence':json.loads((c/'prior-evidence.json').read_text()),'scope':'Changed native fixture compile/vet and opt-in closure; previous exact production/race evidence retained separately','phases':[],'before':check(),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
assert not any(report['before'].values()),report['before']
assert shutil.disk_usage('/tmp').free>=4*(1<<30)
scratch=Path(tempfile.mkdtemp(prefix='asservat-owner-inventory-native-component-',dir='/tmp'));mirror=scratch/'mirror';tmp=scratch/'tmp';tmp.mkdir()
report['scratch']=str(scratch);(c/'started.json').write_text(json.dumps(report,indent=2)+'\n')
env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
code=1;baseline={};overall=time.monotonic();target=mirror/'internal/adapters/objectstore/owner_audit_inventory.go'
def phase(name,cmd,want=0):
 assert not any(check().values()),check();log=c/(name+'.log');start=time.monotonic()
 with log.open('x') as out:
  child=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
  try:status=child.wait(timeout=max(1,min(180,600-(time.monotonic()-overall))))
  except subprocess.TimeoutExpired:
   os.killpg(child.pid,signal.SIGTERM)
   try:child.wait(timeout=10)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
   status=124
 entry={'name':name,'command':cmd,'exit':status,'seconds':time.monotonic()-start,'logSHA256':sha(log),'hashes':check(),'passedTests':events(log,'pass'),'failedTests':events(log,'fail')};report['phases'].append(entry)
 (c/'progress.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(entry),flush=True)
 assert status==want and not any(entry['hashes'].values()),name
 return entry
try:
 for rel in d:
  dest=mirror/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(r/rel,dest)
 for row in m:
  dest=mirror/row['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/row['path'],dest)
 baseline={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()}
 phase('selectors',['python3','scripts/test-owner-inventory-harness.py'])
 phase('compile',['go','test','-vet=off','-run=^$','-count=1','./internal/adapters/objectstore','./test/integration'])
 trace=phase('constructor-trace-race',['go','test','-json','-race','-count=1','-timeout=30s','-run=^TestOwnerAuditInventoryTraceUsesActualConstructor$','./test/integration'])
 assert trace['passedTests']==['TestOwnerAuditInventoryTraceUsesActualConstructor'],trace
 skipped=phase('native-opt-in-closed',['go','test','-json','-count=1','-timeout=30s','-run=^TestOwnerAuditInventoryWithRealServices$','./test/integration'])
 assert 'TestOwnerAuditInventoryWithRealServices' in events(c/'native-opt-in-closed.log','skip') and not skipped['passedTests'],skipped
 phase('vet',['go','vet','./internal/adapters/objectstore','./test/integration'])
 phase('go-architecture',['make','go-architecture-check'])
 code=0
except Exception as error:report['error']=repr(error)
finally:
 after={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()};report['mirrorChanges']=sorted(p for p in baseline.keys()|after.keys() if baseline.get(p)!=after.get(p)) if baseline else []
 report['after']=check()
 if report['mirrorChanges'] or any(report['after'].values()):code=2
 shutil.rmtree(scratch);report.update(exit=code,scratchRemoved=not scratch.exists());(c/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'exit':code,'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
