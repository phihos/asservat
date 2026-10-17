#!/usr/bin/env python3
"""Qualify only after parent allocation and integration of ADR156 value types."""
from pathlib import Path
from urllib.parse import urlsplit, unquote
import hashlib,json,os,re,shutil,signal,subprocess,sys,tempfile,time
ROOT=Path('/home/phil/Projekte/asservat')
STAGE=Path(__file__).resolve().parent
PYTHON='/home/phil/.cache/asservat-build/spec-venv/bin/python'
ARGS=['api','cmd','internal','migrations','test/integration','test/fixtures','scripts','go.mod','go.sum','sqlc.yaml','Makefile','docs','specs','examples','design','charts','README.md','requirements-spec.txt','AGENTS.md','.gitignore','web','-g','!web/node_modules/**']
assert sys.argv[1:]==['--parent-exclusive-slot-allocated']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
def save(p,v):
 with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def names():return sorted(subprocess.check_output(['rg','--files',*ARGS],cwd=ROOT,text=True).splitlines())
def joined(p):
 if p is None:return True
 def exists():
  try:os.killpg(p.pid,0);return True
  except ProcessLookupError:return False
 def send(s):
  try:os.killpg(p.pid,s)
  except ProcessLookupError:pass
 if p.poll() is None:
  send(signal.SIGTERM)
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:send(signal.SIGKILL);p.wait(timeout=10)
 else:p.wait(timeout=1)
 if exists():
  send(signal.SIGKILL);until=time.monotonic()+10
  while exists() and time.monotonic()<until:time.sleep(.05)
 return p.poll() is not None and not exists()
interrupt_signal=None
def interrupt(signum,frame):
 # Do not raise between Popen's actual spawn and assignment of its owned handle.
 global interrupt_signal
 if interrupt_signal is None:interrupt_signal=signum
def check_interrupt():
 if interrupt_signal is not None:raise InterruptedError('qualification signal '+str(interrupt_signal))
signal.signal(signal.SIGINT,interrupt);signal.signal(signal.SIGTERM,interrupt)
assert sha(STAGE/'manifest.json')=='448730dada2bbe492ac5489f4a2e0951267833f1c45abb2762cb890820ddb8ff'
assert (ROOT/'internal/domain/fleet/owner_audit_epoch.go').is_file(), 'ADR156 types are not integrated'
manifest=json.loads((STAGE/'manifest.json').read_text())
for n,v in manifest.items():
 assert sha(ROOT/n)==v['baseSHA256'] and sha(STAGE/'files'/n)==v['sha256'],n
inventory=names();deps={n:sha(ROOT/n) for n in inventory};directories={};queue=[n for n in inventory if n.endswith('.md')];seen=set()
while queue:
 n=queue.pop()
 if n in seen:continue
 seen.add(n)
 for link in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)',(ROOT/n).read_text()):
  u=urlsplit(link.strip('<>').split(' "',1)[0])
  if u.scheme or u.netloc or not u.path:continue
  p=((ROOT/n).parent/unquote(u.path)).resolve();assert p.is_relative_to(ROOT),(n,link);rel=p.relative_to(ROOT).as_posix()
  if p.is_dir():directories[rel]=sorted(c.name for c in p.iterdir())
  else:
   assert p.is_file(),(n,link);deps[rel]=sha(p)
   if rel.endswith('.md'):queue.append(rel)
metadata={n:sha(STAGE/n) for n in ('manifest.json','REVIEW.md','run-component.py')}
out=STAGE/'checks/component-1';out.mkdir(parents=True)
for n,v in [('dependencies.json',deps),('inventory.json',inventory),('linked-directories.json',directories),('metadata.json',metadata)]:save(out/n,v)
shutil.copytree(STAGE/'files',out/'files');shutil.copyfile(STAGE/'manifest.json',out/'manifest.json');shutil.copyfile(__file__,out/'run.py')
def verify():
 return {'deps':[n for n,h in deps.items() if sha(ROOT/n)!=h], 'sets':sorted(set(names())^set(inventory)), 'directories':[n for n,c in directories.items() if not (ROOT/n).is_dir() or sorted(p.name for p in (ROOT/n).iterdir())!=c], 'metadata':[n for n,h in metadata.items() if sha(STAGE/n)!=h], 'payloads':[n for n,v in manifest.items() if sha(STAGE/'files'/n)!=v['sha256'] or sha(ROOT/n)!=v['baseSHA256']]}
assert shutil.disk_usage('/tmp').free>=4*1024**3 and shutil.disk_usage(ROOT).free>=32*1024**3
scratch=Path(tempfile.mkdtemp(prefix='asservat-epoch-codec-',dir='/tmp'));mirror=scratch/'mirror';tmp=scratch/'go-tmp';tmp.mkdir()
report={'native':False,'runtimeSelected':False,'metadata':metadata,'dependencyCount':len(deps),'scratch':str(scratch),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'before':verify(),'phases':[]}
assert not any(report['before'].values())
child=None;code=2;baseline={};validation=None;validation_pending=False
validation_path=mirror/'docs/architecture/validation.json'
def restore_validation(label):
 # Inspect and restore only after every descendant in our owned group is gone.
 if not joined(child):raise RuntimeError('owned group not joined before validation restore')
 generated=validation_path.read_bytes() if validation_path.is_file() else None
 artifact=out/(label+'-validation.json')
 if generated is not None:
  with artifact.open('xb') as f:f.write(generated)
 result={'originalSHA256':hashlib.sha256(validation).hexdigest(),
  'generatedSHA256':hashlib.sha256(generated).hexdigest() if generated is not None else None,
  'generatedArtifact':artifact.name if generated is not None else None,
  'ownedGroupJoinedBeforeRestore':True,'restored':False}
 report.setdefault('validation',{})[label]=result
 validation_path.write_bytes(validation)
 result['restored']=validation_path.read_bytes()==validation
 return generated is not None and result['restored']
try:
 check_interrupt()
 # No child exists during initial mirror creation; keep the write precondition explicit.
 assert joined(child), 'owned group not joined before mirror creation'
 for n in deps:
  check_interrupt()
  p=mirror/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,p)
 for n in manifest:
  check_interrupt()
  p=mirror/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(STAGE/'files'/n,p)
 for n in directories:(mirror/n).mkdir(parents=True,exist_ok=True)
 baseline={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()};save(out/'mirror.json',baseline)
 validation=validation_path.read_bytes()
 with (out/'validation-original.json').open('xb') as f:f.write(validation)
 report['originalValidationSHA256']=hashlib.sha256(validation).hexdigest()
 env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
 package='./internal/adapters/objectstore/framed'
 phases=[('compile',['go','test','-vet=off','-run=^$','-count=1',package,'./test/integration']),('races',['go','test','-json','-race','-vet=off','-count=1','-timeout=6m',package]),('vet',['go','vet',package]),('canonical',['make','spec-check','architecture-check','design-check','go-architecture-check','PYTHON='+PYTHON])]
 required={'TestOwnerEpochCodecExactSnapshotAndPurpose','TestOwnerEpochCodecRejectsMalformedBeforeKeyUse','TestOwnerEpochCodecMaximumConfigurationRemainsBounded','TestOwnerEpochCodecPreservesCancellationAcrossKeyCalls','TestOwnerConfigurationAuditExactPurposeAndSnapshot'}
 for phase,cmd in phases:
  check_interrupt()
  assert not any(verify().values())
  assert joined(child), 'previous owned group not joined before next phase'
  assert {p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}==baseline, 'mirror changed before phase'
  if phase=='canonical':validation_pending=True
  start=time.monotonic();log=out/(phase+'.log');stop=None
  with log.open('x') as f:
   check_interrupt()
   child=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   report['lastOwnedProcess']={'phase':phase,'pid':child.pid}
   print(json.dumps(report['lastOwnedProcess']),flush=True)
   while child.poll() is None:
    if interrupt_signal is not None:stop='qualification signal '+str(interrupt_signal)
    elif time.monotonic()-start>600:stop='600-second infrastructure ceiling'
    elif log.stat().st_size>32*1024**2:stop='32MiB output ceiling'
    elif shutil.disk_usage('/tmp').free<256*1024**2:stop='scratch ceiling'
    if stop:break
    time.sleep(.5)
  group_joined=joined(child)
  assert group_joined, 'owned group not joined before output inspection'
  check_interrupt()
  if phase=='canonical':
   restored=restore_validation('canonical');validation_pending=False
   assert restored, 'canonical validation missing or original bytes not restored'
  actual={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
  passed=[];failed=[];skipped=[];package_pass=False
  for line in log.read_text().splitlines():
   try:e=json.loads(line)
   except json.JSONDecodeError:continue
   if e.get('Action')=='pass' and not e.get('Test'):package_pass=True
   if e.get('Test') and e.get('Action') in ('pass','fail','skip'):{'pass':passed,'fail':failed,'skip':skipped}[e['Action']].append(e['Test'])
  valid=phase!='races' or (required<=set(passed) and not failed and not skipped and package_pass)
  entry={'name':phase,'command':cmd,'exit':child.returncode,'seconds':round(time.monotonic()-start,3),'stopReason':stop,'ownedGroupJoined':group_joined,'requiredChecksPresent':valid,'passedTests':passed,'failedTests':failed,'skippedTests':skipped,'logSHA256':sha(log),'after':verify(),'exactMirrorUnchanged':actual==baseline};report['phases'].append(entry)
  print(json.dumps({k:entry[k] for k in ('name','exit','seconds','ownedGroupJoined','requiredChecksPresent')}),flush=True)
  assert child.returncode==0 and not stop and group_joined and valid and not any(entry['after'].values()) and entry['exactMirrorUnchanged'],phase
 check_interrupt()
 code=0
except BaseException as e:report['error']=repr(e);code=2
finally:
 # Repeated interactive signals must not interrupt joining/restoration/cleanup.
 signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
 report['signalReceived']=interrupt_signal
 if interrupt_signal is not None:code=2
 try:report['ownedGroupJoined']=joined(child)
 except Exception as e:report['ownedGroupJoined']=False;report['joinError']=repr(e)
 if report['ownedGroupJoined'] and validation_pending and validation is not None:
  try:
   if not restore_validation('interrupted'):code=2
  except Exception as e:report['validationRestoreError']=repr(e);code=2
 elif validation_pending:
  report['validationRestoreSkipped']='owned process group did not join';code=2
 actual={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
 report['mirrorChanges']=sorted(n for n in set(actual)|set(baseline) if actual.get(n)!=baseline.get(n));report['after']=verify()
 if not report['ownedGroupJoined'] or report['mirrorChanges'] or any(report['after'].values()):code=2
 report['scratchRemoved']=False
 if report['ownedGroupJoined']:
  try:
   # Reverify the complete owned group immediately before destructive cleanup.
   if not joined(child):raise RuntimeError('owned group not joined before scratch removal')
   shutil.rmtree(scratch);report['scratchRemoved']=not scratch.exists()
  except Exception as e:report['scratchCleanupError']=repr(e);code=2
 report.update(exit=code,scratchRemoved=not scratch.exists());save(out/'result.json',report)
 print(json.dumps({'exit':code,'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
