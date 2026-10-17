#!/usr/bin/env python3
# Sole-slot qualification of the reviewed, integrated startup diagnostic payload.
from pathlib import Path
from collections import Counter
import hashlib,importlib.util,json,os,re,signal,subprocess,sys,time
ROOT=Path('/home/phil/Projekte/asservat');CACHE=Path('/home/phil/.cache/asservat-build');STAGE=Path(__file__).parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert len(sys.argv)==3 and sys.argv[2]=='--parent-exclusive-slot-allocated'
name=sys.argv[1];assert re.fullmatch(r'[a-z0-9][a-z0-9-]*',name)
manifest=STAGE/'manifest.json';manifestHash='ecc7d11e15f84a56448fa5e9e825f0187bed8ae08454e54a287c1c71491fdf12'
assert sha(manifest)==manifestHash
payload=json.loads(manifest.read_text())
for path,digest in payload['files'].items():
 assert sha(ROOT/path)==digest and sha(STAGE/'files'/path)==digest,'reviewed payload differs: '+path
helper=CACHE/'planning/owner-qualification-20261013/run.py';helperHash='70b900ee945711b7829c9054bf89a72bba1085904b1f94fade0006747c015d07'
assert sha(helper)==helperHash
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('gate',helper);gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
def freeze():
 state=gate.freeze()
 for folder in ('docs','examples','design','web'):
  state.update({str(p.relative_to(ROOT)):sha(p) for p in (ROOT/folder).rglob('*') if p.is_file() and 'node_modules' not in p.parts and '__pycache__' not in p.parts})
 for path in ('README.md','AGENTS.md','.gitignore'):state[path]=sha(ROOT/path)
 return state
out=ROOT/'test/results'/name;out.mkdir();tmp=CACHE/(name+'-tmp');tmp.mkdir()
before=freeze();runnerHash=sha(Path(__file__))
(out/'sources.json').write_text(json.dumps(before,indent=2)+'\n')
for p,label in [(Path(__file__),'runner.py'),(helper,'freeze-helper.py'),(manifest,'manifest.json'),(STAGE/'review.patch','review.patch')]: (out/label).write_bytes(p.read_bytes())
for path in payload['files']:
 target=out/'payloads'/(path+'.txt');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/path).read_bytes())
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),ASSERVAT_BUILD_TMP=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
 if k.startswith('ASSERVAT_') and k!='ASSERVAT_BUILD_TMP':del env[k]
selections={'race-caller-deadline': ('./internal/adapters/diagnostics',
                          ['TestGoProfileShortCallerCannotStartUnfinishableRecording'])}
steps=[('compile',['go','test','-count=1','-timeout=15m','-run','^$','./...'])]
for label,(pkg,names) in selections.items():
 steps.append((label,['go','test','-race','-count=1','-timeout=15m','-json','-run','^(?:'+'|'.join(names)+')$',pkg]))
steps += [] # Failed regression evidence; full affected gates follow the correction.

def joined(p):
 if p is None:return True
 def exists():
  try:os.killpg(p.pid,0);return True
  except ProcessLookupError:return False
 def send(sig):
  try:os.killpg(p.pid,sig)
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
 global interrupt_signal
 if interrupt_signal is None:interrupt_signal=signum
signal.signal(signal.SIGINT,interrupt);signal.signal(signal.SIGTERM,interrupt)
mirror=ROOT/'docs/architecture/validation.json';mirrorBefore=mirror.read_bytes();mirrorPending=False
report={'runnerSHA256':runnerHash,'manifestSHA256':manifestHash,'helperSHA256':helperHash,'sourceCount':len(before),'reviewedPayloads':payload['files'],'steps':[],'status':'failed','bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
code=1;child=None
try:
 for label,cmd in steps:
  assert interrupt_signal is None,'qualification interrupted'
  assert freeze()==before,'source changed before '+label
  assert sha(Path(__file__))==runnerHash and sha(helper)==helperHash and sha(manifest)==manifestHash,'runner/manifest/helper changed'
  required=set()
  if label in selections:
   pkg,names=selections[label]
   declarations=[]
   for p in (ROOT/pkg).glob('*_test.go'):declarations += re.findall(r'^func ((?:Test|Fuzz|Example)\w+)\(',p.read_text(),re.M)
   assert all(declarations.count(n)==1 for n in names),'test selection declaration differs'
   required={('asservat.local/asservat/'+pkg[2:],n) for n in names}
  assert joined(child),'preceding group not joined'
  if label=='canonical':mirrorPending=True
  started=time.monotonic();stopReason=None
  with (out/(label+'.log')).open('x') as log:
   child=subprocess.Popen(cmd,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   print(json.dumps({'step':label,'pid':child.pid,'processGroup':child.pid}),flush=True)
   while child.poll() is None:
    if interrupt_signal is not None:stopReason='qualification signal '+str(interrupt_signal)
    elif time.monotonic()-started>1020:stopReason='outer component ceiling'
    if stopReason:break
    time.sleep(.1)
   clean=joined(child)
  item={'name':label,'command':cmd,'pid':child.pid,'processGroup':child.pid,'exit':child.returncode,'seconds':round(time.monotonic()-started,3),'processJoined':clean,'processGroupAbsent':clean,'stopReason':stopReason}
  if label=='canonical' and clean:
   (out/'architecture-validation-after.json').write_bytes(mirror.read_bytes());mirror.write_bytes(mirrorBefore);mirrorPending=False;item['generatedMirrorRestored']=True
  if required:
   events=[]
   for line in (out/(label+'.log')).read_text().splitlines():
    try:events.append(json.loads(line))
    except json.JSONDecodeError:continue
   def top(action):return Counter((e.get('Package'),e['Test']) for e in events if e.get('Action')==action and e.get('Test') and '/' not in e['Test'])
   expected=Counter({key:1 for key in required})
   runs=Counter((e.get('Package'),e['Test']) for e in events if e.get('Action')=='run' and e.get('Test'))
   passes=Counter((e.get('Package'),e['Test']) for e in events if e.get('Action')=='pass' and e.get('Test'))
   packagePass={e.get('Package') for e in events if e.get('Action')=='pass' and not e.get('Test')}
   item.update(requiredTests=sorted(required),exactTopLevelRuns=top('run')==expected,exactTopLevelPasses=top('pass')==expected,allRunChildrenPassed=runs==passes,passedNamedTests=sorted('/'.join(k) for k in passes),missingPackagePasses=sorted({p for p,_ in required}-packagePass),failuresOrSkips=[e for e in events if e.get('Action') in ('fail','skip')])
  report['steps'].append(item)
  print(json.dumps({'step':label,'exit':child.returncode,'seconds':item['seconds'],'processGroupAbsent':clean}),flush=True)
  if child.returncode or not clean or stopReason or not item.get('exactTopLevelRuns',True) or not item.get('exactTopLevelPasses',True) or not item.get('allRunChildrenPassed',True) or item.get('missingPackagePasses') or item.get('failuresOrSkips'):break
 else:code=0
except BaseException as e:report['error']=str(e)
finally:
 signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
 report['signalReceived']=interrupt_signal
 if interrupt_signal is not None:code=1
 try:report['finalProcessGroupAbsent']=joined(child)
 except Exception as e:report['finalProcessGroupAbsent']=False;report['joinError']=str(e)
 if not report['finalProcessGroupAbsent']:code=1
 if mirrorPending and report['finalProcessGroupAbsent']:
  try:
   (out/'architecture-validation-after.json').write_bytes(mirror.read_bytes());mirror.write_bytes(mirrorBefore);mirrorPending=False
  except Exception as e:report['mirrorRestoreError']=str(e);code=1
 try:
  report['sourceUnchanged']=freeze()==before
  report['runnerUnchanged']=sha(Path(__file__))==runnerHash and sha(helper)==helperHash and sha(manifest)==manifestHash
  report['payloadsUnchanged']=all(sha(STAGE/'files'/p)==h for p,h in payload['files'].items())
 except Exception as e:report['sourceUnchanged']=False;report['freezeError']=str(e)
 if not report.get('sourceUnchanged') or not report.get('runnerUnchanged') or not report.get('payloadsUnchanged'):code=1
 report['scratchRemoved']=False
 if report['finalProcessGroupAbsent']:
  try:tmp.rmdir();report['scratchRemoved']=True
  except Exception as e:report['scratchCleanupError']=str(e);code=1
 report['status']='passed' if code==0 else 'failed';report['exit']=code
 report['archiveHashes']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file()}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'sourceUnchanged':report.get('sourceUnchanged'),'scratchRemoved':report['scratchRemoved']}),flush=True)
sys.exit(code)
