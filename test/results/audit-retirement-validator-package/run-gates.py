from pathlib import Path
import hashlib,json,os,signal,subprocess,tempfile,time,shutil,importlib.util
ROOT=Path('/home/phil/Projekte/asservat')
HELPER=Path('/home/phil/.cache/asservat-build/planning/owner-selection-diagnostics-20261013/run-component.py')
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()=='4f56f60dcdf005fdae5c2a34217633c260e0505c433a1aa3fdd4484b5485e519'
spec=importlib.util.spec_from_file_location('asservat_qualified_gate_helper',HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
OUT=ROOT/'test/results/audit-retirement-validator-component-1';OUT.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
save=lambda n,v:(OUT/n).write_text(json.dumps(v,indent=2)+'\n')
files=helper.inventory();source={n:sha(ROOT/n) for n in files};save('sources.json',source)
child=None;tmp=None;interrupted=None;code=1;report={'native':False,'phases':[],'sourceCount':len(source)}
original=(ROOT/'docs/architecture/validation.json').read_bytes();(OUT/'validation-original.json').write_bytes(original)
def signal_seen(signum,frame):
 global interrupted
 if interrupted is None:interrupted=signum
def verify():
 return {'changed':[n for n,h in source.items() if not (ROOT/n).is_file() or sha(ROOT/n)!=h],'fileSet':sorted(set(helper.inventory())^set(files))}
try:
 signal.signal(signal.SIGINT,signal_seen);signal.signal(signal.SIGTERM,signal_seen)
 tmp=Path(tempfile.mkdtemp(prefix='audit-retirement-validator-gates-',dir='/home/phil/.cache/asservat-build'))
 report['scratch']=str(tmp)
 env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
 phases=[('compile',['go','test','-vet=off','-count=1','-run=^$','./test/integration']),('postgres-races',['go','test','-race','-count=1','-timeout=5m','-v','./internal/adapters/postgres','./migrations']),('vet',['go','vet','./internal/adapters/postgres','./test/integration']),('canonical',['make','sql-check','spec-check','architecture-check','design-check','go-architecture-check','ASSERVAT_BUILD_TMP='+str(tmp),'PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'])]
 for name,command in phases:
  assert interrupted is None
  assert not any(verify().values())
  started=time.monotonic();log=OUT/(name+'.log')
  with log.open('x') as stream:
   child=subprocess.Popen(command,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
   report['lastOwnedProcess']={'phase':name,'pid':child.pid};print(json.dumps(report['lastOwnedProcess']),flush=True)
   while child.poll() is None:
    if interrupted is not None or time.monotonic()-started>420 or log.stat().st_size>32*1024**2:break
    time.sleep(.5)
  joined=helper.join_owned(child);assert joined
  if name=='canonical':
   generated=(ROOT/'docs/architecture/validation.json').read_bytes();(OUT/'validation-generated.json').write_bytes(generated)
   report['generatedValidationSHA256']=hashlib.sha256(generated).hexdigest()
   (ROOT/'docs/architecture/validation.json').write_bytes(original)
  phase={'name':name,'command':command,'exit':child.returncode,'seconds':round(time.monotonic()-started,3),'logSHA256':sha(log),'joined':joined,'after':verify()};report['phases'].append(phase);print(json.dumps(phase),flush=True)
  assert child.returncode==0 and interrupted is None and not any(phase['after'].values())
 code=0
except BaseException as exc:report['error']=repr(exc)
finally:
 signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
 report['joined']=helper.join_owned(child)
 if not report['joined']:code=1
 if report['joined']:
  path=ROOT/'docs/architecture/validation.json'
  if path.read_bytes()!=original:
   (OUT/'validation-interrupted.json').write_bytes(path.read_bytes());path.write_bytes(original)
  report['validationRestored']=path.read_bytes()==original
  if tmp is not None:shutil.rmtree(tmp)
 report['scratchRemoved']=tmp is None or not tmp.exists();report['after']=verify()
 if not report['scratchRemoved'] or any(report['after'].values()) or interrupted is not None:code=1
 report['exit']=code;save('result.json',report);print(json.dumps({'exit':code,'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
