from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import importlib.util,json,os,subprocess,tempfile

script=Path(__file__).resolve().parent/'test-custody.py'
spec=importlib.util.spec_from_file_location('custody_harness',script)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
checks=0

def exercise(slow,elapsed,passed_name,expect,reported_elapsed=None):
 global checks
 with tempfile.TemporaryDirectory(prefix='asservat-harness-contract-') as directory:
  root=Path(directory);(root/'test/results').mkdir(parents=True);(root/'test/fixtures/sql').mkdir(parents=True)
  (root/'test/fixtures/sql/runtime-roles.sql').write_text('-- synthetic harness fixture only\n')
  labels={}; commands=[]; runenv=[]
  def fake_run(args,**kwargs):
   commands.append(args)
   if args[:2]==['docker','create']:
    label=args[args.index('--label')+1].split('=',1)[1];name=args[args.index('--name')+1];network=args[args.index('--network')+1]
    labels[name]=(label,network)
   if args[:2]==['docker','inspect']:
    name=args[2];label,network=labels[name]
    return json.dumps([{'Config':{'Labels':{'asservat.test':label}},'Image':'synthetic-image','Id':'synthetic-id','NetworkSettings':{'Networks':{network:{'IPAddress':'127.0.0.1'}}}}])
   if args[:2]==['docker','exec'] and 'json_build_object' in ' '.join(args):
    return json.dumps({'serverStart':'synthetic-incarnation','databaseOID':123})
   return 'synthetic harness command'
  def fake_subprocess(args,**kwargs):
   if args[:2]==['go','test']:
    runenv.append(kwargs['env']);commands.append(args)
    duration = elapsed if reported_elapsed is None else reported_elapsed
    kwargs['stdout'].write('--- PASS: '+passed_name+' ('+str(duration)+'s)\n')
   return SimpleNamespace(returncode=0,stdout="",stderr="")
  with patch.object(m,'ROOT',root),patch.object(m,'hashes',return_value={'synthetic':'unchanged'}),patch.object(m,'run',side_effect=fake_run),patch.object(m.subprocess,'run',side_effect=fake_subprocess),patch.object(m.urllib.request,'urlopen',return_value=SimpleNamespace(close=lambda:None)),patch.object(m.time,'monotonic',side_effect=[100,100+elapsed]),patch.dict(os.environ,{m.CONNECTOR_RETIREMENT_ENV:'1'}):
   result=m.main(connector_retirement=slow)
  report=json.loads((root/'test/results/custody-environment.json').read_text())
  assert result==expect,(result,report)
  assert report['cleanupFailures']==[]
  assert report['testExit']==expect
  assert report['sourceUnchangedDuringTest']
  assert report['phases'][0]['testElapsedSeconds']==elapsed
  assert report['phases'][0]['qualificationExit']==expect
  assert len(runenv)==1
  if slow:
   assert runenv[0][m.CONNECTOR_RETIREMENT_ENV]=='1'
   assert report['goTestTimeoutSeconds']==2400 and report['harnessTestTimeoutSeconds']==2460
   assert report['testPattern']=='^TestContextAdmissionWithRealServices$/^connector-identity-real-time-retirement$'
  else:
   assert m.CONNECTOR_RETIREMENT_ENV not in runenv[0]
   assert report['goTestTimeoutSeconds']==600 and report['harnessTestTimeoutSeconds']==660
  checks+=1

exercise(True,1860,m.CONNECTOR_RETIREMENT_TEST,0)
exercise(True,1859,m.CONNECTOR_RETIREMENT_TEST,1)
exercise(True,1861,'TestContextAdmissionWithRealServices/connector-identity-fast',1)
exercise(True,1861,'TestContextAdmissionWithRealServices',1)
exercise(True,1861,m.CONNECTOR_RETIREMENT_TEST,1,reported_elapsed=1)
exercise(False,1,'TestCustodyWithRealServices',0)
for flag in ['--fleet','--database-recovery','--initial-installation']:
 p=subprocess.run([os.sys.executable,str(script),'--connector-retirement',flag],capture_output=True,text=True)
 assert p.returncode==2 and 'owns its exact' in p.stderr,p.stderr
 checks+=1
p=subprocess.run([os.sys.executable,str(script),'--connector-retirement','--run','anything'],capture_output=True,text=True)
assert p.returncode==2 and 'owns its exact' in p.stderr,p.stderr
checks+=1
with patch.object(m,'run',side_effect=AssertionError('must reject before Docker')):
 try:m.main(connector_retirement=True,fleet=True)
 except ValueError:checks+=1
 else:raise AssertionError('mixed programmatic modes accepted')
compile(script.read_text(),str(script),'exec')
print(f'PASS: {checks} synthetic harness contract cases; no external fixture or real-time qualification executed')
