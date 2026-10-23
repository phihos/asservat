import hashlib,json,os,pathlib,subprocess,sys,time
repo=pathlib.Path('/home/phil/Projekte/asservat-simplify-c62e02ac')
base=pathlib.Path('/home/phil/.cache/asservat-build/recovered-c62e02ac')
kind=sys.argv[1]
commands={
 'design':['make','PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python','spec-check','architecture-check','design-check','go-architecture-check'],
 'sql':['python3','scripts/test-custody.py','--run','^TestContextAdmissionWithRealServices$/^(api-execution-(preparation-boundaries|retained-check-revoked-during-permission-lock|one-preparation-exact-result-historical-publication)|download-worker-installed-original-authority)$']}
cmd=commands[kind]
out=base/('capture-phase-combined-'+kind);out.mkdir(exist_ok=False)
changes=subprocess.check_output(['git','status','--porcelain','-z'],cwd=repo).decode().split('\0')
if any(x and not x[3:].startswith('test/results/') for x in changes):raise SystemExit('Non-result changes prevent source freeze')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
files=[x for x in subprocess.check_output(['git','ls-files','-z'],cwd=repo).decode().split('\0') if x and not x.startswith('test/results/')]
def snapshot():return {x:hashlib.sha256((repo/x).read_bytes()).hexdigest() for x in files if (repo/x).is_file()}
before=snapshot();(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
env=dict(os.environ,TMPDIR='/home/phil/.cache/asservat-build/tmp',GOTMPDIR='/home/phil/.cache/asservat-build/tmp',GOMAXPROCS='2',GOFLAGS='-buildvcs=false -p=1')
start=time.time();record={'commit':head,'argv':cmd,'startedUnix':start}
(out/'invocation.json').write_text(json.dumps(record,indent=2)+'\n')
print('Running '+kind+' gates on '+head,flush=True)
with (out/'gate.log').open('w') as log:result=subprocess.run(cmd,cwd=repo,env=env,stdout=log,stderr=subprocess.STDOUT)
after=snapshot();record.update(exitCode=result.returncode,elapsedSeconds=round(time.time()-start,3),sourceCount=len(before),changedSources=sorted(x for x in set(before)|set(after) if before.get(x)!=after.get(x)))
(out/'result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)
if kind=='sql':
 import shutil
 for path in (repo/'test/results').glob('custody*'):
  if path.is_file() and path.stat().st_mtime>=start:shutil.copy2(path,out/path.name)
sys.exit(result.returncode or bool(record['changedSources']))
