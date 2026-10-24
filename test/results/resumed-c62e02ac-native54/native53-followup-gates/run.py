import hashlib,json,os,pathlib,subprocess,time,shutil
r=pathlib.Path('/home/phil/Projekte/asservat-simplify-c62e02ac')
o=pathlib.Path('/home/phil/.cache/asservat-build/recovered-c62e02ac/native53-followup-gates');o.mkdir(exist_ok=False)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()
files=[p for p in subprocess.check_output(['git','ls-files','-z'],cwd=r,text=True).split('\0') if p and not p.startswith('test/results/')]
def snap():return {p:hashlib.sha256((r/p).read_bytes()).hexdigest() for p in files if (r/p).is_file()}
before=snap();(o/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
env=dict(os.environ,TMPDIR='/home/phil/.cache/asservat-build/tmp',GOTMPDIR='/home/phil/.cache/asservat-build/tmp',GOMAXPROCS='2',GOFLAGS='-buildvcs=false -p=1')
python='PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'
commands=[('design',['make',python,'spec-check','architecture-check','design-check','go-architecture-check']),('compile',['go','test','-race','-run','^$','./test/integration']),('helm',['make',python,'helm-integration'])]
results=[]
for name,argv in commands:
    started=time.time();print('Starting '+name+' on '+head,flush=True)
    with (o/(name+'.log')).open('w') as f:p=subprocess.run(argv,cwd=r,env=env,stdout=f,stderr=subprocess.STDOUT)
    after=snap();changed=[x for x in set(before)|set(after) if before.get(x)!=after.get(x)]
    result={'name':name,'sourceCommit':head,'command':argv,'exitCode':p.returncode,'elapsedSeconds':round(time.time()-started,3),'changedSources':sorted(changed)}
    results.append(result);(o/'results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(result),flush=True)
    if name=='helm' and (r/'test/results/helm-environment.json').stat().st_mtime>=started:shutil.copy2(r/'test/results/helm-environment.json',o/'helm-environment.json')
    if p.returncode or changed:raise SystemExit(p.returncode or 1)
