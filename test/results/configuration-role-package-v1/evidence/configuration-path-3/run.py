from pathlib import Path
import hashlib,json,os,subprocess,sys,time
root=Path('/home/phil/Projekte/asservat')
here=Path(__file__).parent
h=lambda b:hashlib.sha256(b).hexdigest()
manifest=json.loads((here/'manifest.json').read_text())
for r in manifest:
    p=root/r['path'];actual=h(p.read_bytes()) if p.exists() else None
    assert actual==r['base'],r['path']
    assert h((here/'source'/r['path']).read_bytes())==r['sha256'],r['path']
payloads={r['path'] for r in manifest}
deps={str(p.relative_to(root)):h(p.read_bytes()) for base in ['internal','test','cmd','migrations'] for p in (root/base).rglob('*') if p.is_file() and p.suffix in ('.go','.sql','.json') and str(p.relative_to(root)) not in payloads}
for rel in ['go.mod','go.sum']:
    deps[rel]=h((root/rel).read_bytes())
(here/'dependencies.json').write_text(json.dumps(deps,indent=2,sort_keys=True)+'\n')
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR='/home/phil/.cache/asservat-build/tmp')
packages=['./internal/contracts','./internal/adapters/kubernetes','./internal/adapters/postgres','./internal/application/audit','./internal/bootstrap','./test/integration']
commands=[('compile',['go','test','-overlay='+str(here/'overlay.json'),'-run','^$','-vet=off']+packages),('race',['go','test','-overlay='+str(here/'overlay.json'),'-race','-count=1','-v','-timeout=180s','-run','^TestConfigurationRole(Source|Root|Operation)','./internal/adapters/kubernetes']),('vet',['go','vet','-overlay='+str(here/'overlay.json')]+packages[:-1])]
result={'manifest_sha256':h((here/'manifest.json').read_bytes()),'dependencies_sha256':h((here/'dependencies.json').read_bytes()),'commands':[]}
exitcode=0
for name,command in commands:
    start=time.monotonic()
    with (here/(name+'.log')).open('w') as out:
        code=subprocess.run(command,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT).returncode
    entry={'phase':name,'command':command,'exit':code,'seconds':time.monotonic()-start}
    result['commands'].append(entry)
    print(json.dumps(entry),flush=True)
    if code:exitcode=1
    if name=='compile' and code:break
changes=[]
for r in manifest:
    p=root/r['path'];actual=h(p.read_bytes()) if p.exists() else None
    if actual!=r['base'] or h((here/'source'/r['path']).read_bytes())!=r['sha256']:changes.append(r['path'])
for rel,digest in deps.items():
    if not (root/rel).is_file() or h((root/rel).read_bytes())!=digest:changes.append(rel)
result.update(terminal_exit=exitcode,source_changes=changes,checked_payloads=len(manifest),checked_dependencies=len(deps))
(here/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'terminal_exit':exitcode,'source_changes':changes,'dependencies_sha256':result['dependencies_sha256']}),flush=True)
sys.exit(exitcode if not changes else 2)
