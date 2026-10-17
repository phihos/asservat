from pathlib import Path
import json,hashlib,shutil,subprocess,tempfile,os,time
c=Path(__file__).parent;live=Path('/home/phil/Projekte/asservat');h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert h(c/'manifest.json')=='ce9f8b8e499c196ae268dc1a512dc7803e22edfbb456846ee338522e21da0664'
assert h(c/'dependencies.json')=='494e03d3011f21ad979eadc01d147dbc57f46a71320b4f9aaaa2a5bfc83609b4'
m=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'dependency-args.json').read_text());prior=json.loads((c/'prior.json').read_text())
links=json.loads((c/'link-dependencies.json').read_text());directories=json.loads((c/'link-directories.json').read_text())
def verify():
 return {'payloads':[x['path'] for x in m if h(c/'files'/x['path'])!=x['payload_sha256']],'bases':[x['path'] for x in m if h(live/x['path'])!=x['base_sha256']],'dependencies':[p for p,v in deps.items() if h(live/p)!=v],'inventory':sorted(set(subprocess.check_output(['rg','--files',*args],cwd=live,text=True).splitlines())^set(deps)),'links':[p for p,v in links.items() if h(live/p)!=v],'link_directories':[p for p in directories if not (live/p).is_dir()],'prior':[p for p,v in [(prior['manifest_path'],prior['manifest_sha256']),(prior['result_path'],prior['result_sha256'])] if h(Path(p))!=v]}
r={'manifest':h(c/'manifest.json'),'dependencies':h(c/'dependencies.json'),'runner':h(Path(__file__)),'before':verify(),'phases':[],'native':False,'go_jobs':False}
assert not (c/'result.json').exists() and not any(r['before'].values())
assert shutil.disk_usage('/tmp').free>=4*1024**3
tmp=Path(tempfile.mkdtemp(prefix='asservat-selection-schema-6-',dir='/tmp'));r['tmpdir']=str(tmp);code=2
try:
 for rel in dict(deps,**links):
  p=tmp/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
 for rel in directories:(tmp/rel).mkdir(parents=True,exist_ok=True)
 for x in m:
  p=tmp/x['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/x['path'],p)
 mirror={p.relative_to(tmp).as_posix():h(p) for p in tmp.rglob('*') if p.is_file()};(c/'mirror-manifest.json').write_text(json.dumps(mirror,indent=2)+'\n')
 py='/home/phil/.cache/asservat-build/spec-venv/bin/python';env=os.environ.copy();env['ASSERVAT_GATE_MIRROR']=str(tmp)
 for name,cmd in [('schema-regressions',[py,str(c/'schema-regressions.py')]),('contracts',['make','spec-check','architecture-check','design-check','PYTHON='+py])]:
  check=verify();assert not any(check.values()),check
  start=time.time();log=c/'evidence'/(name+'.log')
  with log.open('x') as f:p=subprocess.run(cmd,cwd=tmp,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=180)
  entry={'name':name,'command':cmd,'exit':p.returncode,'seconds':time.time()-start,'log_sha256':h(log),'hashes':verify()};r['phases'].append(entry);print(json.dumps(entry),flush=True)
  code=p.returncode
  if code:break
 r['mirror_changed']=[p for p,v in mirror.items() if h(tmp/p)!=v]
finally:
 shutil.rmtree(tmp);r.update(exit=code,after=verify(),tmpdir_removed=not tmp.exists())
 (c/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r.get('mirror_changed') else 2)
