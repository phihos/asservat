import hashlib,json,os,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
c=Path(__file__).resolve().parent;r=Path('/home/phil/Projekte/asservat')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sys.argv[1:]==['--parent-slot-allocated']
assert not (c/'result.json').exists() and not (c/'started.json').exists()
m=json.loads((c/'manifest.json').read_text());d=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'args.json').read_text())
pins={p:sha(c/p) for p in ['manifest.json','dependencies.json','args.json','run.py']}
def check():
 names=set(subprocess.check_output(['rg','--files','-g','!**/node_modules/**',*args],cwd=r,text=True).splitlines())
 return {'pins':[p for p,v in pins.items() if sha(c/p)!=v],'payload':[x['path'] for x in m if sha(c/'files'/x['path'])!=x['payload']],'bases':[x['path'] for x in m if sha(r/x['path'])!=x['base']],'dependencies':[p for p,v in d.items() if sha(r/p)!=v],'inventory':sorted(names^set(d))}
report={'pins':pins,'native':False,'phases':[],'before':check(),'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
assert not any(report['before'].values()),report['before']
assert shutil.disk_usage('/tmp').free >= 4*(1<<30)
scratch=Path(tempfile.mkdtemp(prefix='asservat-retention-backfill-',dir='/tmp'));mirror=scratch/'mirror';tmp=scratch/'tmp';tmp.mkdir()
report['scratch']=str(scratch);(c/'started.json').write_text(json.dumps(report,indent=2)+'\n')
env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
code=1;baseline={}
try:
 for rel in d:
  target=mirror/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(r/rel,target)
 for item in m:shutil.copyfile(c/'files'/item['path'],mirror/item['path'])
 baseline={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()}
 for name,cmd in [('compile',['go','test','-vet=off','-run=^$','-count=1','./test/integration']),('vet',['go','vet','./test/integration'])]:
  assert not any(check().values()),check();log=c/(name+'.log');start=time.monotonic()
  with log.open('x') as out:
   child=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
   try:status=child.wait(timeout=180)
   except subprocess.TimeoutExpired:
    os.killpg(child.pid,signal.SIGTERM)
    try:child.wait(timeout=10)
    except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
    status=124
  entry={'name':name,'command':cmd,'exit':status,'seconds':time.monotonic()-start,'logSHA256':sha(log),'hashes':check()};report['phases'].append(entry);print(json.dumps(entry),flush=True)
  assert status==0 and not any(entry['hashes'].values()),name
 code=0
except Exception as error:report['error']=repr(error)
finally:
 after={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()};report['mirrorChanges']=sorted(p for p in baseline.keys()|after.keys() if baseline.get(p)!=after.get(p)) if baseline else []
 report['after']=check()
 if report['mirrorChanges'] or any(report['after'].values()):code=2
 shutil.rmtree(scratch);report.update(exit=code,scratchRemoved=not scratch.exists());(c/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'exit':code,'scratchRemoved':report['scratchRemoved']}),flush=True)
raise SystemExit(code)
