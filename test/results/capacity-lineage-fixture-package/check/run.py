from pathlib import Path
import hashlib,json,os,subprocess,time
root=Path('/home/phil/Projekte/asservat');s=Path('/home/phil/.cache/asservat-build/planning/capacity-native-lineage-20261013');c=s/'candidate-v1';out=s/'checks/fixture-1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='9337806c8e68935f24c3a0245276ef51133876f1b849d349789578bc69f0e62c'
assert sha(c/'dependencies.json')=='b85026aa46057eb596e789a7396e78e4e4fa7eb120eba53fd1b6148c26cdc408'
m=json.loads((c/'manifest.json').read_text());deps=json.loads((c/'dependencies.json').read_text())
def verify():
 v={'payloads':[],'bases':[],'dependencies':[]}
 for e in m['files']:
  if sha(c/'changes'/e['path'])!=e['payload_sha256']:v['payloads'].append(e['path'])
  if sha(root/e['path'])!=e['base_sha256']:v['bases'].append(e['path'])
 for p,h in deps.items():
  if sha(root/p)!=h:v['dependencies'].append(p)
 return v
r={'manifest':sha(c/'manifest.json'),'dependencies':sha(c/'dependencies.json'),'runner_sha256':sha(Path(__file__)),'before':verify(),'started_at':time.time()}
assert not any(r['before'].values()),r['before']
env=os.environ.copy();env.update({'GOMAXPROCS':'2','GOFLAGS':'-p=2','TMPDIR':str(out/'tmp')});env.pop('ASSERVAT_CUSTODY_FIXTURES',None)
cmd=['go','test','-race','-vet=off','-overlay',str(c/'overlay.json'),'./test/integration','-run','^TestCapacityNativeProcessingLineageDates$','-count=1','-v']
with (out/'compile.log').open('x') as log:p=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
(out/'compile.exit').write_text(str(p.returncode)+'\n');r.update({'command':cmd,'exit':p.returncode,'log_sha256':sha(out/'compile.log'),'ended_at':time.time(),'after':verify()})
r['terminal_exit']=p.returncode if p.returncode else (2 if any(r['after'].values()) else 0)
with (out/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
print(json.dumps(r,indent=2));raise SystemExit(r['terminal_exit'])
