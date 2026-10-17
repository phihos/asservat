"""Parent-allocated exact native mode; never writes live source."""
import hashlib,json,os,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
assert len(sys.argv)==4 and sys.argv[1]=='--parent-slot-allocated'
c=Path(sys.argv[2]).resolve();out=Path(sys.argv[3]).resolve();repo=Path('/home/phil/Projekte/asservat')
assert c.name=='native-component-1' and out.parent==c.parent and not out.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json')=='7b0ecade4073c62afd3c1a69a8a94170c264857ee55af6df4131474fb762408a'
assert json.loads((c/'result.json').read_text())['exit']==0
manifest=json.loads((c/'manifest.json').read_text())['files'];deps=json.loads((c/'dependencies.json').read_text());args=json.loads((c/'args.json').read_text())
pins={p:sha(c/p) for p in ['manifest.json','dependencies.json','args.json','run.py','result.json']}
def check():
 names=set(subprocess.check_output(['rg','--files','-g','!**/node_modules/**',*args],cwd=repo,text=True).splitlines())
 return {'componentPins':[p for p,v in pins.items() if sha(c/p)!=v],'payload':[r['path'] for r in manifest if sha(c/'files'/r['path'])!=r['payload']],'bases':[r['path'] for r in manifest if sha(repo/r['path'])!=r['base']],'dependencies':[p for p,v in deps.items() if sha(repo/p)!=v],'inventory':sorted(names^set(deps))}
initial=check();assert not any(initial.values()),initial
assert shutil.disk_usage('/tmp').free>=4*(1<<30)
out.mkdir();shutil.copyfile(Path(__file__),out/'run.py')
report={'component':str(c),'componentPins':pins,'runner':sha(out/'run.py'),'before':initial,'phases':[],'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'scope':'read-only scoped physical owner audit inventory; no installed reserve/retirement/refund'}
scratch=Path(tempfile.mkdtemp(prefix='asservat-owner-inventory-native-',dir='/tmp'));mirror=scratch/'mirror';tmp=scratch/'tmp';tmp.mkdir();report['scratch']=str(scratch)
(out/'started.json').write_text(json.dumps(report,indent=2)+'\n')
env={k:v for k,v in os.environ.items() if not k.startswith('ASSERVAT_')};env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
code=1;baseline={};start=time.monotonic()
try:
 for rel in deps:
  dest=mirror/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(repo/rel,dest)
 for row in manifest:
  dest=mirror/row['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(c/'files'/row['path'],dest)
 (mirror/'test/results').mkdir(parents=True,exist_ok=True)
 baseline={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file()}
 cmd=['python3','scripts/test-custody.py','--owner-audit-inventory']
 with (out/'harness.log').open('x') as log:
  child=subprocess.Popen(cmd,cwd=mirror,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  try:status=child.wait(timeout=900)
  except subprocess.TimeoutExpired:
   os.killpg(child.pid,signal.SIGINT)
   try:child.wait(timeout=45)
   except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGTERM);child.wait(timeout=30)
   status=124
 report['phases'].append({'command':cmd,'exit':status,'seconds':time.monotonic()-start,'logSHA256':sha(out/'harness.log')})
 native=mirror/'test/results/owner-audit-inventory-environment.json'
 if native.is_file():report['native']=json.loads(native.read_text())
 n=report.get('native',{})
 name='TestOwnerAuditInventoryWithRealServices';required={name,name+'/inspection-credential-cannot-mutate-or-read-bodies',name+'/expired-original-source-exact-physical-inventory',name+'/inventory-preserves-all-physical-obligations'}
 report['requiredPassNames']=sorted(required);report['missingPassNames']=sorted(required-set(n.get('passedTestNames',[])))
 assert status==0 and n.get('testExit')==0,report['phases']
 assert not report['missingPassNames'],report['missingPassNames']
 assert n.get('sourceHashes') and n.get('sourceUnchangedDuringTest') is True,n
 assert n.get('cleanupFailures')==[],n
 assert n.get('phases') and all(p.get('testExit')==0 and p.get('qualificationExit')==0 for p in n['phases']),n.get('phases')
 code=0
except Exception as error:report['error']=repr(error)
finally:
 results=mirror/'test/results'
 if results.exists():shutil.copytree(results,out/'native-results')
 actual={str(p.relative_to(mirror)):sha(p) for p in mirror.rglob('*') if p.is_file() and not p.is_relative_to(results)}
 report['mirrorChanges']=sorted(p for p in baseline.keys()|actual.keys() if baseline.get(p)!=actual.get(p)) if baseline else []
 report['after']=check()
 if report['mirrorChanges'] or any(report['after'].values()):code=2
 # A joined harness with clean owned teardown is required before deleting its
 # mirror. Failed teardown leaves scratch for parent-owned cleanup diagnosis.
 clean=report.get('native',{}).get('cleanupFailures')==[]
 if clean:shutil.rmtree(scratch)
 report.update(exit=code,scratchRemoved=not scratch.exists(),seconds=time.monotonic()-start)
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'exit':code,'scratchRemoved':report['scratchRemoved'],'error':report.get('error'),'missingPassNames':report.get('missingPassNames'),'nativeTestExit':report.get('native',{}).get('testExit')}),flush=True)
raise SystemExit(code)
