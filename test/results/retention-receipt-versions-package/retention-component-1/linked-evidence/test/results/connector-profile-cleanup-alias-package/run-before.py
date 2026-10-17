import hashlib,json,os,shutil,subprocess,time
from pathlib import Path
r=Path('/home/phil/Projekte/asservat')
s=Path(__file__).parent
out=s/'before'; assert not out.exists(); out.mkdir()
manifest=json.loads((s/'manifest.json').read_text())
def check():
 changed=[]
 for row in manifest:
  p=r/row['path']; a=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
  b=hashlib.sha256((s/'files'/row['path']).read_bytes()).hexdigest()
  if a!=row['base'] or b!=row['payload']:changed.append(row['path'])
 return changed
report={'scope':'Negative branch SQL51 reproduction only; fixture-only definer, original live process/deadlines, no production migration or role expansion','before':check(),'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
assert not report['before']
assert shutil.disk_usage(r).free>=32*(1<<30)
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2 -overlay='+str(s/'overlay.json'))
cmd=['python3','scripts/test-custody.py','--run','^TestContextAdmissionWithRealServices$/^connector-identity-fast$/^live-profile-cleanup-trigger-denies-with-original-row$']
start=time.monotonic();wall=time.time()
with (out/'harness.log').open('w') as log:run=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT)
for p in (r/'test/results').glob('custody*'):
 if p.is_file() and p.stat().st_mtime>=wall:shutil.copyfile(p,out/p.name)
v=json.loads((out/'custody-environment.json').read_text())
log=(out/'custody.log').read_text()
intended='live-profile cleanup must reach its original reference denial, not a SQL compilation failure' in log and 'column reference "a.id" is ambiguous (SQLSTATE 42702)' in log
report.update(command=cmd,exit=run.returncode,seconds=round(time.monotonic()-start,3),intendedFailure=intended,sourceUnchanged=v.get('sourceUnchangedDuringTest'),sourceCount=len(v.get('sourceHashes',{})),cleanupFailures=v.get('cleanupFailures'),after=check())
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2),flush=True)
raise SystemExit(0 if run.returncode and intended and report['sourceUnchanged'] and not report['cleanupFailures'] and not report['after'] else 1)
