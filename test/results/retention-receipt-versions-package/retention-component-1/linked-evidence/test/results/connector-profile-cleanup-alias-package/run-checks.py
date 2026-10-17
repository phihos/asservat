import hashlib,json,os,shutil,subprocess,tempfile,time
from pathlib import Path
r=Path('/home/phil/Projekte/asservat');out=r/'test/results/connector-profile-cleanup-alias-checks';assert not out.exists();out.mkdir()
scratch=Path(tempfile.mkdtemp(prefix='asservat-connector-alias-',dir='/tmp'))
py='/home/phil/.cache/asservat-build/spec-venv/bin/python'
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(scratch),ASSERVAT_BUILD_TMP=str(scratch),PYTHON=py,SQLC='/home/phil/.cache/asservat-build/bin/sqlc')
phases=[('sql',['make','sql-check']),('schema-races',['go','test','-race','-count=1','-timeout=180s','-run','^TestInitialSchema','./internal/adapters/postgres']),('canonical',['make','spec-check','architecture-check','design-check','go-architecture-check']),('native',['python3','scripts/test-custody.py','--run','^TestContextAdmissionWithRealServices$/^connector-(identity-fast|retirement-prepaid-fast)$'])]
report={'scope':'SQL56 alias-only correction: embedded schema, deterministic SQL generation, canonical gates, real original cleanup-role live-reference denial and existing fast connector retirement; synthetic protected roots, not full lifetime cleanup or installed workflow','phases':[],'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip()};code=0
try:
 for name,cmd in phases:
  assert shutil.disk_usage(r).free>=32*(1<<30)
  start=time.monotonic();wall=time.time()
  with (out/(name+'.log')).open('w') as log:run=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT)
  entry={'name':name,'command':cmd,'exit':run.returncode,'seconds':round(time.monotonic()-start,3)}
  if name=='native':
   dest=out/'native';dest.mkdir()
   for p in (r/'test/results').glob('custody*'):
    if p.is_file() and p.stat().st_mtime>=wall:shutil.copyfile(p,dest/p.name)
   v=json.loads((dest/'custody-environment.json').read_text());entry.update(sourceUnchanged=v.get('sourceUnchangedDuringTest'),sourceCount=len(v.get('sourceHashes',{})),cleanupFailures=v.get('cleanupFailures'),passedTests=v.get('passedTestNames',[]))
   if not entry['sourceUnchanged'] or entry['cleanupFailures'] or not entry['passedTests']:code=1
  report['phases'].append(entry);print(json.dumps({k:v for k,v in entry.items() if k!='passedTests'}),flush=True)
  if run.returncode or code:code=run.returncode or code;break
finally:
 shutil.rmtree(scratch);report.update(exit=code,scratchRemoved=not scratch.exists());(out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(code)
