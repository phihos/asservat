import hashlib,json,os,shutil,subprocess,tempfile,time
from pathlib import Path
r=Path('/home/phil/Projekte/asservat');s=Path('/home/phil/.cache/asservat-build/planning/audit-create-pinning-20261013');out=s/'checks-1';assert not out.exists();out.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows=json.loads((s/'manifest.json').read_text())
paths=set(json.loads((r/'test/results/initial-owner-integration-1/source-hashes.json').read_text()))
paths.discard('docs/implementation-progress.md')
paths.update(str(p.relative_to(r)) for p in (r/'internal').rglob('*.go'))
before={p:sha(r/p) for p in sorted(paths)};(out/'dependencies.json').write_text(json.dumps(before,indent=2)+'\n')
for x in rows:
 assert (sha(r/x['path']) if (r/x['path']).exists() else None)==x['base'],x['path']
 assert sha(s/'files'/x['path'])==x['payload']
(out/'manifest.json').write_bytes((s/'manifest.json').read_bytes())
for x in rows:
 p=out/'files'/x['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((s/'files'/x['path']).read_bytes())
overlay={str(r/x['path']):str(out/'files'/x['path']) for x in rows}
(out/'overlay.json').write_text(json.dumps({'Replace':overlay},indent=2)+'\n')
original=dict(overlay);del original[str(r/'internal/adapters/objectstore/owner_enrollment.go')];del original[str(r/'internal/adapters/objectstore/download_window.go')]
(out/'before-overlay.json').write_text(json.dumps({'Replace':original},indent=2)+'\n')
assert shutil.disk_usage('/tmp').free>4*1024**3
scratch=Path(tempfile.mkdtemp(prefix='asservat-audit-pinning-',dir='/tmp'))
env=dict(os.environ,GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(scratch))
phases=[('compile',['go','test','-overlay',str(out/'overlay.json'),'-vet=off','-run','^$','./...'],0),('before',['go','test','-overlay',str(out/'before-overlay.json'),'-vet=off','-count=1','-v','-run','^Test(OwnerAuditCreatePreservesAcknowledgedVersion|DownloadWindowReadUsesPositiveVersionAndFindStaysReadOnly)$','./internal/adapters/objectstore'],1),('races',['go','test','-overlay',str(out/'overlay.json'),'-race','-vet=off','-count=1','-timeout=180s','-v','./internal/adapters/objectstore','./internal/adapters/objectstore/framed'],0),('audit-application',['go','test','-overlay',str(out/'overlay.json'),'-race','-vet=off','-count=1','-timeout=180s','-v','./internal/application/audit'],0),('vet',['go','vet','-overlay',str(out/'overlay.json'),'./internal/adapters/objectstore'],0)]
report={'phases':[],'native':False,'sourceCount':len(before),'scratch':str(scratch),'manifest':sha(s/'manifest.json')};code=0
try:
 for name,cmd,expected in phases:
  start=time.monotonic()
  with (out/(name+'.log')).open('w') as log:run=subprocess.run(cmd,cwd=r,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=360)
  changed=[p for p,h in before.items() if sha(r/p)!=h]
  payload_changed=[x['path'] for x in rows if sha(s/'files'/x['path'])!=x['payload'] or sha(out/'files'/x['path'])!=x['payload']]
  content=(out/(name+'.log')).read_text()
  entry={'name':name,'command':cmd,'exit':run.returncode,'expected':expected,'seconds':round(time.monotonic()-start,3),'sourceChanged':changed,'payloadChanged':payload_changed,'topLevelPass':sum(x.startswith('--- PASS:') for x in content.splitlines()),'namedPass':sum(x.lstrip().startswith('--- PASS:') for x in content.splitlines()),'skips':sum('--- SKIP:' in x for x in content.splitlines())}
  if name=='before':entry['intendedMarkers']=all(m in content for m in ['OWNER_PUT_RECEIPT_REPLACED','OWNER_PUT_SUBSTITUTION_ACCEPTED','WINDOW_POSITIVE_VERSION_NOT_SELECTED'])
  report['phases'].append(entry);print(json.dumps(entry),flush=True)
  if run.returncode!=expected or changed or payload_changed or entry.get('intendedMarkers',True)!=True:code=run.returncode or 1;break
except BaseException as exc:
 code=124 if isinstance(exc,subprocess.TimeoutExpired) else 1
 report['runnerError']=type(exc).__name__
 raise
finally:
 shutil.rmtree(scratch)
 report.update(exit=code,scratchRemoved=not scratch.exists(),sourceChanged=[p for p,h in before.items() if sha(r/p)!=h])
 report['files']={f.name:sha(f) for f in out.iterdir() if f.is_file()}
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report),flush=True)
raise SystemExit(code)
