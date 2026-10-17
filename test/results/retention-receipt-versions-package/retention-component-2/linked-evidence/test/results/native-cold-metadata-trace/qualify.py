from pathlib import Path
import hashlib,json,os,subprocess,sys,time
root=Path('/home/phil/Projekte/asservat');stage=Path('/home/phil/.cache/asservat-build/planning/native-cold-metadata-trace-20261012')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=[p for dirname in ['api','internal','cmd','test/integration'] for p in (root/dirname).rglob('*') if p.is_file()]+[root/'go.mod',root/'go.sum']
before={str(p.relative_to(root)):sha(p) for p in paths}
(stage/'dependencies.json').write_text(json.dumps(before,indent=2)+'\n')
manifest=json.loads((stage/'manifest.json').read_text())
for r in manifest: assert sha(stage/r['path'])==r['sha256']
env=os.environ.copy();env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR='/home/phil/.cache/asservat-build/tmp')
cmd=['go','test','-overlay',str(stage/'overlay.json'),'-race','./test/integration','-run','^TestNativePreparationTrace','-count=1','-timeout=60s','-v']
start=time.monotonic()
with (stage/'focused.log').open('w') as log: p=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
changed=[name for name,h in before.items() if not (root/name).exists() or sha(root/name)!=h]
for r in manifest:
 if sha(stage/r['path'])!=r['sha256']: changed.append('overlay/'+r['path'])
report={'exit':p.returncode,'seconds':time.monotonic()-start,'dependencies':len(before),'changed':changed}
(stage/'focused-result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
sys.exit(2 if changed else p.returncode)
