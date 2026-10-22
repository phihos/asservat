#!/usr/bin/env python3
"""Run only after the parent grants the coordinated test window."""
from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys, time
root = Path('/home/phil/Projekte/asservat-download-permission-c62e02ac')
archive = Path(__file__).resolve().parent
label, *argv = sys.argv[1:]
if not label or not argv:
    raise SystemExit('label and exact command required')
environment = {'GOMAXPROCS':'2', 'TMPDIR':'/home/phil/.cache/asservat-build/tmp', 'GOTMPDIR':'/home/phil/.cache/asservat-build/tmp', 'GOFLAGS':'-buildvcs=false -p=1'}
env = dict(os.environ, **environment)
def sources():
    paths = subprocess.check_output(['git','ls-files','-co','--exclude-standard','-z'],cwd=root).decode().split('\0')
    return {rel:hashlib.sha256((root/rel).read_bytes()).hexdigest() for rel in sorted(set(paths)) if rel and not rel.startswith('test/results/') and (rel.endswith('.go') or rel in ('go.mod','go.sum')) and (root/rel).is_file()}
before = sources()
(archive/(label+'-source-before.json')).write_text(json.dumps(before,indent=2)+'\n')
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
clock = time.monotonic()
with (archive/(label+'.log')).open('w') as log:
    result = subprocess.run(argv,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
after = sources()
(archive/(label+'-source-after.json')).write_text(json.dumps(after,indent=2)+'\n')
changed = [p for p in sorted(before.keys()|after.keys()) if before.get(p)!=after.get(p)]
receipt = {'label':label,'cwd':str(root),'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'argv':argv,'environment':environment,'startedUTC':started,'exitCode':result.returncode,'elapsedSeconds':round(time.monotonic()-clock,6),'sourceCount':len(before),'changedSources':changed}
(archive/(label+'-result.json')).write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt),flush=True)
raise SystemExit(result.returncode)
