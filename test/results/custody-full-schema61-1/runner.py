#!/usr/bin/env python3
"""Run the complete custody real-service suite once; parent owns the slot."""
from pathlib import Path
import json, os, re, shutil, subprocess, sys, time
ROOT = Path('/home/phil/Projekte/asservat'); CACHE = Path('/home/phil/.cache/asservat-build')
assert len(sys.argv) == 3 and sys.argv[2] == '--parent-exclusive-slot-allocated'
name = sys.argv[1]; assert re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
out = ROOT / 'test/results' / name; out.mkdir()
tmp = CACHE / (name + '-tmp'); tmp.mkdir()
(out / 'runner.py').write_bytes(Path(__file__).read_bytes())
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
    if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP': del env[k]
cmd = ['python3', 'scripts/test-custody.py']
start = time.monotonic()
with (out / 'gate.log').open('x') as log:
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
report = {'command': cmd, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3)}
for f in ('custody.log', 'custody-environment.json', 'custody-postgres.log'):
    src = ROOT / 'test/results' / f
    if src.exists() and src.stat().st_mtime > time.time() - report['seconds'] - 60:
        shutil.copyfile(src, out / f)
env_report = json.loads((out / 'custody-environment.json').read_text()) if (out / 'custody-environment.json').exists() else {}
report['passedTopLevel'] = sorted({n.split('/')[0] for n in env_report.get('passedTestNames', [])})
report['passedCount'] = len(env_report.get('passedTestNames', []))
report['cleanupFailures'] = env_report.get('cleanupFailures')
report['sourceUnchangedDuringTest'] = env_report.get('sourceUnchangedDuringTest')
report['testExit'] = env_report.get('testExit')
shutil.rmtree(tmp, ignore_errors=True)
report['status'] = 'passed' if p.returncode == 0 and report['testExit'] == 0 and report['cleanupFailures'] == [] and report['sourceUnchangedDuringTest'] else 'failed'
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report)[:600])
sys.exit(0 if report['status'] == 'passed' else 1)
