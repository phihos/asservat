#!/usr/bin/env python3
"""Run the initial-installation suite (real PostgreSQL role matrix) once for
the ADR-170 connector duty layout; parent owns the slot."""
from pathlib import Path
import json, os, re, shutil, subprocess, sys, time
ROOT = Path('/home/phil/Projekte/asservat'); CACHE = Path('/home/phil/.cache/asservat-build')
assert len(sys.argv) == 3 and sys.argv[2] == '--parent-exclusive-slot-allocated'
name = sys.argv[1]; assert re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
REQUIRED = ['TestInitialInstallationWithRealServices'] + ['TestInitialInstallationWithRealServices/public-runtime-roles-' + m for m in ('matrix', 'unknown-claim', 'lost-completion', 'held-lock', 'recovery-after-lock')]
out = ROOT / 'test/results' / name; out.mkdir()
tmp = CACHE / (name + '-tmp'); tmp.mkdir()
(out / 'runner.py').write_bytes(Path(__file__).read_bytes())
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
    if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP': del env[k]
cmd = ['python3', 'scripts/test-custody.py', '--initial-installation']
start = time.monotonic()
with (out / 'gate.log').open('x') as log:
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
report = {'command': cmd, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3), 'requiredPassed': REQUIRED}
for f in ('initial-installation.log', 'initial-installation-environment.json', 'initial-installation-postgres.log'):
    src = ROOT / 'test/results' / f
    if src.exists() and src.stat().st_mtime > time.time() - report['seconds'] - 60:
        shutil.copyfile(src, out / f)
envr = json.loads((out / 'initial-installation-environment.json').read_text()) if (out / 'initial-installation-environment.json').exists() else {}
passed = set(envr.get('passedTestNames', envr.get('passedTests', [])))
report['passedCount'] = len(passed)
report['missing'] = [t for t in REQUIRED if t not in passed]
report['cleanupFailures'] = envr.get('cleanupFailures')
report['sourceUnchangedDuringTest'] = envr.get('sourceUnchangedDuringTest')
shutil.rmtree(tmp, ignore_errors=True); report['scratchRemoved'] = not tmp.exists()
report['status'] = 'passed' if p.returncode == 0 and not report['missing'] and report['cleanupFailures'] == [] and report['sourceUnchangedDuringTest'] else 'failed'
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
sys.exit(0 if report['status'] == 'passed' else 1)
