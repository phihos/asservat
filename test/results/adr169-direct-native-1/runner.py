#!/usr/bin/env python3
"""Run the two-cluster direct observation fixture once with ADR-169 regional
enrollment (regional Pod holds no hub connector SQL duty); parent owns the slot."""
from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys, time
ROOT = Path('/home/phil/Projekte/asservat'); CACHE = Path('/home/phil/.cache/asservat-build')
assert len(sys.argv) == 3 and sys.argv[2] == '--parent-exclusive-slot-allocated'
name = sys.argv[1]; assert re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
REQUIRED = ['TestDirectHolderObservationWithRealKubernetes'] + ['TestDirectHolderObservationWithRealKubernetes/' + m for m in ('capacity-namespace-candidates', 'capacity-workload-candidates', 'capacity-workload', 'capacity-namespace-guard', 'changed-original-regional-template-denies')]
out = ROOT / 'test/results' / name; out.mkdir()
tmp = CACHE / (name + '-tmp'); tmp.mkdir()
(out / 'runner.py').write_bytes(Path(__file__).read_bytes())
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
    if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP': del env[k]
cmd = ['python3', 'scripts/test-context-storage.py', '--run', '^TestDirectHolderObservationWithRealKubernetes$']
start = time.monotonic()
with (out / 'gate.log').open('x') as log:
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
report = {'command': cmd, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3), 'requiredPassed': REQUIRED,
          'scope': 'ADR-169 delegated regional enrollment: owner Pod hosts the lifecycle channel with real ADR-153 runners, SQL, encrypted audit and the ADR-168 SQL store; regional Pod presents its Secret credential and answers native/source reads. fixtureIssuer and synthetic setup roots remain.'}
for f in ('context-storage.log', 'context-storage-environment.json', 'context-storage-helper-issuer.log', 'context-storage-postgres.log', 'context-storage-fixture-error.log'):
    src = ROOT / 'test/results' / f
    if src.exists() and src.stat().st_mtime > time.time() - report['seconds'] - 60:
        shutil.copyfile(src, out / f)
env_report = json.loads((out / 'context-storage-environment.json').read_text()) if (out / 'context-storage-environment.json').exists() else {}
passed = set(env_report.get('passedTests', []))
report['missing'] = [t for t in REQUIRED if t not in passed]
report['cleanupFailures'] = env_report.get('cleanupFailures')
report['sourceUnchangedDuringTest'] = env_report.get('sourceUnchangedDuringTest')
shutil.rmtree(tmp, ignore_errors=True); report['scratchRemoved'] = not tmp.exists()
report['status'] = 'passed' if p.returncode == 0 and not report['missing'] and report['cleanupFailures'] == [] and report['sourceUnchangedDuringTest'] else 'failed'
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
sys.exit(0 if report['status'] == 'passed' else 1)
