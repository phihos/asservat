#!/usr/bin/env python3
"""Run the product hub-federation and connector processes in two owned
clusters once (ADR-169/170); parent owns the slot."""
from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys, time
ROOT = Path('/home/phil/Projekte/asservat'); CACHE = Path('/home/phil/.cache/asservat-build')
assert len(sys.argv) == 3 and sys.argv[2] == '--parent-exclusive-slot-allocated'
name = sys.argv[1]; assert re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
REQUIRED = ['TestFederationRegionalProductWithRealKubernetes']
out = ROOT / 'test/results' / name; out.mkdir()
tmp = CACHE / (name + '-tmp'); tmp.mkdir()
(out / 'runner.py').write_bytes(Path(__file__).read_bytes())
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
    if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP': del env[k]
cmd = ['python3', 'scripts/test-context-storage.py', '--run', '^TestFederationRegionalProductWithRealKubernetes$']
start = time.monotonic()
with (out / 'gate.log').open('x') as log:
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
report = {'command': cmd, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3), 'requiredPassed': REQUIRED,
          'scope': 'ADR-193 step 3f: generation 1 from a product BootstrapIssuer slot, enrolled in-band by the connector over the bootstrap purpose; the hub claims, stages the source under the hub-decided backing, writes and acknowledges the generation-1 audit and activates (00064). Product /asservat hub-federation and connector Pods with product connector grants, real OpenBao PKI/transit/KV, encrypted S3 audit. Fixture-created roles, PKI, owner/fleet trust and the fleet operator authority remain synthetic setup authority; no product installer.'}
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
