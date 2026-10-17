#!/usr/bin/env python3
"""Run the complete download-worker mode family once; parent owns the slot."""
from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys, time
ROOT = Path('/home/phil/Projekte/asservat'); CACHE = Path('/home/phil/.cache/asservat-build')
assert len(sys.argv) == 3 and sys.argv[2] == '--parent-exclusive-slot-allocated'
name = sys.argv[1]; assert re.fullmatch(r'[a-z0-9][a-z0-9-]*', name)
MODES = ['download-worker-native-retention-observation', 'download-worker-native-content', 'download-worker-native-content-resume', 'download-worker-native-content-interrupted', 'download-worker-native-control-races', 'download-worker-native-control-admission-race', 'download-worker-native-preparation-race', 'download-worker-native-exchange', 'download-worker-routing-two-clusters', 'download-worker-request-owners', 'download-worker-enrollment-channel', 'download-worker-enrollment-current-request', 'download-worker-enrollment-audit-versions', 'download-worker-enrollment-replay', 'download-worker-enrollment-unaudited', 'download-worker-enrollment-budget', 'download-worker-enrollment-parallel', 'download-worker-enrollment-change-key', 'download-worker-enrollment-roles', 'download-worker-enrollment-audit-reuse', 'download-worker-enrollment-expired-lock', 'download-worker-missing-configuration', 'download-worker-configuration-mutated', 'download-worker-configuration-unaudited-rollout', 'download-worker-configuration-roles', 'download-worker-configuration-audit-reuse', 'download-worker-configuration-fence-order', 'download-worker-configuration-identity-expired', 'download-worker-configuration-rollback', 'download-worker-configuration-suspended', 'download-worker-configuration-fenced', 'download-worker-configuration-lock-expired', 'download-worker-coordinator-recovery', 'download-worker-fresh-audit', 'download-worker-short-runtime', 'download-worker-parallel-claim', 'download-worker-unaudited', 'download-worker-binding-replacement', 'download-worker-capacity-held', 'download-worker-expired-claim', 'download-worker-cancelled-parent']
PATTERN = '^TestContextAdmissionWithRealServices$/^download-worker-'
out = ROOT / 'test/results' / name; out.mkdir()
tmp = CACHE / (name + '-tmp'); tmp.mkdir()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(out / 'runner.py').write_bytes(Path(__file__).read_bytes())
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
for k in list(env):
    if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP': del env[k]
cmd = ['python3', 'scripts/test-custody.py', '--run', PATTERN]
start = time.monotonic()
with (out / 'gate.log').open('x') as log:
    p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
report = {'command': cmd, 'exit': p.returncode, 'seconds': round(time.monotonic() - start, 3), 'requiredPassed': ['TestContextAdmissionWithRealServices/' + m for m in MODES]}
for f in ('custody.log', 'custody-environment.json', 'custody-postgres.log'):
    src = ROOT / 'test/results' / f
    if src.exists() and src.stat().st_mtime > time.time() - report['seconds'] - 60:
        shutil.copyfile(src, out / f)
env_report = json.loads((out / 'custody-environment.json').read_text()) if (out / 'custody-environment.json').exists() else {}
passed = set(env_report.get('passedTestNames', []))
report['missing'] = [t for t in report['requiredPassed'] if t not in passed]
report['cleanupFailures'] = env_report.get('cleanupFailures')
report['sourceUnchangedDuringTest'] = env_report.get('sourceUnchangedDuringTest')
shutil.rmtree(tmp, ignore_errors=True); report['scratchRemoved'] = not tmp.exists()
report['status'] = 'passed' if p.returncode == 0 and not report['missing'] and report['cleanupFailures'] == [] and report['sourceUnchangedDuringTest'] else 'failed'
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
sys.exit(0 if report['status'] == 'passed' else 1)
