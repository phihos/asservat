#!/usr/bin/env python3
"""One finite, sequential component job; never starts external services."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

C = Path(__file__).resolve().parent
LIVE = Path('/home/phil/Projekte/asservat')
SQLC = Path('/home/phil/.cache/asservat-build/bin/sqlc')
PYTHON = '/home/phil/.cache/asservat-build/spec-venv/bin/python'
EXPECTED_SOURCE = '97935ac3540376ab0d0e349c00623ebcb1d182c0fa6cef657ee4628d23f834ee'
GENERATED = 'internal/adapters/postgres/custodydb/retention_sources.sql.go'
PACKAGES = ['./internal/domain/audit', './internal/application/configuration',
            './internal/application/privacy', './internal/adapters/postgres',
            './internal/adapters/objectstore/...', './test/integration']
RACE_PACKAGES = PACKAGES[:5]
REQUIRED = ['TestRetentionCurrentAuditRequiresImmutableVersions',
            'TestRetentionHistoricalReceiptPreservesRestrictiveReplay',
            'TestRetentionReconcilerRequiresInitialValuesAndStableGuard',
            'TestRetentionReconcilerResumesDurableExpiredCursorWithoutReplacingHistory',
            'TestAcceptedRetentionRequiresCompleteCurrentGuardedSources',
            'TestRetentionReaderCannotFreshenAfterIO',
            'TestRetentionAcceptanceEncryptedExactPurposeAndHistory']
PURPOSES = ['checkpoint', 'lifecycle']
BEFORE_TEST = 'internal/domain/audit/retention_versions_test.go'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


assert sys.argv[1:] == ['--parent-slot-allocated'], 'explicit parent build allocation required'
assert not (C / 'result.json').exists() and not (C / 'started.json').exists()
pins = json.loads((C / 'checkpoint.json').read_text())
manifest = json.loads((C / 'manifest.json').read_text())
deps = json.loads((C / 'dependencies.json').read_text())
args = json.loads((C / 'dependency-args.json').read_text())
excluded = set(json.loads((C / 'dependency-exclusions.json').read_text()))
auxiliary = json.loads((C / 'linked-evidence.json').read_text())
assert pins['manifest.json'] == EXPECTED_SOURCE
prior_before = json.loads((C / 'prior-before.json').read_text())
prior = Path(prior_before['checkpoint'])
assert json.loads((prior / 'dependencies.json').read_text()) == deps, 'before dependencies changed'
assert sha(C / 'files' / BEFORE_TEST) == sha(prior / 'files' / BEFORE_TEST), 'before test changed'
for path in ['internal/domain/audit/retention_acceptance.go', 'internal/domain/audit/lifecycle.go']:
    assert sha(C / 'bases' / path) == sha(prior / 'bases' / path) == deps[path]
assert prior_before['phase']['before_valid'] and len(prior_before['phase']['intended_assertions']) == 4


def verify():
    inventory = set(subprocess.check_output(
        ['rg', '--files', '-g', '!**/node_modules/**', *args], cwd=LIVE, text=True).splitlines()) - excluded
    return {
        'checkpoint': [name for name, digest in pins.items()
                       if sha(SQLC if name == 'sqlc_binary' else C / name) != digest],
        'payloads': [x['path'] for x in manifest if sha(C / 'files' / x['path']) != x['payload_sha256']],
        'bases': [x['path'] for x in manifest if sha(LIVE / x['path']) != x['base_sha256']],
        'dependencies': [p for p, v in deps.items() if sha(LIVE / p) != v],
        'inventory': sorted(inventory ^ set(deps)),
        'linked_snapshot': [p for p, v in auxiliary.items() if sha(C / 'linked-evidence' / p) != v],
        'prior_before': [p for p, v in prior_before['files'].items() if sha(Path(p)) != v],
    }


result = {'started': time.time(), 'manifest': sha(C / 'manifest.json'),
          'checkpoint': sha(C / 'checkpoint.json'), 'runner': sha(Path(__file__)),
          'native': False, 'before': verify(), 'phases': [],
          'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
          'excluded_live_paths': sorted(excluded), 'reused_before': prior_before}
save(C / 'started.json', result)
assert not any(result['before'].values()), result['before']
free = shutil.disk_usage('/tmp').free
assert free >= 4 * 1024**3, 'less than 4GiB free in /tmp'
scratch = Path(tempfile.mkdtemp(prefix='asservat-retention-receipts-', dir='/tmp'))
mirror = scratch / 'mirror'
tmp = scratch / 'go-tmp'
tmp.mkdir()
env = {k: v for k, v in os.environ.items() if not k.startswith('ASSERVAT_')}
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')
result.update(tmpdir=str(scratch), tmp_free_before=free)
baseline = {}
allowed_generated = {'docs/architecture/validation.json', GENERATED}


def run(name, command, cwd, expected=0):
    check = verify()
    if any(check.values()):
        raise RuntimeError(('preflight changed', name, check))
    started = time.monotonic()
    log = C / 'evidence' / (name + '.log')
    timeout = False
    with log.open('x') as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        print(json.dumps({'phase': name, 'pid': child.pid, 'command': command}), flush=True)
        try:
            while child.poll() is None:
                if time.monotonic() - started > 600 or log.stat().st_size > 32 * 1024**2 or shutil.disk_usage('/tmp').free < 256 * 1024**2:
                    raise subprocess.TimeoutExpired(command, 600)
                time.sleep(.5)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    content = log.read_text()
    entry = {'name': name, 'command': command, 'exit': child.returncode,
             'expected_exit': expected, 'timed_out': timeout,
             'seconds': time.monotonic() - started, 'log_sha256': sha(log),
             'pass_entries': sum(s.lstrip().startswith('--- PASS:') for s in content.splitlines()),
             'top_level_passes': sum(s.startswith('--- PASS:') for s in content.splitlines()),
             'hashes': verify()}
    if name == 'before-version-predicates':
        wanted = ['TestRetentionCurrentAuditRequiresImmutableVersions/' + purpose + '/' + version
                  for purpose in PURPOSES for version in ['empty', 'null']]
        entry['intended_assertions'] = [test for test in wanted if '--- FAIL: ' + test + ' (' in content]
        entry['before_valid'] = (len(entry['intended_assertions']) == 4 and '[build failed]' not in content
                                 and 'current receipt=true want false' in content)
    if name == 'affected-races':
        entry['missing_required_passes'] = [test for test in REQUIRED if '--- PASS: ' + test + ' (' not in content]
    result['phases'].append(entry)
    print(json.dumps(entry), flush=True)
    if (timeout or child.returncode != expected or any(entry['hashes'].values())
            or entry.get('before_valid') is False or entry.get('missing_required_passes')):
        raise RuntimeError(('phase failed', name, child.returncode))
    return content


exit_code = 2
try:
    probe = scratch / 'write-probe'
    with probe.open('xb') as f:
        f.write(bytes(1024**2)); f.flush(); os.fsync(f.fileno())
    probe.unlink()
    for name in deps:
        p = mirror / name
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(LIVE / name, p)
    for name in auxiliary:
        p = mirror / name
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(C / 'linked-evidence' / name, p)
    for item in manifest:
        p = mirror / item['path']
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(C / 'files' / item['path'], p)
    baseline = {p.relative_to(mirror).as_posix(): sha(p) for p in mirror.rglob('*') if p.is_file()}
    save(C / 'mirror-manifest.json', baseline)
    assert run('sqlc-version', [str(SQLC), 'version'], mirror).strip() == 'v1.31.1'
    run('sqlc-generate', [str(SQLC), 'generate'], mirror)
    current_generated = {p.relative_to(mirror).as_posix(): sha(p)
                         for p in (mirror / 'internal/adapters/postgres/custodydb').glob('*.go')}
    original_generated = {p: v for p, v in baseline.items() if p.startswith('internal/adapters/postgres/custodydb/') and p.endswith('.go')}
    changed = sorted(p for p in current_generated.keys() | original_generated.keys()
                     if current_generated.get(p) != original_generated.get(p))
    assert changed == [GENERATED], ('unexpected generation delta', changed)
    destination = C / 'generated' / GENERATED
    destination.parent.mkdir(parents=True)
    shutil.copyfile(mirror / GENERATED, destination)
    original_destination = C / 'bases' / GENERATED
    original_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(LIVE / GENERATED, original_destination)
    assert sha(original_destination) == deps[GENERATED]
    generated_entry = {'path': GENERATED, 'base_sha256': deps[GENERATED], 'payload_sha256': sha(destination)}
    save(C / 'generated-manifest.json', [generated_entry])
    save(C / 'combined-manifest.json', manifest + [generated_entry])
    result['generated_manifest'] = sha(C / 'generated-manifest.json')
    run('compile', ['go', 'test', '-vet=off', '-run=^$', '-count=1', *PACKAGES], mirror)
    run('affected-races', ['go', 'test', '-race', '-vet=off', '-count=1', '-timeout=180s', '-v', *RACE_PACKAGES], mirror)
    run('vet', ['go', 'vet', *PACKAGES], mirror)
    run('sql-and-contracts', ['make', 'sql-check', 'go-architecture-check', 'spec-check',
        'architecture-check', 'design-check', 'PYTHON=' + PYTHON,
        'ASSERVAT_BUILD_TMP=' + str(tmp), 'SQLC=' + str(SQLC)], mirror)
    exit_code = 0
except Exception as error:
    result['runner_error'] = repr(error)
finally:
    result['mirror_unexpected_changes'] = [p for p, v in baseline.items()
                                          if p not in allowed_generated and sha(mirror / p) != v]
    result['mirror_unexpected_additions'] = sorted(p.relative_to(mirror).as_posix()
        for p in mirror.rglob('*') if p.is_file()
        and p.relative_to(mirror).as_posix() not in baseline.keys() | allowed_generated) if baseline else []
    if (mirror / GENERATED).is_file() and (C / 'generated-manifest.json').exists():
        result['generated_stable'] = sha(mirror / GENERATED) == json.loads((C / 'generated-manifest.json').read_text())[0]['payload_sha256']
    result['after'] = verify()
    if any(result['after'].values()) or result['mirror_unexpected_changes'] or result['mirror_unexpected_additions'] or result.get('generated_stable') is False:
        exit_code = 2
    shutil.rmtree(scratch)
    result.update(exit=exit_code, ended=time.time(), tmpdir_removed=not scratch.exists())
    save(C / 'result.json', result)
    print(json.dumps(result), flush=True)
raise SystemExit(exit_code)
