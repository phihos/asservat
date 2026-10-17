from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time

stage = Path(__file__).resolve().parent
repo = Path('/home/phil/Projekte/asservat')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
maps = {n: json.loads((stage / (n + '.json')).read_text()) for n in ['payload', 'bases', 'dependencies', 'freeze']}
helper = ['test/fixtures/observation-native/' + n for n in ['data.go', 'enrollment.go', 'inputs.go', 'main.go', 'metrics.go', 'runtime.go']]
test = 'test/fixtures/observation-native/enrollment_test.go'
expected = {**maps['dependencies'], test: maps['payload'][test]}
mirror = scratch = None
reports, terminal, failure = [], 1, None
evidence = stage / 'evidence'
evidence.mkdir(exist_ok=False)


def write(name, value):
    with (evidence / name).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')


def paths(root):
    return {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}


def live_paths():
    found = set(subprocess.check_output(['rg', '--files', '-g', '*.go', '-g', 'go.mod', '-g', 'go.sum'], cwd=repo, text=True).splitlines())
    for directory in ['internal', 'api', 'cmd', 'migrations', 'test/fixtures/sql']:
        found.update(subprocess.check_output(['rg', '--files', directory], cwd=repo, text=True).splitlines())
    found.update(['Makefile', 'scripts/test-context-storage.py', 'scripts/helm_registry.py'])
    return found


def check():
    result = {
        'dependencies': [n for n, h in maps['dependencies'].items() if sha(repo / n) != h],
        'bases': [n for n, h in maps['bases'].items() if sha(repo / n) != h],
        'frozen': [n for n, h in maps['freeze'].items() if sha(stage / n) != h],
        'sourceFileSet': sorted(paths(stage / 'source') ^ set(maps['dependencies'])),
        'payloadFileSet': sorted(paths(stage / 'files') ^ set(maps['payload'])),
        'liveFileSet': sorted(live_paths() ^ set(maps['dependencies'])),
    }
    if mirror is not None:
        result['mirror'] = [n for n, h in expected.items() if sha(mirror / n) != h]
        result['mirrorFileSet'] = sorted(paths(mirror) ^ set(expected))
    return result


def phase(name, command, wanted=0, markers=0, extra_env=None):
    before = check()
    if any(before.values()):
        write(name + '-preflight.json', before)
        raise RuntimeError('source drift before ' + name)
    current_env = {**env, **(extra_env or {})}
    started = time.monotonic()
    logpath = evidence / (name + '.log')
    with logpath.open('x') as log:
        child = subprocess.Popen(command, cwd=mirror, env=current_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        print(json.dumps({'phase': name, 'pid': child.pid, 'command': command}), flush=True)
        try:
            code = child.wait(timeout=600)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            code = 124
    content = logpath.read_text()
    marker_count = content.count('BEFORE-FIXTURE-ISSUER-ORIGINAL-INSTANT:')
    after = check()
    report = {'phase': name, 'command': command, 'exit': code, 'expectedExit': wanted, 'seconds': round(time.monotonic() - started, 3), 'beforeMarkers': marker_count, 'CGO_ENABLED': current_env['CGO_ENABLED'], 'before': before, 'after': after}
    reports.append(report)
    write(name + '.json', report)
    print(json.dumps({'phase': name, 'exit': code, 'seconds': report['seconds'], 'beforeMarkers': marker_count, 'unchanged': not any(after.values())}), flush=True)
    if code != wanted or marker_count != markers or any(after.values()):
        raise RuntimeError('phase failed or wrong reproduction: ' + name)
    if markers and any(s in content for s in ['original permit expired', 'setup failed', 'build failed', '[no test files]']):
        raise RuntimeError('before did not reach intended live-permit denial')


try:
    initial = check()
    write('preflight.json', initial)
    if any(initial.values()):
        raise RuntimeError('preflight mismatch')
    free = shutil.disk_usage('/tmp').free
    if free < 4 * (1 << 30):
        raise RuntimeError('less than four GiB free scratch')
    scratch = Path(tempfile.mkdtemp(prefix='asservat-connector-issuer-time-', dir='/tmp'))
    if scratch.stat().st_uid != os.getuid() or scratch.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('invalid owned scratch')
    write('scratch.json', {'path': str(scratch), 'uid': os.getuid(), 'mode': '0700', 'freeBefore': free})
    mirror = scratch / 'mirror'
    mirror.mkdir()
    for n, h in expected.items():
        source = stage / ('files' if n == test else 'source') / n
        target = mirror / n
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != h:
            raise RuntimeError('mirror copy mismatch: ' + n)
    write('before-mirror.json', expected)
    env = os.environ.copy()
    env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(scratch), CGO_ENABLED='1', PYTHONDONTWRITEBYTECODE='1')
    for key in tuple(env):
        if key.startswith('ASSERVAT_'):
            env.pop(key)
    phase('before-actual-helper', ['go', 'test', '-race', '-count=1', '-timeout=60s', '-vet=off', '-v', '-run=^TestNativeFixtureConnectorIssuerOriginalSigningInstant$', *helper, test], wanted=1, markers=2)
    expected = {**maps['dependencies'], **maps['payload']}
    for n in maps['payload']:
        shutil.copyfile(stage / 'files' / n, mirror / n)
    write('after-mirror.json', expected)
    phase('after-actual-helper-race', ['go', 'test', '-race', '-count=1', '-timeout=60s', '-vet=off', '-v', '-run=^TestNativeFixtureConnectorIssuer', *helper, test])
    binary = scratch / 'observation-native'
    phase('actual-helper-build', ['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(binary), *helper], extra_env={'CGO_ENABLED': '0'})
    write('helper-identity.json', {'sha256': sha(binary), 'bytes': binary.stat().st_size, 'files': {n: expected[n] for n in helper}, 'runtimeExecuted': False})
    phase('integration-compile', ['go', 'test', '-race', '-count=1', '-run=^$', '-vet=off', './test/integration'])
    phase('helper-vet', ['go', 'vet', *helper, test])
    phase('integration-vet', ['go', 'vet', './test/integration'])
    terminal = 0
except BaseException as exc:
    failure = {'type': type(exc).__name__, 'message': str(exc)}
finally:
    final = check()
    if any(final.values()):
        terminal = 1
    cleanup = {'scratchCreated': scratch is not None, 'removed': scratch is None}
    if scratch is not None:
        try:
            shutil.rmtree(scratch)
            cleanup.update(removed=not scratch.exists(), freeAfter=shutil.disk_usage('/tmp').free)
        except BaseException as exc:
            terminal = 1
            cleanup['error'] = type(exc).__name__ + ': ' + str(exc)
    write('scratch-cleanup.json', cleanup)
    write('RESULT.json', {'terminal': terminal, 'failure': failure, 'phases': reports, 'finalHashes': final, 'cleanup': cleanup, 'nativeQualification': False, 'runtimeSelection': False})
    write('evidence-hashes.json', {str(p.relative_to(evidence)): sha(p) for p in sorted(evidence.rglob('*')) if p.is_file()})
    print(json.dumps({'terminal': terminal, 'failure': failure, 'phases': len(reports), 'unchanged': not any(final.values()), 'cleanup': cleanup}), flush=True)
raise SystemExit(terminal)
