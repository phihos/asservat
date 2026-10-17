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
maps = {n: json.loads((stage / (n + '.json')).read_text()) for n in ['payload', 'bases', 'dependencies', 'component-dependency', 'freeze']}
names = ['data.go', 'enrollment.go', 'inputs.go', 'main.go', 'metrics.go', 'runtime.go']
helper = ['test/fixtures/observation-native/' + n for n in names]
mirror = None
expected = {**maps['dependencies'], **maps['payload']}
scratch = None
reports, terminal, failure = [], 1, None
evidence = stage / 'evidence'
evidence.mkdir(exist_ok=False)


def write(name, data):
    with (evidence / name).open('x') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')


def files(root):
    return {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}


def live_paths():
    paths = set(subprocess.check_output(['rg', '--files', '-g', '*.go', '-g', 'go.mod', '-g', 'go.sum'], cwd=repo, text=True).splitlines())
    for directory in ['internal', 'api', 'cmd', 'migrations', 'test/fixtures/sql']:
        paths.update(subprocess.check_output(['rg', '--files', directory], cwd=repo, text=True).splitlines())
    paths.update(['Makefile', 'scripts/test-context-storage.py', 'scripts/helm_registry.py'])
    return paths


def check():
    state = {
        'dependencies': [n for n, h in maps['dependencies'].items() if sha(repo / n) != h],
        'bases': [n for n, h in maps['bases'].items() if sha(repo / n) != h],
        'integratedComponent': [n for n, h in maps['component-dependency'].items() if sha(repo / n) != h],
        'frozen': [n for n, h in maps['freeze'].items() if sha(stage / n) != h],
        'sourceFileSet': sorted(files(stage / 'source') ^ set(maps['dependencies'])),
        'payloadFileSet': sorted(files(stage / 'files') ^ set(maps['payload'])),
        'liveFileSet': sorted(live_paths() ^ set(maps['dependencies'])),
    }
    if mirror is not None:
        state['mirror'] = [n for n, h in expected.items() if sha(mirror / n) != h]
        state['mirrorFileSet'] = sorted(files(mirror) ^ set(expected))
    return state


def phase(name, command):
    before = check()
    if any(before.values()):
        write(name + '-preflight.json', before)
        raise RuntimeError('source drift before ' + name)
    start = time.monotonic()
    with (evidence / (name + '.log')).open('x') as log:
        child = subprocess.Popen(command, cwd=mirror, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
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
    after = check()
    report = {'phase': name, 'command': command, 'exit': code, 'seconds': round(time.monotonic() - start, 3), 'before': before, 'after': after}
    reports.append(report)
    write(name + '.json', report)
    print(json.dumps({'phase': name, 'exit': code, 'seconds': report['seconds'], 'unchanged': not any(after.values())}), flush=True)
    if code != 0 or any(after.values()):
        raise RuntimeError('phase failed: ' + name)


try:
    initial = check()
    write('preflight.json', initial)
    if any(initial.values()):
        raise RuntimeError('immutable preflight mismatch')
    free = shutil.disk_usage('/tmp').free
    if free < 4 * 1024**3 or subprocess.check_output(['stat', '-f', '-c', '%T', '/tmp'], text=True).strip() != 'tmpfs':
        raise RuntimeError('owned tmpfs needs at least 4 GiB free')
    scratch = Path(tempfile.mkdtemp(prefix='asservat-connector-native-selection-', dir='/tmp'))
    if scratch.stat().st_uid != os.getuid() or scratch.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('invalid owned scratch')
    write('scratch.json', {'path': str(scratch), 'uid': os.getuid(), 'mode': '0700', 'freeBefore': free})
    mirror = scratch / 'mirror'
    mirror.mkdir()
    for n, h in expected.items():
        source = stage / ('files' if n in maps['payload'] else 'source') / n
        target = mirror / n
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != h:
            raise RuntimeError('mirror copy mismatch: ' + n)
    write('mirror.json', expected)
    env = os.environ.copy()
    env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(scratch), CGO_ENABLED='0', PYTHONDONTWRITEBYTECODE='1')
    for key in list(env):
        if key.startswith('ASSERVAT_') and ('NATIVE' in key or 'FIXTURE' in key):
            del env[key]
    # These are the actual harness file order, build flags and CGO setting.
    # Explicit files are necessary because every helper file has build ignore.
    binary = scratch / 'observation-native'
    phase('helper-build', ['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(binary), *helper])
    write('helper-identity.json', {'sha256': sha(binary), 'bytes': binary.stat().st_size, 'files': {n: expected[n] for n in helper}, 'harness': maps['dependencies']['scripts/test-context-storage.py'], 'CGO_ENABLED': '0', 'runtimeExecuted': False})
    phase('helper-vet', ['go', 'vet', *helper])
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
