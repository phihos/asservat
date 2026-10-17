from pathlib import Path
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time

from inventory import REPO, authored_paths, sha

stage = Path(__file__).resolve().parent
maps = {name: json.loads((stage / (name + '.json')).read_text()) for name in ('payload', 'before-payload', 'bases', 'dependencies', 'source', 'freeze')}
authored = set(json.loads((stage / 'authored-files.json').read_text()))
directories = json.loads((stage / 'mirror-directories.json').read_text())
mirrors = {}
reports = []
scratch = None
terminal = 1
failure = None
evidence = stage / 'evidence'
# Never overwrite an earlier failure, even when launched from the wrong cwd.
evidence.mkdir(exist_ok=False)


def write(name, value):
    with (evidence / name).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')


def files(path):
    return {str(p.relative_to(path)) for p in path.rglob('*') if p.is_file()}


def check():
    result = {
        'dependencies': [n for n, h in maps['dependencies'].items() if sha(REPO / n) != h],
        'bases': [n for n, h in maps['bases'].items() if sha(REPO / n) != h],
        'authoredFileSet': sorted(authored_paths() ^ authored),
        'frozenFiles': [n for n, h in maps['freeze'].items() if sha(stage / n) != h],
        'payloadFileSet': sorted(files(stage / 'files') ^ set(maps['payload'])),
        'beforeFileSet': sorted(files(stage / 'before') ^ set(maps['before-payload'])),
        'sourceFileSet': sorted(files(stage / 'source') ^ set(maps['source'])),
    }
    for name, (mirror, expected) in mirrors.items():
        result[name + 'Mirror'] = [n for n, h in expected.items() if sha(mirror / n) != h]
        result[name + 'MirrorFileSet'] = sorted(files(mirror) ^ set(expected))
    return result


def selected_tests(mirror, packages, pattern):
    expected = set()
    for package in packages:
        for path in (mirror / package.removeprefix('./')).glob('*_test.go'):
            expected.update(name for name in re.findall(r'^func (Test\w+)\(', path.read_text(), re.M) if re.search(pattern, name))
    if not expected:
        raise RuntimeError('empty expected test selection')
    return expected


def phase(name, command, mirror, expected=None, intentional_before=False, canonical=False):
    before = check()
    if any(before.values()):
        write(name + '-preflight.json', before)
        raise RuntimeError('source drift before ' + name)
    start = time.monotonic()
    # The architecture design gate writes this existing report only in the
    # disposable mirror. Preserve its actual output separately, then restore
    # the exact frozen input before source/file-set verification.
    generated = mirror / 'docs/architecture/validation.json'
    original_report = generated.read_bytes() if canonical and generated.exists() else None
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
    if canonical and generated.exists():
        shutil.copyfile(generated, evidence / (name + '-validation.json'))
        if original_report is None:
            generated.unlink()
        else:
            generated.write_bytes(original_report)
    after = check()
    output = (evidence / (name + '.log')).read_text()
    passed = set(re.findall(r'^--- PASS: (\w+)', output, re.M))
    failed = set(re.findall(r'^--- FAIL: (\w+)', output, re.M))
    skips = re.findall(r'^\s*--- SKIP: (\S+)', output, re.M)
    semantic = {'expectedTests': sorted(expected or []), 'passedTop': sorted(passed), 'failedTop': sorted(failed), 'skips': skips}
    if intentional_before:
        # Require the useful failure, not a setup error, compile error, killed
        # process, race report, or an unrelated failure under the same prefix.
        phases = re.findall(r'legacy-native ordinal=(\d+) elapsed=(\S+) remaining=(\S+) observer=(\d+) probe=(\d+) failed=(true|false)', output)
        admitted = re.search(r'legacy-effects prepared=1 intent=1 stored=\d+ outcome=\d+ accepted=0 elapsed=(\S+)', output) is not None
        marker = 'BEFORE-NESTED-NATIVE-BOUND:' in output
        exact = code == 1 and failed == {'TestConnectorLifecycleEnrollmentWithinOriginalBound'} and not passed and not skips
        intended = exact and marker and admitted and len(phases) >= 2 and phases[0][3:] == ('54', '12', 'false') and phases[-1][-1] == 'true' and 'DATA RACE' not in output and 'panic:' not in output
        semantic.update(intentionalFailure=intended, admittedBeforeFailure=admitted, markerPresent=marker, nativePhases=phases)
        accepted = intended
    else:
        accepted = code == 0 and not skips and (expected is None or passed == expected) and not failed
    report = {'phase': name, 'command': command, 'exit': code, 'accepted': accepted, 'seconds': round(time.monotonic() - start, 3), 'before': before, 'after': after, 'namedPass': len(re.findall(r'^\s*--- PASS:', output, re.M)), **semantic}
    write(name + '.json', report)
    reports.append(report)
    print(json.dumps({'phase': name, 'exit': code, 'accepted': accepted, 'seconds': report['seconds'], 'topPass': len(passed), 'namedPass': report['namedPass'], 'unchanged': not any(after.values())}), flush=True)
    if not accepted or any(after.values()):
        raise RuntimeError('phase did not meet exact acceptance: ' + name)


try:
    initial = check()
    write('preflight.json', initial)
    if any(initial.values()):
        raise RuntimeError('immutable source preflight mismatch')
    free = shutil.disk_usage('/tmp').free
    if free < 4 * 1024**3 or subprocess.check_output(['stat', '-f', '-c', '%T', '/tmp'], text=True).strip() != 'tmpfs':
        raise RuntimeError('owned tmpfs scratch requires at least 4 GiB free')
    scratch = Path(tempfile.mkdtemp(prefix='asservat-connector-lifecycle-', dir='/tmp'))
    if scratch.stat().st_uid != os.getuid() or scratch.stat().st_mode & 0o777 != 0o700:
        raise RuntimeError('invalid owned scratch')
    write('scratch.json', {'path': str(scratch), 'uid': os.getuid(), 'mode': '0700', 'freeBefore': free})
    env = os.environ.copy()
    env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(scratch), PYTHONDONTWRITEBYTECODE='1')
    for key in list(env):
        if key.startswith('ASSERVAT_') and ('NATIVE' in key or 'FIXTURE' in key):
            del env[key]
    for name, override, source_dir in [('before', maps['before-payload'], 'before'), ('after', maps['payload'], 'files')]:
        mirror = scratch / name
        mirror.mkdir()
        expected = {**maps['source'], **override}
        for n, h in expected.items():
            source = stage / source_dir / n if n in override else stage / 'source' / n
            if sha(source) != h:
                raise RuntimeError('frozen mirror input mismatch: ' + n)
            target = mirror / n
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        for directory in directories:
            (mirror / directory).mkdir(parents=True, exist_ok=True)
        mirrors[name] = (mirror, expected)
        write(name + '-mirror.json', expected)
    old, new = mirrors['before'][0], mirrors['after'][0]
    binary = scratch / 'before-kubernetes.test'
    phase('before-compile', ['go', 'test', '-race', '-c', '-vet=off', '-o', str(binary), './internal/adapters/kubernetes'], old)
    phase('before-standalone', [str(binary), '-test.run=^TestConnectorLifecycleLegacyStandaloneNativeCounts$', '-test.v', '-test.timeout=20s'], old, {'TestConnectorLifecycleLegacyStandaloneNativeCounts'})
    phase('before-nested-bound', [str(binary), '-test.run=^TestConnectorLifecycleEnrollmentWithinOriginalBound$', '-test.v', '-test.timeout=20s'], old, intentional_before=True)
    phase('after-whole-compile', ['go', 'test', '-race', '-count=1', '-run=^$', '-vet=off', './...'], new)
    kube = '^TestConnector(Lifecycle|ProcessProofBeforeReadinessAndCurrentProtection|IdentitySnapshotIsClosedPinnedAndNotAuthority|BackingOnlyEditPreservesBehavioralProcessIdentity|RetirementProofPreservesLiveActorAndPurpose|ObservationOperation)'
    phase('after-native-component-races', ['go', 'test', '-race', '-count=1', '-timeout=240s', '-vet=off', '-run=' + kube, '-v', './internal/adapters/kubernetes'], new, selected_tests(new, ['./internal/adapters/kubernetes'], kube))
    packages = ['./internal/application/fleet', './internal/domain/fleet']
    phase('after-effects-legacy-races', ['go', 'test', '-race', '-count=1', '-timeout=180s', '-vet=off', '-run=^TestConnector', '-v', *packages], new, selected_tests(new, packages, '^TestConnector'))
    phase('affected-vet', ['go', 'vet', './internal/domain/fleet', './internal/application/fleet', './internal/adapters/kubernetes', './internal/bootstrap'], new)
    python = '/home/phil/.cache/asservat-build/spec-venv/bin/python'
    phase('canonical', ['make', 'PYTHON=' + python, 'go-architecture-check', 'spec-check', 'architecture-check', 'design-check'], new, canonical=True)
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
    result = {'terminal': terminal, 'failure': failure, 'phases': reports, 'finalHashes': final, 'cleanup': cleanup, 'nativeQualification': False, 'installedSelection': False}
    write('RESULT.json', result)
    write('evidence-hashes.json', {str(p.relative_to(evidence)): sha(p) for p in sorted(evidence.rglob('*')) if p.is_file()})
    print(json.dumps({'terminal': terminal, 'failure': failure, 'phases': len(reports), 'unchanged': not any(final.values()), 'cleanup': cleanup}), flush=True)
raise SystemExit(terminal)
