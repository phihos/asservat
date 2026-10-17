"""Run only with the parent's exclusive build slot and frozen source closure."""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

assert sys.argv[1:] == ['--parent-slot-allocated']
c = Path(__file__).resolve().parent
repo = Path('/home/phil/Projekte/asservat')
assert not (c / 'started.json').exists() and not (c / 'result.json').exists()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
manifest = json.loads((c / 'manifest.json').read_text())['files']
deps = json.loads((c / 'dependencies.json').read_text())
args = json.loads((c / 'dependency-args.json').read_text())
inventory = set(json.loads((c / 'inventory.json').read_text()))
directories = json.loads((c / 'linked-directories.json').read_text())
freeze = json.loads((c / 'freeze.json').read_text())
metadata = {p: sha(c / p) for p in ['manifest.json', 'dependency-args.json', 'inventory.json',
    'dependencies.json', 'linked-directories.json', 'freeze.json', 'run.py', 'draft-before.go.txt',
    'REVIEW.md', 'SQL-PLAN.md', 'INSTALLED-PATH.md', 'freeze.py']}
assert sha(c / 'dependencies.json') == freeze['dependencies']
assert sha(c / 'run.py') == freeze['runner']
assert sha(c / 'freeze.py') == freeze['freezer']
assert sha(c / 'draft-before.go.txt') == freeze['draftBeforeSHA256']
assert sha(c / 'manifest.json') == freeze['manifest']

def verify():
    current = set(subprocess.check_output(['rg', '--files', *args], cwd=repo, text=True).splitlines())
    return {'metadata': [p for p, h in metadata.items() if sha(c / p) != h],
            'payloads': [x['path'] for x in manifest if sha(c / 'files' / x['path']) != x['payload']],
            'bases': [x['path'] for x in manifest if sha(repo / x['path']) != x['base']],
            'dependencies': [p for p, h in deps.items() if sha(repo / p) != h],
            'inventory': sorted(current ^ inventory),
            'directories': [p for p, v in directories.items() if not (repo / p).is_dir() or sorted(q.name for q in (repo / p).iterdir()) != v]}

def join_owned(process):
    """Join only the process group created by this runner, even after I/O errors."""
    if process is None:
        return True

    def group_exists():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def signal_group(value):
        try:
            os.killpg(process.pid, value)
        except ProcessLookupError:
            pass

    try:
        if process.poll() is None:
            signal_group(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                signal_group(signal.SIGKILL)
                process.wait(timeout=10)
        else:
            process.wait(timeout=1)
        # A joined parent alone is insufficient if descendants survived a signal.
        if group_exists():
            signal_group(signal.SIGKILL)
            until = time.monotonic() + 10
            while group_exists() and time.monotonic() < until:
                time.sleep(.05)
        return process.poll() is not None and not group_exists()
    except (OSError, subprocess.TimeoutExpired):
        return False


def test_events(path, action):
    names = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get('Action') == action and value.get('Test'):
            names.append(value['Test'])
    return names

report = {'native': False, 'runtimeSelected': False, 'freeze': freeze, 'metadata': metadata,
          'before': verify(), 'phases': [], 'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
assert not any(report['before'].values()), report['before']
assert shutil.disk_usage('/tmp').free >= 4 * 1024**3
scratch = Path(tempfile.mkdtemp(prefix='asservat-owner-epoch-component-', dir='/tmp'))
mirror = scratch / 'mirror'
tmp = scratch / 'go-tmp'
tmp.mkdir()
report['scratch'] = str(scratch)
(c / 'started.json').write_text(json.dumps(report, indent=2) + '\n')
env = {k: v for k, v in os.environ.items() if not k.startswith('ASSERVAT_')}
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')
packages = ['./internal/domain/fleet', './internal/domain/audit', './internal/application/fleet']
python = '/home/phil/.cache/asservat-build/spec-venv/bin/python'
phases = [
    ('compile', ['go', 'test', '-vet=off', '-run=^$', '-count=1', *packages], 0),
    ('draft-before-expiry', ['go', 'test', '-json', '-vet=off', '-count=1', '-timeout=60s',
      '-run=^TestOwnerAuditEpochAdmissionRejectsElapsedOriginalDependency$', './internal/domain/fleet'], 1),
    ('fleet-domain-races', ['go', 'test', '-json', '-race', '-vet=off', '-count=1', '-timeout=6m', './internal/domain/fleet'], 0),
    ('audit-domain-races', ['go', 'test', '-json', '-race', '-vet=off', '-count=1', '-timeout=6m', './internal/domain/audit'], 0),
    ('application-races', ['go', 'test', '-json', '-race', '-vet=off', '-count=1', '-timeout=6m', './internal/application/fleet'], 0),
    ('vet', ['go', 'vet', *packages], 0),
    ('go-architecture', ['make', 'go-architecture-check', 'PYTHON=' + python], 0),
    ('canonical', ['make', 'spec-check', 'architecture-check', 'design-check', 'PYTHON=' + python], 0),
]
required = {
    'fleet-domain-races': {'TestOwnerAuditEpochRejectsInvalidBoundsAndOriginalPins', 'TestOwnerAuditEpochCloneAndInstantEquality',
        'TestOwnerAuditEpochRolloverDoesNotMoveAdmittedDependency', 'TestOwnerAuditEpochAccountingChargesUnknownClaims',
        'TestOwnerAuditEpochAdmissionRequiresWholeRetainedLifecycle', 'TestOwnerAuditEpochScheduleReportsUnfundedRollover',
        'TestOwnerAuditEpochAdmissionRejectsElapsedOriginalDependency'},
    'audit-domain-races': {'TestOwnerConfigurationEpochReceiptIsSeparateFromV1', 'TestOwnerConfigurationEpochRejectsInvalidReceiptAndScope'},
}
code = 2
child = None
baseline = {}
validation_original = None
validation_path = mirror / 'docs/architecture/validation.json'

def interrupted(signum, frame):
    raise InterruptedError('qualification interrupted by signal ' + str(signum))

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
target = freeze['draftBeforePath']
try:
    for relative in deps:
        dest = mirror / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repo / relative, dest)
    for item in manifest:
        dest = mirror / item['path']
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(c / 'files' / item['path'], dest)
    for relative in directories:
        (mirror / relative).mkdir(parents=True, exist_ok=True)
    baseline = {str(p.relative_to(mirror)): sha(p) for p in mirror.rglob('*') if p.is_file()}
    (c / 'mirror-manifest.json').write_text(json.dumps(baseline, indent=2) + '\n')
    for name, command, expected in phases:
        check = verify()
        assert not any(check.values()), check
        shutil.copyfile(c / ('draft-before.go.txt' if name == 'draft-before-expiry' else 'files/' + target), mirror / target)
        log = c / (name + '.log')
        started = time.monotonic()
        stopped = None
        if name == 'canonical':
            validation_original = validation_path.read_bytes()
            (c / 'validation-before.json').write_bytes(validation_original)
        with log.open('x') as output:
            child = subprocess.Popen(command, cwd=mirror, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            report['lastOwnedProcess'] = {'phase': name, 'pid': child.pid}
            print(json.dumps(report['lastOwnedProcess']), flush=True)
            while child.poll() is None:
                if time.monotonic() - started > 600:
                    stopped = '600-second component infrastructure ceiling'
                elif log.stat().st_size > 32 * 1024**2:
                    stopped = '32-MiB output ceiling'
                elif shutil.disk_usage('/tmp').free < 256 * 1024**2:
                    stopped = 'scratch below 256 MiB'
                if stopped:
                    if not join_owned(child):
                        raise RuntimeError('owned phase could not be joined')
                    break
                time.sleep(0.5)
        if not join_owned(child):
            raise RuntimeError('owned phase group not joined before output inspection')
        if name == 'canonical':
            generated = validation_path.read_bytes()
            (c / 'canonical-validation.json').write_bytes(generated)
            report['generatedValidation'] = {'originalSHA256': hashlib.sha256(validation_original).hexdigest(),
                'generatedSHA256': hashlib.sha256(generated).hexdigest()}
            validation_path.write_bytes(validation_original)
            report['generatedValidation']['restored'] = validation_path.read_bytes() == validation_original
            validation_original = None
        actual = {str(p.relative_to(mirror)): sha(p) for p in mirror.rglob('*') if p.is_file()}
        expected_mirror = dict(baseline)
        if name == 'draft-before-expiry':
            expected_mirror[target] = freeze['draftBeforeSHA256']
        passed, failed, skipped = (test_events(log, x) for x in ['pass', 'fail', 'skip'])
        valid = set(passed) >= required.get(name, set()) and not failed and not skipped
        if name == 'draft-before-expiry':
            prefix = 'TestOwnerAuditEpochAdmissionRejectsElapsedOriginalDependency'
            valid = set(failed) == {prefix, prefix + '/exact-original-end', prefix + '/after-original-end'} and passed == [prefix + '/immediately-before'] and not skipped and 'original dependency end was not enforced' in log.read_text()
        elif name == 'application-races':
            valid = valid and len([x for x in passed if '/' not in x]) >= 1
        entry = {'name': name, 'command': command, 'exit': child.returncode, 'expectedExit': expected,
                 'seconds': time.monotonic() - started, 'stopReason': stopped, 'logSHA256': sha(log),
                 'passedTests': passed, 'failedTests': failed, 'skippedTests': skipped,
                 'requiredChecksPresent': valid, 'hashes': verify(), 'ownedProcessGroupJoined': True,
                 'exactMirrorUnchanged': actual == expected_mirror}
        report['phases'].append(entry)
        (c / 'progress.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(entry), flush=True)
        assert not stopped and child.returncode == expected and valid and not any(entry['hashes'].values()) and entry['exactMirrorUnchanged'], name
    code = 0
except BaseException as error:
    report['error'] = repr(error)
finally:
    # A second interactive interruption must not skip owned-group joining.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    report['ownedProcessGroupJoined'] = join_owned(child)
    if not report['ownedProcessGroupJoined']:
        code = 2
    if report['ownedProcessGroupJoined']:
        if validation_original is not None:
            try:
                generated = validation_path.read_bytes() if validation_path.is_file() else None
                if generated is not None:
                    (c / 'interrupted-validation.json').write_bytes(generated)
                report['interruptedValidation'] = {
                    'originalSHA256': hashlib.sha256(validation_original).hexdigest(),
                    'generatedSHA256': hashlib.sha256(generated).hexdigest() if generated is not None else None}
                validation_path.write_bytes(validation_original)
                report['interruptedValidation']['restored'] = validation_path.read_bytes() == validation_original
            except OSError as error:
                report['validationRestoreError'] = repr(error)
                code = 2
        if (mirror / target).exists():
            shutil.copyfile(c / 'files' / target, mirror / target)
    actual = {str(p.relative_to(mirror)): sha(p) for p in mirror.rglob('*') if p.is_file()}
    report['mirrorChanges'] = sorted(p for p in set(baseline) | set(actual) if baseline.get(p) != actual.get(p))
    report['after'] = verify()
    if report['mirrorChanges'] or any(report['after'].values()):
        code = 2
    report['scratchRemoved'] = False
    if report['ownedProcessGroupJoined']:
        try:
            shutil.rmtree(scratch)
            report['scratchRemoved'] = not scratch.exists()
        except OSError as error:
            report['scratchCleanupError'] = repr(error)
            code = 2
    report['exit'] = code
    (c / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'exit': code, 'scratchRemoved': report['scratchRemoved'],
        'ownedProcessGroupJoined': report['ownedProcessGroupJoined']}), flush=True)
raise SystemExit(code)
