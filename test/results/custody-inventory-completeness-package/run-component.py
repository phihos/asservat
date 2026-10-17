#!/usr/bin/env python3
"""Staged before/after correction; run only after a parent build-slot allocation."""
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time

LIVE = Path('/home/phil/Projekte/asservat')
STAGE = Path(__file__).parent
MANIFEST = '8be34e7a29b037f5f56fdf2b8897da68ceb69369a4fa03bccc120bfe7ce4249f'
PYTHON = '/home/phil/.cache/asservat-build/spec-venv/bin/python'
ARGS = ['api', 'cmd', 'internal', 'migrations', 'test/integration', 'test/fixtures', 'scripts', 'go.mod', 'go.sum', 'sqlc.yaml', 'Makefile', 'docs', 'specs', 'examples', 'design', 'charts', 'README.md', 'requirements-spec.txt', 'AGENTS.md', '.gitignore', 'web', '-g', '!web/node_modules/**']
TEST = 'TestPurgeRejectsOmittedInventoryCompleteness'
CHILDREN = [TEST + '/' + phase + '/' + api for phase in ('initial', 'final') for api in ('versions', 'uploads', 'current')]
TARGET = 'internal/adapters/objectstore/custody.go'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def save(p, value):
    with p.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def inventory():
    return sorted(subprocess.check_output(['rg', '--files', *ARGS], cwd=LIVE, text=True).splitlines())



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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent-exclusive-slot-allocated', action='store_true')
    p.add_argument('--output-name', default='component-1')
    a = p.parse_args()
    if not a.parent_exclusive_slot_allocated or not re.fullmatch('[a-z0-9][a-z0-9-]*', a.output_name):
        p.error('parent allocation and valid output basename required')
    assert sha(STAGE / 'manifest.json') == MANIFEST
    manifest = json.loads((STAGE / 'manifest.json').read_text())
    output = STAGE / 'checks' / a.output_name
    output.mkdir(parents=True)
    (output / 'evidence').mkdir()
    for name, row in manifest.items():
        assert sha(LIVE / name) == row['baseSHA256'], ('base drift', name)
        assert sha(STAGE / 'files' / name) == row['sha256'], ('payload drift', name)
    files = inventory()
    deps = {name: sha(LIVE / name) for name in files}
    directories = {}
    queue = [name for name in set(files) | set(manifest) if name.endswith('.md')]
    seen = set()
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        text = ((STAGE / 'files' / name) if name in manifest else (LIVE / name)).read_text()
        for destination in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', text):
            url = urlsplit(destination.strip('<>').split(' "', 1)[0])
            if url.scheme or url.netloc or not url.path:
                continue
            path = ((LIVE / name).parent / unquote(url.path)).resolve()
            if not path.is_relative_to(LIVE):
                raise RuntimeError('external local file link')
            child = path.relative_to(LIVE).as_posix()
            if path.is_dir():
                directories[child] = sorted(p.name for p in path.iterdir())
            elif child not in manifest:
                if not path.is_file():
                    raise RuntimeError('missing linked dependency: ' + child)
                deps[child] = sha(path)
                if child.endswith('.md'):
                    queue.append(child)
    metadata = {name: sha(STAGE / name) for name in ('run-component.py', 'manifest.json', 'bases.json', 'review.patch', 'HANDOFF.md')}
    save(output / 'dependencies.json', dict(sorted(deps.items())))
    save(output / 'inventory.json', files)
    save(output / 'linked-directories.json', directories)
    save(output / 'metadata.json', metadata)
    shutil.copytree(STAGE / 'files', output / 'files')
    shutil.copyfile(STAGE / 'manifest.json', output / 'manifest.json')

    def verify():
        return {'metadata': [n for n, h in metadata.items() if sha(STAGE / n) != h],
                'payloads': [n for n, r in manifest.items() if sha(STAGE / 'files' / n) != r['sha256']],
                'bases': [n for n, r in manifest.items() if sha(LIVE / n) != r['baseSHA256']],
                'dependencies': [n for n, h in deps.items() if sha(LIVE / n) != h],
                'inventory': sorted(set(inventory()) ^ set(files)),
                'directories': [n for n, children in directories.items() if not (LIVE / n).is_dir() or sorted(p.name for p in (LIVE / n).iterdir()) != children]}

    report = {'native': False, 'runtimeEnablement': False, 'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'manifestSHA256': MANIFEST, 'metadata': metadata, 'dependencyCount': len(deps), 'before': verify(), 'phases': []}
    assert not any(report['before'].values()), report['before']
    assert shutil.disk_usage('/tmp').free >= 4 * 1024**3
    scratch = Path(tempfile.mkdtemp(prefix='asservat-custody-completeness-', dir='/tmp'))
    mirror, tmp = scratch / 'mirror', scratch / 'go-tmp'
    tmp.mkdir()
    report['scratch'] = str(scratch)
    env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), PYTHONDONTWRITEBYTECODE='1')
    for key in list(env):
        if key.startswith('ASSERVAT_'):
            env.pop(key)
    package = './internal/adapters/objectstore'
    phases = [
        ('original-before', ['go', 'test', '-race', '-vet=off', '-count=1', '-timeout=15m', '-v', '-run=^' + TEST + '$', package], 1),
        ('compile', ['go', 'test', '-vet=off', '-count=1', '-run=^$', package, './test/integration'], 0),
        ('corrected-races', ['go', 'test', '-race', '-vet=off', '-count=1', '-timeout=15m', '-v', package], 0),
        ('vet', ['go', 'vet', package, './test/integration'], 0),
        ('go-architecture', ['make', 'go-architecture-check', 'PYTHON=' + PYTHON], 0),
        ('canonical', ['make', 'spec-check', 'architecture-check', 'design-check', 'PYTHON=' + PYTHON], 0),
    ]
    code, expected_mirror = 2, {}
    process, validation_original = None, None
    validation_path = mirror / 'docs/architecture/validation.json'
    try:
        for name in deps:
            path = mirror / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(LIVE / name, path)
        for name in manifest:
            path = mirror / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(STAGE / 'files' / name, path)
        for name in directories:
            (mirror / name).mkdir(parents=True, exist_ok=True)
        expected_mirror = {p.relative_to(mirror).as_posix(): sha(p) for p in mirror.rglob('*') if p.is_file()}
        save(output / 'mirror-manifest.json', expected_mirror)
        for name, command, expected_exit in phases:
            current = verify()
            if any(current.values()):
                report['prePhaseFailure'] = current
                break
            shutil.copyfile((LIVE if name == 'original-before' else STAGE / 'files') / TARGET, mirror / TARGET)
            log = output / 'evidence' / (name + '.log')
            started, stop = time.monotonic(), None
            if name == 'canonical':
                validation_original = validation_path.read_bytes()
                with (output / 'validation-before.json').open('xb') as saved:
                    saved.write(validation_original)
            with log.open('x') as stream:
                process = subprocess.Popen(command, cwd=mirror, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                report['lastOwnedProcess'] = {'phase': name, 'pid': process.pid}
                print(json.dumps({'phase': name, 'pid': process.pid}), flush=True)
                while process.poll() is None:
                    if time.monotonic() - started > 960:
                        stop = '960-second infrastructure ceiling'
                    elif log.stat().st_size > 32 * 1024**2:
                        stop = '32-MiB output ceiling'
                    elif shutil.disk_usage('/tmp').free < 256 * 1024**2:
                        stop = 'scratch below 256 MiB'
                    if stop:
                        if not join_owned(process):
                            raise RuntimeError('owned phase could not be joined')
                        break
                    time.sleep(.5)
            if not join_owned(process):
                raise RuntimeError('owned phase not joined before output inspection')
            if name == 'canonical':
                generated = validation_path.read_bytes()
                (output / 'evidence' / 'canonical-validation.json').write_bytes(generated)
                report['generatedValidation'] = {'beforeSHA256': hashlib.sha256(validation_original).hexdigest(), 'generatedSHA256': hashlib.sha256(generated).hexdigest()}
                validation_path.write_bytes(validation_original)
                report['generatedValidation']['restored'] = validation_path.read_bytes() == validation_original
                validation_original = None
            text = log.read_text()
            passes = re.findall(r'^\s*--- PASS: (\S+) ', text, re.M)
            failures = re.findall(r'^\s*--- FAIL: (\S+) ', text, re.M)
            required = True
            if name == 'original-before':
                required = set(CHILDREN) <= set(failures) and text.count('omitted IsTruncated certified absence or wrong failure:') == 6 and text.count('err=<nil> deletes=1 aborts=1') == 6 and '[build failed]' not in text and 'panic:' not in text
            if name == 'corrected-races':
                required = set(CHILDREN) <= set(passes) and all(n in passes for n in ['TestPurgeRequiresCompleteConfinedInventory/null-version', 'TestPurgeRequiresCompleteConfinedInventory/truncated', 'TestOperationPurgeConfinesAllVersionsAndTerminalSlot/original', 'TestOperationPurgeConfinesAllVersionsAndTerminalSlot/truncated', 'TestDownloadStopPurgeConfinesAllVersionsAndTerminalSlot/original', 'TestDownloadStopPurgeConfinesAllVersionsAndTerminalSlot/truncated'])
            actual = {p.relative_to(mirror).as_posix(): sha(p) for p in mirror.rglob('*') if p.is_file()}
            expected = dict(expected_mirror)
            if name == 'original-before':
                expected[TARGET] = manifest[TARGET]['baseSHA256']
            entry = {'name': name, 'command': command, 'exit': process.returncode, 'expectedExit': expected_exit, 'seconds': round(time.monotonic() - started, 3), 'stopReason': stop, 'processJoined': process.poll() is not None, 'requiredChecksPresent': required, 'passedTests': passes, 'failedTests': failures, 'logSHA256': sha(log), 'after': verify(), 'exactMirrorUnchanged': actual == expected}
            report['phases'].append(entry)
            print(json.dumps({'phase': name, 'exit': process.returncode, 'requiredChecksPresent': required, 'seconds': entry['seconds']}), flush=True)
            code = 0 if process.returncode == expected_exit and required and not stop and not any(entry['after'].values()) and entry['exactMirrorUnchanged'] else 2
            if code:
                break
    except BaseException as exc:
        report['runnerError'] = repr(exc)
        code = 2
    finally:
        report['ownedProcessJoined'] = join_owned(process)
        if not report['ownedProcessJoined']:
            code = 2
        if report['ownedProcessJoined']:
            if validation_original is not None:
                try:
                    if validation_path.is_file():
                        shutil.copyfile(validation_path, output / 'evidence' / 'interrupted-validation.json')
                    validation_path.write_bytes(validation_original)
                    report['interruptedValidationRestored'] = validation_path.read_bytes() == validation_original
                except OSError as exc:
                    report['validationRestoreError'] = repr(exc)
                    code = 2
            if (mirror / TARGET).exists():
                shutil.copyfile(STAGE / 'files' / TARGET, mirror / TARGET)
        actual = {p.relative_to(mirror).as_posix(): sha(p) for p in mirror.rglob('*') if p.is_file()}
        report['exactMirrorUnchanged'] = actual == expected_mirror
        report['after'] = verify()
        if not report['exactMirrorUnchanged'] or any(report['after'].values()):
            code = 2
        report['scratchRemoved'] = False
        if report['ownedProcessJoined']:
            try:
                shutil.rmtree(scratch)
                report['scratchRemoved'] = not scratch.exists()
            except OSError as exc:
                report['scratchCleanupError'] = repr(exc)
                code = 2
        report['exit'] = code
        save(output / 'result.json', report)
        print(json.dumps({'exit': code, 'scratchRemoved': report['scratchRemoved'], 'ownedProcessJoined': report['ownedProcessJoined']}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
