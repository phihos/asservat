#!/usr/bin/env python3
"""Focused ADR161 race/schema gate; run only in the parent-allocated slot."""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from events import discovery, execution, json_values, partition, source_declarations

ROOT = Path('/home/phil/Projekte/asservat')
CACHE = Path('/home/phil/.cache/asservat-build')
STAGE = Path(__file__).resolve().parent
PYTHON = str(CACHE / 'spec-venv/bin/python')
MODULE = 'asservat.local/asservat'
KUBE = MODULE + '/internal/adapters/kubernetes'
FLAGS = ['-race', '-count=1', '-timeout=15m']
SCHEMAS = ['manifest-schema-check', 'permission-schema-check', 'policy-schema-check',
           'permission-crd-check', 'control-schema-check', 'start-crd-check',
           'retention-crd-check', 'investigation-schema-check']
ARIA = 'web/node_modules/react-aria/dist/private/interactions/usePress.mjs'
SQLC = CACHE / 'bin/sqlc'
SQLC_SHA256 = 'fae55f275d1a5d8722eb5b52b97a2cc2d2f39e3d9135dd0449291be21df26b44'
REVIEWED_SHARDS = '622e35afcdac6190d1a5fa9f6864ba6bffaa33ff63450093ca8f714ab2c69419'
STAGE_FILES = ['component.py', 'events.py', 'test-events.py', 'synthetic-events.json', 'selection.json', 'payloads.json']
interrupt_signal = None


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open('x') as file:
        json.dump(value, file, indent=2)
        file.write('\n')


def freeze():
    files = {ROOT / n for n in ('Makefile', 'go.mod', 'go.sum', 'sqlc.yaml',
             'requirements-spec.txt', 'README.md', 'AGENTS.md', '.gitignore')}
    for folder in ('api', 'cmd', 'internal', 'migrations', 'test/integration',
                   'test/fixtures', 'scripts', 'charts', 'specs', 'docs', 'examples', 'design', 'web'):
        files.update(p for p in (ROOT / folder).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and 'node_modules' not in p.parts)
    # Its actual presence is also contractual: do not pass by silently skipping
    # console source compatibility or the built-package case.
    if not (ROOT / ARIA).is_file() or not (ROOT / 'web/dist/index.html').is_file():
        raise RuntimeError('required existing console qualification inputs absent')
    files.add(ROOT / ARIA)
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}


def interrupt(signum, frame):
    # Recording only closes the Popen spawn/assignment interruption window.
    global interrupt_signal
    if interrupt_signal is None:
        interrupt_signal = signum


def check_interrupt():
    if interrupt_signal is not None:
        raise InterruptedError('qualification signal ' + str(interrupt_signal))


def group_exists(child):
    if child is None:
        return False
    try:
        os.killpg(child.pid, 0)
        return True
    except ProcessLookupError:
        return False


def join_owned(child):
    # Same positive process-group join protocol as the reviewed codec runner.
    if child is None:
        return True
    def send(sig):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
    if child.poll() is None:
        send(signal.SIGTERM)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            send(signal.SIGKILL)
            child.wait(timeout=10)
    else:
        child.wait(timeout=1)
    if group_exists(child):
        send(signal.SIGKILL)
        until = time.monotonic() + 10
        while group_exists(child) and time.monotonic() < until:
            time.sleep(.05)
    return child.poll() is not None and not group_exists(child)


def source_inventory(packages, baseline, selected):
    expected = {}
    wanted = {MODULE + '/' + p for p in selected}
    for package in packages:
        name, directory = package.get('ImportPath'), Path(package.get('Dir', ''))
        if name not in wanted or name in expected or directory != ROOT / name.removeprefix(MODULE + '/'):
            raise ValueError('foreign/duplicate selected package')
        if package.get('Error') or package.get('DepsErrors') or package.get('Module', {}).get('Path') != MODULE:
            raise ValueError('invalid or foreign package metadata')
        actual_files = package.get('TestGoFiles', []) + package.get('XTestGoFiles', [])
        # These selected directories currently have no build-tagged test files.
        # Fail explicitly if platform/build selection ever changes their closure.
        if set(actual_files) != {p.name for p in directory.glob('*_test.go')}:
            raise ValueError('go-list test file set differs from frozen package')
        declared = []
        for filename in actual_files:
            path = directory / filename
            if str(path.relative_to(ROOT)) not in baseline:
                raise ValueError('unfrozen test file')
            declared.extend(source_declarations(path.read_text()))
        if len(declared) != len(set(declared)):
            raise ValueError('duplicate source declaration')
        expected[name] = sorted(declared)
    if set(expected) != wanted:
        raise ValueError('selected package discovery incomplete')
    return expected


def selected_inventory(selected):
    expected = {}
    for rel, item in selected.items():
        files = sorted((ROOT / rel).glob('*_test.go')) if item['files'] == '*' else [ROOT / rel / n for n in item['files']]
        names = sorted(n for file in files for n in source_declarations(file.read_text()))
        if not names or Counter(names) != Counter(item['tests']):
            raise ValueError('reviewed selected declarations changed: ' + rel)
        expected[MODULE + '/' + rel] = names
    return expected


def verify_make_contract():
    text = (ROOT / 'Makefile').read_text()
    match = re.search(r'^go-check: ([^\n]+)\n((?:\t[^\n]*\n)+)', text, re.M)
    if not match or match[1].split() != SCHEMAS:
        raise ValueError('reviewed Make prerequisites changed')
    recipe = [line.strip() for line in match[2].splitlines() if not line.strip().startswith('#')]
    if recipe != ['go vet ./...', '$(PYTHON) scripts/test-go-shards.py', '$(PYTHON) scripts/check-go-tests.py']:
        raise ValueError('reviewed Make Go coverage changed')
    if sha(ROOT / 'scripts/check-go-tests.py') != REVIEWED_SHARDS:
        raise ValueError('reviewed exact shard selection changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-name', required=True)
    parser.add_argument('--parent-exclusive-slot-allocated', action='store_true')
    args = parser.parse_args()
    if not args.parent_exclusive_slot_allocated or not re.fullmatch('[a-z0-9][a-z0-9-]*', args.output_name):
        parser.error('parent allocation and create-only output name required')
    out = ROOT / 'test/results' / args.output_name
    out.mkdir()
    tmp = CACHE / (args.output_name + '-tmp')
    tmp.mkdir()
    child = None
    started = time.monotonic()
    baseline, metadata = {}, {}
    validation_path = ROOT / 'docs/architecture/validation.json'
    validation_original = None
    validation_captured = False
    report = {'gate': 'ADR161 focused race, SQL/schema and canonical checks; compile/vet separately qualified',
              'scratch': str(tmp), 'phases': [], 'validationErrors': [],
              'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    code = 1
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    def verify():
        return freeze() == baseline and sha(SQLC) == SQLC_SHA256 and all(sha(STAGE / n) == h for n, h in metadata.items())
    env = {k: v for k, v in os.environ.items() if not k.startswith('ASSERVAT_')}
    env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')

    def restore_validation():
        nonlocal validation_captured
        if validation_original is None:
            return
        if not join_owned(child):
            raise RuntimeError('owned group not joined before validation snapshot/restore')
        if not validation_captured:
            generated = validation_path.read_bytes() if validation_path.exists() else None
            if generated is not None:
                with (out / 'validation-generated.json').open('xb') as file:
                    file.write(generated)
            report['validationGeneratedSHA256'] = hashlib.sha256(generated).hexdigest() if generated is not None else None
            validation_captured = True
        if not join_owned(child):
            raise RuntimeError('owned group not joined before validation restore write')
        if not validation_path.exists() or validation_path.read_bytes() != validation_original:
            validation_path.write_bytes(validation_original)
        report['validationRestored'] = validation_path.read_bytes() == validation_original
        if not report['validationRestored']:
            raise RuntimeError('original validation artifact restore failed')

    def phase(name, command, ceiling=1020):
        nonlocal child
        check_interrupt()
        if not verify() or not join_owned(child):
            raise RuntimeError('source changed or previous owned group not joined')
        stdout, stderr = out / (name + '.log'), out / (name + '.stderr')
        start, stop = time.monotonic(), None
        entry = {'name': name, 'command': command, 'infrastructureCeilingSeconds': ceiling}
        report['phases'].append(entry)
        with stdout.open('x') as output, stderr.open('x') as error:
            check_interrupt()
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output, stderr=error, start_new_session=True)
            entry['pid'] = child.pid
            print(json.dumps({'phase': name, 'pid': child.pid}), flush=True)
            while child.poll() is None:
                if interrupt_signal is not None:
                    stop = 'qualification signal ' + str(interrupt_signal)
                elif time.monotonic() - start > ceiling:
                    stop = 'infrastructure ceiling'
                elif stdout.stat().st_size + stderr.stat().st_size > 128 * 1024**2:
                    stop = '128 MiB output ceiling'
                elif shutil.disk_usage(tmp).free < 1024**3:
                    stop = 'scratch free-space floor'
                if stop:
                    break
                time.sleep(.5)
        leaked = child.poll() is not None and group_exists(child)
        joined = join_owned(child)
        entry.update(exit=child.returncode, seconds=round(time.monotonic() - start, 3),
                     stopReason=stop, unexpectedLiveDescendants=leaked, ownedGroupJoined=joined,
                     stdoutSHA256=sha(stdout), stderrSHA256=sha(stderr))
        if name == 'canonical' and joined:
            restore_validation()
        check_interrupt()
        if child.returncode != 0 or stop or not joined or leaked or not verify():
            raise RuntimeError('phase failed, changed inputs or unjoined descendants: ' + name)
        return stdout.read_text()

    try:
        baseline = freeze()
        if sha(SQLC) != SQLC_SHA256:
            raise ValueError('reviewed sqlc binary changed')
        report['sqlcSHA256'] = SQLC_SHA256
        metadata = {name: sha(STAGE / name) for name in STAGE_FILES}
        save(out / 'sources.json', baseline)
        save(out / 'runner-files.json', metadata)
        for name in metadata:
            with (out / name).open('xb') as file:
                file.write((STAGE / name).read_bytes())
        report.update(sourceCount=len(baseline), sourceSnapshotSHA256=sha(out / 'sources.json'), runnerSHA256=metadata['component.py'])
        if shutil.disk_usage(ROOT).free < 32 * 1024**3:
            raise RuntimeError('less than 32 GiB free before component gate')
        verify_make_contract()
        payloads = json.loads((STAGE / 'payloads.json').read_text())
        if len(payloads) != 79 or any(baseline.get(p) != h for p, h in payloads.items()):
            raise ValueError('reviewed integrated payloads differ')
        report['reviewedPayloads'] = payloads
        for rel in payloads:
            target = out / 'payloads' / (rel + '.txt')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as file:
                file.write((ROOT / rel).read_bytes())
        selected = json.loads((STAGE / 'selection.json').read_text())
        required = selected_inventory(selected)
        save(out / 'required-tests.json', required)
        phase('strict-event-parser', [PYTHON, str(STAGE / 'test-events.py')])
        packages = json_values(phase('packages', ['go', 'list', '-json', *required]))
        source = source_inventory(packages, baseline, selected)
        save(out / 'source-test-inventory.json', source)
        discovered = discovery(phase('test-discovery', ['go', 'test', *FLAGS, '-json', '-list', '^(Test|Fuzz|Example)', *required]), source)
        save(out / 'discovered-tests.json', discovered)
        if any(not set(ns) <= set(discovered[p]) for p, ns in required.items()):
            raise ValueError('selected test absent from actual Go listing')
        executions = []
        for package, names in required.items():
            pattern = '^(' + '|'.join(re.escape(n) for n in names) + ')$'
            label = package.removeprefix(MODULE + '/').replace('/', '-')
            output = phase(label, ['go', 'test', *FLAGS, '-json', '-run', pattern, package])
            executions.append(execution(output, {package: names}, {}))
        wanted = sum(map(len, required.values()))
        if sum(e['parents'] for e in executions) != wanted:
            raise ValueError('exact selected parent count differs')
        report['tests'] = {'packageCount': len(required), 'parentCount': wanted,
                           'executions': executions, 'skips': []}
        phase('schemas-and-sql', ['make', *SCHEMAS, 'sql-check', 'PYTHON=' + PYTHON])
        validation_original = validation_path.read_bytes()
        with (out / 'validation-original.json').open('xb') as file:
            file.write(validation_original)
        report['validationOriginalSHA256'] = hashlib.sha256(validation_original).hexdigest()
        phase('canonical', ['make', 'go-architecture-check', 'spec-check', 'architecture-check', 'design-check', 'PYTHON=' + PYTHON])
        check_interrupt()
        code = 0
    except BaseException as error:
        report['validationErrors'].append(repr(error))
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        report['signalReceived'] = interrupt_signal
        if interrupt_signal is not None:
            code = 1
        try:
            report['ownedGroupJoined'] = join_owned(child)
        except BaseException as error:
            report['ownedGroupJoined'] = False
            report['joinError'] = repr(error)
        try:
            if report['ownedGroupJoined'] and validation_original is not None:
                restore_validation()
        except BaseException as error:
            report['validationRestored'] = False
            report['validationRestoreError'] = repr(error)
            code = 1
        try:
            report['sourceSnapshotUnchanged'] = bool(baseline) and verify()
        except BaseException as error:
            report['sourceSnapshotUnchanged'] = False
            report['sourceVerificationError'] = repr(error)
        report['emptyScratchRemoved'] = False
        if report['ownedGroupJoined']:
            try:
                if not join_owned(child):
                    raise RuntimeError('owned group not joined immediately before scratch removal')
                # Do not erase unexpected leftovers and claim successful cleanup.
                tmp.rmdir()
                report['emptyScratchRemoved'] = not tmp.exists()
            except BaseException as error:
                report['cleanupError'] = repr(error)
        if not report['ownedGroupJoined'] or not report['sourceSnapshotUnchanged'] or not report['emptyScratchRemoved']:
            code = 1
        report['archiveHashes'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        report['exit'] = code
        report['seconds'] = round(time.monotonic() - started, 3)
        save(out / 'result.json', report)
        print(json.dumps({'exit': code, 'ownedGroupJoined': report['ownedGroupJoined'],
                          'emptyScratchRemoved': report['emptyScratchRemoved'],
                          'validationErrors': report['validationErrors']}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
