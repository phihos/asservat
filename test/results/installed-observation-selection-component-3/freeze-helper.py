#!/usr/bin/env python3
"""Run one parent-allocated gate; staging this file performs no qualification."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

ROOT = Path('/home/phil/Projekte/asservat')
CACHE = Path('/home/phil/.cache/asservat-build')
PYTHON = CACHE / 'spec-venv/bin/python'
OWNER_TEST = 'TestInitialBootstrapChainWithRealServices'
OWNER_REQUIRED = [OWNER_TEST, OWNER_TEST + '/all-four-commands-passive-without-setup-files',
                  OWNER_TEST + '/runtime-provider-owner-identity',
                  OWNER_TEST + '/administrator-removal-detected-without-recreation']
MODES = {
    'owner': (['python3', 'scripts/test-context-storage.py', '--initial-bootstrap-chain',
               '--runtime-provider-pair', '--runtime-provider-worker', '--runtime-provider-owner'], 'context-storage'),
    'fleet': (['make', 'fleet-integration', 'PYTHON=' + str(PYTHON)], 'fleet'),
    'custody': (['make', 'custody-integration', 'PYTHON=' + str(PYTHON)], 'custody'),
    'go': (['make', 'go-check', 'go-architecture-check', 'PYTHON=' + str(PYTHON)], None),
}
PATTERNS = {'fleet': 'Test(Enrollment|PeerRegistry|ConnectorPKI|BootstrapChannel|InitialProviderIssuer)',
            'custody': 'Test(Custody|PermissionAuthority|ContextAdmission|PeerRegistry|Enrollment)'}
# These two named cases explicitly require fleet/context KMS fixtures. The full
# custody target deliberately supplies neither; fleet must pass them separately.
CUSTODY_EXPECTED_SKIPS = {'TestEnrollmentOwnerPKIWithRealServices', 'TestEnrollmentOwnerBootstrapPKIWithRealServices'}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def save(p, value):
    with p.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def freeze():
    files = {ROOT / n for n in ('Makefile', 'go.mod', 'go.sum', 'sqlc.yaml', 'requirements-spec.txt')}
    for folder in ('api', 'cmd', 'internal', 'migrations', 'test/integration', 'test/fixtures', 'scripts', 'charts/asservat', 'specs'):
        files.update(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files.add(ROOT / 'docs/architecture/catalog.yaml')
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}


def harness_freeze(mode):
    # Independently spell the fixture's entire documented closure, including its
    # file set. A subset comparison must never accept omitted harness inputs.
    files = {ROOT / n for n in ('go.mod', 'go.sum')}
    for folder, patterns in [('cmd', ('*.go',)), ('internal', ('*.go', '*.json')),
                             ('migrations', ('*.sql', '*.go')), ('test/integration', ('*.go',)),
                             ('test/fixtures', ('*.sql',))]:
        for pattern in patterns:
            files.update((ROOT / folder).rglob(pattern))
    if mode == 'owner':
        files.update(ROOT / n for n in ('scripts/test-context-storage.py', 'scripts/helm_registry.py'))
        files.update((ROOT / 'test/fixtures').rglob('*.go'))
        files.update(p for p in (ROOT / 'charts/asservat').rglob('*') if p.is_file())
    else:
        files.update(ROOT / n for n in ('sqlc.yaml', 'scripts/test-custody.py'))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}


def required_names(mode):
    if mode == 'owner':
        return OWNER_REQUIRED
    pattern = re.compile(PATTERNS[mode])
    declared = set()
    for p in (ROOT / 'test/integration').glob('*_test.go'):
        declared.update(n for n in re.findall(r'^func (Test\w+)\(t \*testing.T\)', p.read_text(), re.M) if pattern.search(n))
    if mode == 'custody':
        declared -= CUSTODY_EXPECTED_SKIPS
    if not declared:
        raise RuntimeError('no selected source-declared tests')
    return sorted(declared)


def docker_cleanup(native, mode):
    if mode == 'owner':
        tag = native['workerBuild']['tag']
        if not tag.startswith('asservat-context-worker:context-'):
            raise RuntimeError('unexpected owned image tag')
        label = tag.split(':', 1)[1]
        clusters = [c['name'] + '-control-plane' for c in native['clusters']]
    else:
        containers = list(native['images'])
        pg = [n for n in containers if n.endswith('-postgres')]
        if len(pg) != 1 or not pg[0].startswith('asservat-custody-'):
            raise RuntimeError('owned database identity absent')
        label = pg[0][len('asservat-'):-len('-postgres')]
        clusters = []
    evidence = {}
    for kind in ('container', 'network', 'volume', 'image'):
        command = ['docker', kind, 'ls']
        if kind == 'container':
            command += ['-a']
        command += ['--filter', 'label=asservat.test=' + label, '--format', '{{.Name}}' if kind == 'volume' else '{{.ID}}']
        probe = subprocess.run(command, text=True, capture_output=True, timeout=20)
        evidence[kind] = {'exit': probe.returncode, 'remainingIDs': probe.stdout.splitlines()}
        if probe.returncode or probe.stdout.strip():
            raise RuntimeError('owned ' + kind + ' cleanup not positively established')
    if clusters:
        probe = subprocess.run(['docker', 'container', 'ls', '-a', '--format', '{{.Names}}'], text=True, capture_output=True, timeout=20)
        present = sorted(set(clusters) & set(probe.stdout.splitlines()))
        evidence['kindNodes'] = {'exit': probe.returncode, 'remainingNames': present}
        if probe.returncode or present:
            raise RuntimeError('owned Kind node cleanup not positively established')
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--output-name', required=True)
    parser.add_argument('--parent-exclusive-slot-allocated', action='store_true')
    args = parser.parse_args()
    if not args.parent_exclusive_slot_allocated:
        parser.error('parent must allocate the single native/build slot and freeze sources')
    if not re.fullmatch('[a-z0-9][a-z0-9-]*', args.output_name):
        parser.error('invalid create-only result basename')
    output = ROOT / 'test/results' / args.output_name
    output.mkdir()
    tmp = CACHE / (args.output_name + '-tmp')
    tmp.mkdir()
    baseline = freeze()
    save(output / 'sources.json', baseline)
    command, prefix = MODES[args.mode]
    expected = harness_freeze(args.mode) if prefix else {}
    required = required_names(args.mode) if prefix else []
    save(output / 'expected-harness-sources.json', expected)
    env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
    for k in tuple(env):
        if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP':
            env.pop(k)
    report = {'mode': args.mode, 'command': command, 'runnerSHA256': sha(Path(__file__)),
              'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'sourceCount': len(baseline), 'sourceSnapshotSHA256': sha(output / 'sources.json'),
              'expectedHarnessSourceCount': len(expected), 'requiredPassedTests': required,
              'expectedSkippedTests': sorted(CUSTODY_EXPECTED_SKIPS) if args.mode == 'custody' else [],
              'scratch': str(tmp), 'validationErrors': [], 'processJoined': False}
    code = 1
    try:
        report['diskBeforeBytes'] = shutil.disk_usage(ROOT).free
        report['tmpFreeBeforeBytes'] = shutil.disk_usage('/tmp').free
        if report['diskBeforeBytes'] < 32 * (1 << 30):
            raise RuntimeError('less than 32 GiB free before gate')
        if args.mode == 'owner' and report['tmpFreeBeforeBytes'] < 4 * (1 << 30):
            raise RuntimeError('less than 4 GiB free before native build')
        old = {p.name: (p.stat().st_mtime_ns, sha(p)) for p in (ROOT / 'test/results').glob((prefix or 'never-selected-') + '*') if p.is_file()}
        if freeze() != baseline:
            raise RuntimeError('source changed before launch')
        start = time.monotonic()
        with (output / 'gate.log').open('x') as log:
            run = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        report.update(processJoined=True, commandExit=run.returncode, seconds=round(time.monotonic() - start, 3))
        errors = report['validationErrors']
        if run.returncode:
            errors.append('gate command failed')
        if prefix:
            for p in (ROOT / 'test/results').glob(prefix + '*'):
                if p.is_file() and old.get(p.name) != (p.stat().st_mtime_ns, sha(p)):
                    shutil.copyfile(p, output / p.name)
            native_path = output / (prefix + '-environment.json')
            if not native_path.exists():
                raise RuntimeError('fresh native report absent')
            native = json.loads(native_path.read_text())
            names = native.get('passedTests', native.get('passedTestNames', []))
            if not isinstance(names, list) or any(not isinstance(n, str) for n in names):
                names = []
            report.update(passedTests=names, missingRequiredTests=sorted(set(required) - set(names)),
                          cleanupFailures=native.get('cleanupFailures'), testExit=native.get('testExit'),
                          exactHarnessSources=native.get('sourceHashes') == expected)
            if report['missingRequiredTests']:
                errors.append('missing required selected PASS names')
            if native.get('testExit') != 0 or native.get('sourceUnchangedDuringTest') is not True:
                errors.append('native test exit/source stability failed')
            if native.get('sourceHashes') != expected:
                errors.append('native source hashes or exact file set differ from independent closure')
            if native.get('cleanupFailures') != []:
                errors.append('native cleanup missing or failed')
            if args.mode == 'owner':
                required_flags = ('runtimeProviderPairQualification', 'runtimeProviderWorkerQualification', 'runtimeProviderOwnerQualification', 'initialBootstrapChainQualification')
                if any(native.get(k) is not True for k in required_flags) or native.get('testPattern') != '^' + OWNER_TEST + '$' or native.get('fixtureMigratesDatabase') is not False or native.get('aggregateGoTimeout') != '14m' or native.get('bootstrapFixtureSeconds') != 720:
                    errors.append('original owner qualification path or budget changed')
                if native.get('buildScratchRemoved') is not True:
                    errors.append('native build scratch not removed')
            else:
                if native.get('testPattern') != PATTERNS[args.mode] or native.get('goTestTimeoutSeconds') != (300 if args.mode == 'fleet' else 900):
                    errors.append('full native target selection or aggregate timeout changed')
            # Read-only absence checks supplement the harness's positive teardown.
            # They never delete a resource or touch a foreign test environment.
            report['ownedDockerCleanup'] = docker_cleanup(native, args.mode)
        else:
            log = (output / 'gate.log').read_text()
            markers = ['go vet ./...', 'go test -race -count=1 -timeout=15m ./...', 'Go architecture OK:']
            report['missingGateMarkers'] = [s for s in markers if s not in log]
            report['passedPackages'] = re.findall(r'^ok\s+(\S+)\s+', log, re.M)
            if report['missingGateMarkers'] or not report['passedPackages']:
                errors.append('full Go/architecture gate output incomplete')
        code = 0 if not errors else 1
    except Exception as exc:
        report['runnerError'] = str(exc)
    finally:
        report['sourceSnapshotUnchanged'] = freeze() == baseline
        if not report['sourceSnapshotUnchanged']:
            code = 1
        try:
            tmp.rmdir()
            report['emptyScratchRemoved'] = True
        except OSError:
            report['emptyScratchRemoved'] = False
            code = 1
        report['archiveHashes'] = {p.name: sha(p) for p in output.iterdir() if p.is_file()}
        report['exit'] = code
        save(output / 'result.json', report)
        print(json.dumps({'mode': args.mode, 'exit': code, 'seconds': report.get('seconds'), 'validationErrors': report['validationErrors'], 'runnerError': report.get('runnerError')}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
