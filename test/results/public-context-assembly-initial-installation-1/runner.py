#!/usr/bin/env python3
"""Run one parent-allocated gate; staging this file performs no qualification."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time

ROOT = Path('/home/phil/Projekte/asservat')
CACHE = Path('/home/phil/.cache/asservat-build')
PYTHON = CACHE / 'spec-venv/bin/python'
OWNER_TEST = 'TestInitialBootstrapChainWithRealServices'
OWNER_REQUIRED = [OWNER_TEST, OWNER_TEST + '/all-four-commands-passive-without-setup-files',
                  OWNER_TEST + '/runtime-provider-owner-identity',
                  OWNER_TEST + '/administrator-removal-detected-without-recreation']
INITIAL_TEST = 'TestInitialInstallationWithRealServices'
# Full, unchanged fresh-fixture parent; includes the four actual generated-role
# positive leaves under matrix and acknowledged lost-completion recovery.
INITIAL_REQUIRED = [
    'TestInitialInstallationWithRealServices',
    'TestInitialInstallationWithRealServices/audit-witness-and-later-recovery-block',
    'TestInitialInstallationWithRealServices/concurrent-preparations-retain-one-attempt',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-ack-current-generation',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-ack-lock-expired',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-ack-recovery',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-ack-source-expired',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-changed-source',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-expired-observation',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-held-lock',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-ambient',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-changed-source',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-held-lock',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-matrix',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-missing-role',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-launched-recovery-after-lock',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-matrix',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-reconcile',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-recovery-after-lock',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-source-after-lock',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-source-mutation',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-source-rollback',
    'TestInitialInstallationWithRealServices/configuration-runtime-roles-unknown-claim',
    'TestInitialInstallationWithRealServices/consumed-witness-cannot-recreate-lost-sql',
    'TestInitialInstallationWithRealServices/existing-state-before-or-after-preparation-denies',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-administrator',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-database',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-held-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-late-callback',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-caller-expired-after-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-concurrent-observers',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-current',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-current-end',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-digest',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-generation',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-issuer',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-late-callback',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-recovery-after-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-source-after-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-owner-source-expired-after-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-postmaster',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-recovery',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-recovery-after-lock',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-runtime-role',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-schema-after-construction',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-schema-head',
    'TestInitialInstallationWithRealServices/initial-runtime-bridge-sql-schema-unapplied',
    'TestInitialInstallationWithRealServices/interrupted-audit-resumes-same-attempt',
    'TestInitialInstallationWithRealServices/older-observation-cannot-replace-preparation-watermark',
    'TestInitialInstallationWithRealServices/original-deadline-survives-lock-wait',
    'TestInitialInstallationWithRealServices/owner-identity-roles-constructor-bridge-contention',
    'TestInitialInstallationWithRealServices/owner-identity-roles-constructor-expired-source',
    'TestInitialInstallationWithRealServices/owner-identity-roles-held-lock',
    'TestInitialInstallationWithRealServices/owner-identity-roles-lost-completion',
    'TestInitialInstallationWithRealServices/owner-identity-roles-matrix',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-changed',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-expired',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-final-change',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-final-expired',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-final-recovery',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-contention-final-renewed',
    'TestInitialInstallationWithRealServices/owner-identity-roles-observation-unknown-commit',
    'TestInitialInstallationWithRealServices/owner-identity-roles-recovery-after-lock',
    'TestInitialInstallationWithRealServices/owner-identity-roles-root-after-lock',
    'TestInitialInstallationWithRealServices/owner-identity-roles-runtime-administrator-denied',
    'TestInitialInstallationWithRealServices/owner-identity-roles-unknown-claim',
    'TestInitialInstallationWithRealServices/owner-identity-roles-verification-root-after-lock',
    'TestInitialInstallationWithRealServices/production-sql-role-provisioning-and-retirement',
    'TestInitialInstallationWithRealServices/public-runtime-roles-held-lock',
    'TestInitialInstallationWithRealServices/public-runtime-roles-lost-completion',
    'TestInitialInstallationWithRealServices/public-runtime-roles-lost-completion/capture-preview-generated-role-effects',
    'TestInitialInstallationWithRealServices/public-runtime-roles-lost-completion/capture-resolution-generated-role-effects',
    'TestInitialInstallationWithRealServices/public-runtime-roles-matrix',
    'TestInitialInstallationWithRealServices/public-runtime-roles-matrix/capture-preview-generated-role-effects',
    'TestInitialInstallationWithRealServices/public-runtime-roles-matrix/capture-resolution-generated-role-effects',
    'TestInitialInstallationWithRealServices/public-runtime-roles-recovery-after-lock',
    'TestInitialInstallationWithRealServices/public-runtime-roles-unknown-claim',
    'TestInitialInstallationWithRealServices/purpose-roles-cannot-cross-write',
    'TestInitialInstallationWithRealServices/reject-missing-version-before-initial-audit-ack',
    'TestInitialInstallationWithRealServices/reject-null-version-before-initial-audit-ack',
    'TestInitialInstallationWithRealServices/schema-inventory-and-row-security-deny',
    'TestInitialInstallationWithRealServices/source-or-incarnation-substitution-denies',
]
MODES = {
    'owner': (['python3', 'scripts/test-context-storage.py', '--initial-bootstrap-chain',
               '--runtime-provider-pair', '--runtime-provider-worker', '--runtime-provider-owner'], 'context-storage'),
    'initial-installation': (['make', 'initial-installation-integration', 'PYTHON=' + str(PYTHON)], 'initial-installation'),
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
    if mode == 'initial-installation':
        return INITIAL_REQUIRED
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


# New native mode only: retain the reviewed process-group cleanup pattern.
# A signal records cancellation; repeated signals cannot interrupt final joining.
interrupted = None


def interrupt(signum, frame):
    global interrupted
    if interrupted is None:
        interrupted = signum


def group_exists(child):
    if child is None:
        return False
    try:
        os.killpg(child.pid, 0)
        return True
    except ProcessLookupError:
        return False


def join_owned(child):
    if child is None:
        return True
    def send(signum):
        try:
            os.killpg(child.pid, signum)
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
    if args.mode == 'initial-installation':
        signal.signal(signal.SIGINT, interrupt)
        signal.signal(signal.SIGTERM, interrupt)
    child = None
    output = ROOT / 'test/results' / args.output_name
    output.mkdir()
    tmp = CACHE / (args.output_name + '-tmp')
    tmp.mkdir()
    snapshot = freeze
    if args.mode == 'initial-installation':
        def snapshot():
            state = freeze()
            for folder in ('docs', 'examples', 'design', 'web'):
                state.update({str(p.relative_to(ROOT)): sha(p) for p in (ROOT / folder).rglob('*')
                              if p.is_file() and 'node_modules' not in p.parts and '__pycache__' not in p.parts})
            for name in ('README.md', 'AGENTS.md', '.gitignore'):
                state[name] = sha(ROOT / name)
            return state
    baseline = snapshot()
    save(output / 'sources.json', baseline)
    if args.mode == 'initial-installation':
        (output / 'runner.py').write_bytes(Path(__file__).read_bytes())
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
        if snapshot() != baseline:
            raise RuntimeError('source changed before launch')
        if args.mode == 'initial-installation':
            source = (ROOT / 'test/integration/initial_installation_test.go').read_text()
            if 'context.WithTimeout(context.Background(), 180*time.Second)' not in source:
                raise RuntimeError('original initial-installation parent budget changed')
            if sha(Path(__file__)) != report['runnerSHA256']:
                raise RuntimeError('qualification runner changed before launch')
            if interrupted is not None:
                raise InterruptedError('qualification signal ' + str(interrupted))
        start = time.monotonic()
        with (output / 'gate.log').open('x') as log:
            if args.mode == 'initial-installation':
                child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                report.update(processPID=child.pid, processGroup=child.pid)
                print(json.dumps({'mode': args.mode, 'pid': child.pid, 'processGroup': child.pid}), flush=True)
                while child.poll() is None:
                    if interrupted is not None:
                        raise InterruptedError('qualification signal ' + str(interrupted))
                    time.sleep(.1)
                child.wait()
                run = child
                report['processGroupAbsentAfterCommand'] = not group_exists(child)
            else:
                run = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        report.update(processJoined=True, commandExit=run.returncode, seconds=round(time.monotonic() - start, 3))
        errors = report['validationErrors']
        if run.returncode:
            errors.append('gate command failed')
        if args.mode == 'initial-installation' and not report['processGroupAbsentAfterCommand']:
            errors.append('native command left an owned process group')
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
            elif args.mode == 'initial-installation':
                archived_log = (output / 'initial-installation.log').read_text()
                logged = re.findall(r'^\s*--- PASS: (Test\S+) \([0-9]+(?:\.[0-9]+)?s\)$', archived_log, re.M)
                failures = re.findall(r'^\s*--- (?:FAIL|SKIP): (Test\S+)', archived_log, re.M)
                report['exactSelectedPASSNames'] = (len(logged) == len(required) and set(logged) == set(required)
                                                    and len(names) == len(required) and set(names) == set(required))
                report['failedOrSkippedTests'] = failures
                if not report['exactSelectedPASSNames'] or failures:
                    errors.append('full original initial-installation parent/leaves missing, skipped or changed')
                if (native.get('testPattern') != '^' + INITIAL_TEST + '$'
                        or native.get('goTestTimeoutSeconds') != 300
                        or native.get('harnessTestTimeoutSeconds') != 360
                        or native.get('connectorRetirementRealtime') is not False
                        or len(native.get('phases', [])) != 1
                        or native['phases'][0].get('phase') != 'suite'
                        or native['phases'][0].get('testExit') != 0
                        or native['phases'][0].get('qualificationExit') != 0
                        or set(native['phases'][0].get('passedTestNames', [])) != set(required)):
                    errors.append('original fresh-fixture selection or aggregate budgets changed')
                suffixes = {name.rsplit('-', 1)[-1] for name in native.get('images', {})}
                if suffixes != {'postgres', 's3', 'kms'} or len(native.get('images', {})) != 3:
                    errors.append('exact fresh PostgreSQL/S3/OpenBao fixture absent')
                containers = list(native['images'])
                pg = [name for name in containers if name.endswith('-postgres')]
                if len(pg) != 1 or not pg[0].startswith('asservat-custody-'):
                    raise RuntimeError('initial-installation owned scratch identity absent')
                fixture_scratch = CACHE / pg[0][len('asservat-'):-len('-postgres')]
                report['fixtureScratch'] = str(fixture_scratch)
                report['fixtureScratchRemoved'] = not fixture_scratch.exists()
                if not report['fixtureScratchRemoved']:
                    errors.append('owned fresh-fixture scratch still present')
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
        if args.mode == 'initial-installation':
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            report['signalReceived'] = interrupted
            report['runnerUnchanged'] = sha(Path(__file__)) == report['runnerSHA256']
            if not report['runnerUnchanged']:
                code = 1
            if interrupted is not None:
                code = 1
            try:
                report['finalProcessGroupAbsent'] = join_owned(child)
                report['processJoined'] = child is not None and child.poll() is not None
            except Exception as exc:
                report['finalProcessGroupAbsent'] = False
                report['joinError'] = str(exc)
            if not report['finalProcessGroupAbsent']:
                code = 1
        report['sourceSnapshotUnchanged'] = snapshot() == baseline
        if not report['sourceSnapshotUnchanged']:
            code = 1
        try:
            if args.mode == 'initial-installation' and not report['finalProcessGroupAbsent']:
                raise OSError('owned process group not joined; scratch retained')
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
