#!/usr/bin/env python3
"""Run one parent-allocated gate; staging this file performs no qualification."""
from pathlib import Path
from collections import Counter
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
FRESHNESS_TEST = 'TestEnrollmentFleetFreshnessWithRealPostgres'
FRESHNESS_PATTERN = '^' + FRESHNESS_TEST + '$'
FRESHNESS_REQUIRED = [
    'TestEnrollmentFleetFreshnessWithRealPostgres',
    'TestEnrollmentFleetFreshnessWithRealPostgres/aba-and-repeated-fence-never-revive-old-basis',
    'TestEnrollmentFleetFreshnessWithRealPostgres/actual-activation-seeds-once-and-replay-never-renews',
    'TestEnrollmentFleetFreshnessWithRealPostgres/adapter-confirms-only-unchanged-authority-contention',
    'TestEnrollmentFleetFreshnessWithRealPostgres/exact-lock-disposition-authority',
    'TestEnrollmentFleetFreshnessWithRealPostgres/exact-lock-disposition-observation',
    'TestEnrollmentFleetFreshnessWithRealPostgres/exact-lock-disposition-table',
    'TestEnrollmentFleetFreshnessWithRealPostgres/expired-positive-basis-still-fences-original-semantic-root',
    'TestEnrollmentFleetFreshnessWithRealPostgres/failure-fence-waits-for-current-share',
    'TestEnrollmentFleetFreshnessWithRealPostgres/initial-activation-table-order-does-not-invert-semantic-row',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-fences-existing-root-without-observation-backfill',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-preserves-unrelated-reader-and-lock-grants',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-default-function',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-default-references',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-default-table',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-default-trigger',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-global-writer-member',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-column',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-inherited',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-public',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-references',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-table',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-legacy-trigger',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-retained-foreign-key',
    'TestEnrollmentFleetFreshnessWithRealPostgres/migration-refuses-retained-trigger',
    'TestEnrollmentFleetFreshnessWithRealPostgres/missing-root-never-seeds-current-observation',
    'TestEnrollmentFleetFreshnessWithRealPostgres/original-basis-expiry-survives-lock-wait',
    'TestEnrollmentFleetFreshnessWithRealPostgres/pristine-inventory-rejects-unactivated-observation-row',
    'TestEnrollmentFleetFreshnessWithRealPostgres/restrictive-source-waits-for-current-share',
    'TestEnrollmentFleetFreshnessWithRealPostgres/runtime-cannot-write-base-or-positive-row',
    'TestEnrollmentFleetFreshnessWithRealPostgres/unchanged-renewal-coexists-with-current-share',
]
PYTHON = CACHE / 'spec-venv/bin/python'
MODES = {name: (['make', name + '-integration', 'PYTHON=' + str(PYTHON)], name)
         for name in ('initial-installation', 'database-recovery', 'fleet', 'custody')}
PATTERNS = {'fleet': 'Test(Enrollment|PeerRegistry|ConnectorPKI|BootstrapChannel|InitialProviderIssuer)',
            'custody': 'Test(Custody|PermissionAuthority|ContextAdmission|PeerRegistry|Enrollment)',
            'initial-installation': '^TestInitialInstallationWithRealServices$',
            'database-recovery': '^TestDatabaseRecoveryAfterRestartAndRestore$'}
CUSTODY_EXPECTED_SKIPS = {'TestEnrollmentOwnerPKIWithRealServices',
                        'TestEnrollmentOwnerBootstrapPKIWithRealServices',
                        'TestContextAdmissionWithRealServices/connector-identity-real-time-retirement'}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def save(p, value):
    with p.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')

def freeze():
    files = {ROOT / n for n in ('Makefile', 'go.mod', 'go.sum', 'sqlc.yaml', 'requirements-spec.txt')}
    for folder in ('api', 'cmd', 'internal', 'migrations', 'test/integration', 'test/fixtures', 'scripts', 'charts/asservat', 'specs'):
        files.update((p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts))
    files.add(ROOT / 'docs/architecture/catalog.yaml')
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}

def harness_freeze(mode):
    files = {ROOT / n for n in ('go.mod', 'go.sum')}
    for folder, patterns in [('cmd', ('*.go',)), ('internal', ('*.go', '*.json')), ('migrations', ('*.sql', '*.go')), ('test/integration', ('*.go',)), ('test/fixtures', ('*.sql',))]:
        for pattern in patterns:
            files.update((ROOT / folder).rglob(pattern))
    files.update(ROOT / n for n in ('sqlc.yaml', 'scripts/test-custody.py'))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}

def required_names(mode):
    if mode == 'database-recovery':
        return ['TestDatabaseRecoveryAfterRestartAndRestore']
    if mode == 'initial-installation':
        parent = 'TestInitialInstallationWithRealServices'
        caller = (ROOT / 'test/integration/initial_installation_test.go').read_text().split('func ' + parent + '(t *testing.T) {', 1)[1]
        leaves = re.findall(r'\bt.Run\("([^"+]+)",', caller)
        leaves.remove('native-witness-source-and-provider-composition')
        leaves += ['reject-missing-version-before-initial-audit-ack', 'reject-null-version-before-initial-audit-ack']
        for values, prefix in re.findall(r'for _, mode := range \[\]string\{([^}]+)\} \{\s*t.Run\("([^"+]+)"\+mode,', caller):
            if prefix != 'installer-pod-':
                leaves += [prefix + mode for mode in re.findall(r'"([^"]+)"', values)]
        historical = re.findall(r'\bt.Run\("(historical-[^"]+)",', (ROOT / 'test/integration/initial_installation_read_test.go').read_text())
        if len(historical) != 4 or 'history.qualifyBoundsAndRole(t, ctx, admin, s.scope.InstallationID)' not in caller:
            raise RuntimeError('reviewed historical initial-installation call graph changed')
        leaves += ['audit-witness-and-later-recovery-block/' + name for name in historical]
        roles = (ROOT / 'test/integration/public_runtime_roles_test.go').read_text()
        draft = (ROOT / 'test/integration/public_context_preview_roles_test.go').read_text()
        if 'qualifyPublicContextDraftRole(t, ctx, admin, conn, role.Purpose, input.InstallationID)' not in roles or 't.Run(purpose+"-generated-role-effects"' not in draft:
            raise RuntimeError('reviewed generated-role initial-installation call graph changed')
        for mode in ('matrix', 'lost-completion'):
            for purpose in ('capture-preview', 'capture-resolution'):
                leaves += ['public-runtime-roles-' + mode + '/' + purpose + '-generated-role-effects']
        names = [parent] + [parent + '/' + leaf for leaf in leaves]
        if len(names) != 87 or len(set(names)) != len(names):
            raise RuntimeError('full initial-installation inventory requires review')
        return sorted(names)
    selected = set()
    for p in (ROOT / 'test/integration').glob('*_test.go'):
        selected.update(name for name in re.findall(r'^func (Test\w+)\(t \*testing.T\)', p.read_text(), re.M) if re.search(PATTERNS[mode], name))
    if mode == 'custody':
        selected -= CUSTODY_EXPECTED_SKIPS
    if FRESHNESS_TEST not in selected:
        raise RuntimeError('full suite omitted the newly integrated SQL59 parent')
    selected.update(FRESHNESS_REQUIRED)
    return sorted(selected)


def docker_cleanup(native, mode):
    containers = list(native['images'])
    pg = [n for n in containers if n.endswith('-postgres')]
    if len(pg) != 1 or not pg[0].startswith('asservat-custody-'):
        raise RuntimeError('owned database identity absent')
    label = pg[0][len('asservat-'):-len('-postgres')]
    services = ('postgres', 's3', 'kms') if mode in ('fleet', 'initial-installation') else ('postgres', 's3')
    if set(containers) != {'asservat-' + label + '-' + role for role in services}:
        raise RuntimeError('exact owned fleet fixture service set changed')
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
            time.sleep(0.05)
    return child.poll() is not None and (not group_exists(child))

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
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    child = None
    output = ROOT / 'test/results' / args.output_name
    output.mkdir()
    tmp = CACHE / (args.output_name + '-tmp')
    tmp.mkdir()

    def snapshot():
        state = freeze()
        for folder in ('docs', 'examples', 'design', 'web'):
            state.update({str(p.relative_to(ROOT)): sha(p) for p in (ROOT / folder).rglob('*') if p.is_file() and 'node_modules' not in p.parts and ('__pycache__' not in p.parts)})
        for name in ('README.md', 'AGENTS.md', '.gitignore'):
            state[name] = sha(ROOT / name)
        return state
    baseline = snapshot()
    save(output / 'sources.json', baseline)
    (output / 'runner.py').write_bytes(Path(__file__).read_bytes())
    command, prefix = MODES[args.mode]
    expected = harness_freeze(args.mode)
    required = required_names(args.mode)
    save(output / 'expected-harness-sources.json', expected)
    env = dict(os.environ, XDG_CACHE_HOME=str(CACHE.parent), GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp), ASSERVAT_BUILD_TMP=str(tmp), PYTHONDONTWRITEBYTECODE='1')
    for k in tuple(env):
        if k.startswith('ASSERVAT_') and k != 'ASSERVAT_BUILD_TMP':
            env.pop(k)
    report = {'mode': args.mode, 'qualificationScope': 'full existing ' + args.mode + ' target after SQL59 integration; retains explicit synthetic fixture authority and does not qualify installed owner/public-runtime composition', 'command': command, 'runnerSHA256': sha(Path(__file__)), 'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'sourceCount': len(baseline), 'sourceSnapshotSHA256': sha(output / 'sources.json'), 'expectedHarnessSourceCount': len(expected), 'requiredPassedTests': required, 'expectedSkippedTests': sorted(CUSTODY_EXPECTED_SKIPS) if args.mode == 'custody' else [], 'excludedNativeQualifications': ['Kubernetes installer Pod and native witness/source composition', 'installed owner runtime and provider projections', 'regional capture/public journey/native transfer', 'separately opted-in 31-minute connector retirement'], 'scratch': str(tmp), 'validationErrors': [], 'processJoined': False}
    code = 1
    try:
        report['diskBeforeBytes'] = shutil.disk_usage(ROOT).free
        report['tmpFreeBeforeBytes'] = shutil.disk_usage('/tmp').free
        if report['diskBeforeBytes'] < 32 * (1 << 30):
            raise RuntimeError('less than 32 GiB free before gate')
        old = {p.name: (p.stat().st_mtime_ns, sha(p)) for p in (ROOT / 'test/results').glob(prefix + '*') if p.is_file()}
        if snapshot() != baseline:
            raise RuntimeError('source changed before launch')
        source = (ROOT / 'test/integration/fleet_freshness_native_test.go').read_text()
        for marker in ('context.WithTimeout(context.Background(), 180*time.Second)', 'func TestEnrollmentFleetFreshnessWithRealPostgres(t *testing.T)', "func qualifyFleetFreshnessMigrationACLs("):
            if marker not in source:
                raise RuntimeError('original SQL59 selection or parent budget changed')
        reviewed_path = Path(__file__).with_name('reviewed-payloads.json')
        reviewed = json.loads(reviewed_path.read_text())
        report['reviewedPayloadsSHA256'] = sha(reviewed_path)
        report['reviewedPayloadsMatch'] = all((baseline.get(p) == h for p, h in reviewed.items()))
        if not report['reviewedPayloadsMatch']:
            raise RuntimeError('reviewed SQL59 payload changed before launch')
        shutil.copyfile(reviewed_path, output / reviewed_path.name)
        if sha(Path(__file__)) != report['runnerSHA256']:
            raise RuntimeError('qualification runner changed before launch')
        if interrupted is not None:
            raise InterruptedError('qualification signal ' + str(interrupted))
        start = time.monotonic()
        with (output / 'gate.log').open('x') as log:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            report.update(processPID=child.pid, processGroup=child.pid)
            print(json.dumps({'mode': args.mode, 'pid': child.pid, 'processGroup': child.pid}), flush=True)
            while child.poll() is None:
                if interrupted is not None:
                    raise InterruptedError('qualification signal ' + str(interrupted))
                time.sleep(0.1)
            child.wait()
            run = child
            report['processGroupAbsentAfterCommand'] = not group_exists(child)
        report.update(processJoined=True, commandExit=run.returncode, seconds=round(time.monotonic() - start, 3))
        errors = report['validationErrors']
        if run.returncode:
            errors.append('gate command failed')
        if not report['processGroupAbsentAfterCommand']:
            errors.append('native command left an owned process group')
        for p in (ROOT / 'test/results').glob(prefix + '*'):
            if p.is_file() and old.get(p.name) != (p.stat().st_mtime_ns, sha(p)):
                shutil.copyfile(p, output / p.name)
        native_path = output / (prefix + '-environment.json')
        if not native_path.exists():
            raise RuntimeError('fresh native report absent')
        native = json.loads(native_path.read_text())
        names = native.get('passedTests', native.get('passedTestNames', []))
        if not isinstance(names, list) or any((not isinstance(n, str) for n in names)):
            names = []
        report.update(passedTests=names, missingRequiredTests=sorted(set(required) - set(names)), cleanupFailures=native.get('cleanupFailures'), testExit=native.get('testExit'), exactHarnessSources=native.get('sourceHashes') == expected)
        if report['missingRequiredTests']:
            errors.append('missing required selected PASS names')
        if native.get('testExit') != 0 or native.get('sourceUnchangedDuringTest') is not True:
            errors.append('native test exit/source stability failed')
        if native.get('sourceHashes') != expected:
            errors.append('native source hashes or exact file set differ from independent closure')
        if native.get('cleanupFailures') != []:
            errors.append('native cleanup missing or failed')
        archived_log = (output / (prefix + '.log')).read_text()
        logged = re.findall('^\\s*--- PASS: (Test\\S+) \\([0-9]+(?:\\.[0-9]+)?s\\)$', archived_log, re.M)
        started = re.findall('^=== RUN   (Test\\S+)\\s*$', archived_log, re.M)
        failures = re.findall(r'^\s*--- FAIL: (Test\S+)', archived_log, re.M)
        skipped = re.findall(r'^\s*--- SKIP: (Test\S+)', archived_log, re.M)
        expected_skips = CUSTODY_EXPECTED_SKIPS if args.mode == 'custody' else set()
        expected_phases = ['initial', 'restarted', 'restored'] if args.mode == 'database-recovery' else ['suite']
        phases = native.get('phases', [])
        inventory_ok = not failures and set(skipped) == expected_skips and len(skipped) == len(expected_skips)
        inventory_ok = inventory_ok and Counter(started) == Counter(logged) + Counter(skipped) and Counter(logged) == Counter(names)
        inventory_ok = inventory_ok and set(required) <= set(names)
        if args.mode == 'database-recovery':
            inventory_ok = inventory_ok and Counter(names) == Counter({required[0]: 3})
        elif args.mode == 'initial-installation':
            inventory_ok = inventory_ok and Counter(names) == Counter(required)
        else:
            inventory_ok = inventory_ok and len(names) == len(set(names))
            inventory_ok = inventory_ok and {x for x in names if '/' not in x} == {x for x in required if '/' not in x}
        report.update(requiredLogTests=required, startedTests=started, loggedPassedTests=logged,
                      skippedTests=skipped, failedTests=failures, completeSelectedInventory=inventory_ok)
        if not inventory_ok:
            errors.append('full selected RUN/PASS/expected-SKIP inventory failed')
        timeout = 900 if args.mode == 'custody' else 300
        if native.get('testPattern') != PATTERNS[args.mode] or native.get('goTestTimeoutSeconds') != timeout or native.get('harnessTestTimeoutSeconds') != timeout + 60 or native.get('connectorRetirementRealtime') is not False:
            errors.append('full existing target selection or aggregate budget changed')
        phase_ok = [p.get('phase') for p in phases] == expected_phases
        phase_ok = phase_ok and all(p.get('testExit') == 0 and p.get('qualificationExit') == 0 for p in phases)
        phase_ok = phase_ok and [name for p in phases for name in p.get('passedTestNames', [])] == names
        if args.mode == 'database-recovery' and phase_ok:
            phase_ok = all(p.get('passedTestNames') == required for p in phases)
            initial, restarted, restored = [p['incarnation'] for p in phases]
            phase_ok = phase_ok and initial['serverStart'] != restarted['serverStart'] and initial['databaseOID'] == restarted['databaseOID']
            phase_ok = phase_ok and restarted['serverStart'] == restored['serverStart'] and restarted['databaseOID'] != restored['databaseOID']
            report['databaseIncarnations'] = [p['incarnation'] for p in phases]
        report['completeOriginalPhases'] = phase_ok
        if not phase_ok:
            errors.append('complete original native phase/real incarnation evidence failed')
        images = native.get('images', {})
        report['actualFixtureImages'] = images
        if any(not re.fullmatch('sha256:[a-f0-9]{64}', v.get('imageID', '')) or not re.fullmatch('[a-f0-9]{64}', v.get('containerID', '')) for v in images.values()):
            errors.append('actual fixture image/container identity absent')
        pg = [name for name in images if name.startswith('asservat-custody-') and name.endswith('-postgres')]
        if len(pg) != 1:
            raise RuntimeError('owned native fixture identity absent')
        label = pg[0][len('asservat-'):-len('-postgres')]
        fixture_scratch = CACHE / label
        report['fixtureScratch'] = str(fixture_scratch)
        report['fixtureScratchRemoved'] = not fixture_scratch.exists()
        if not report['fixtureScratchRemoved']:
            errors.append('owned native fixture scratch still present')
        report['ownedDockerCleanup'] = docker_cleanup(native, args.mode)
        code = 0 if not errors else 1
    except Exception as exc:
        report['runnerError'] = str(exc)
    finally:
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
            if not report['finalProcessGroupAbsent']:
                raise OSError('owned process group not joined; scratch retained')
            tmp.rmdir()
            report['emptyScratchRemoved'] = True
        except OSError:
            report['emptyScratchRemoved'] = False
            code = 1
        report['archiveHashes'] = {str(p.relative_to(output)): sha(p) for p in output.rglob('*') if p.is_file()}
        report['exit'] = code
        save(output / 'result.json', report)
        print(json.dumps({'mode': args.mode, 'exit': code, 'seconds': report.get('seconds'), 'validationErrors': report['validationErrors'], 'runnerError': report.get('runnerError')}), flush=True)
    return code
if __name__ == '__main__':
    raise SystemExit(main())
