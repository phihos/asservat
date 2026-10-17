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
JOURNEY_TEST = 'TestContextAdmissionWithRealServices'
JOURNEY_LEAF = JOURNEY_TEST + '/native-regional-api-journey'
JOURNEY_REQUIRED = [JOURNEY_TEST, JOURNEY_LEAF]
JOURNEY_PATTERN = '^TestContextAdmissionWithRealServices$/^native-regional-api-journey$'
MODES = {'journey': (['python3', 'scripts/test-context-storage.py', '--regional-context-start', 'journey'], 'context-storage')}

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
    files.update((ROOT / n for n in ('scripts/test-context-storage.py', 'scripts/helm_registry.py')))
    files.update((ROOT / 'test/fixtures').rglob('*.go'))
    files.update((p for p in (ROOT / 'charts/asservat').rglob('*') if p.is_file()))
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(files)}

def required_names(mode):
    # Slash-selected context harness reports only the child; actual log must
    # contain exactly both parent and child RUN/PASS (checked independently).
    return [JOURNEY_LEAF]


def docker_cleanup(native, mode):
    tag = native['workerBuild']['tag']
    if not tag.startswith('asservat-context-worker:context-'):
        raise RuntimeError('unexpected owned image tag')
    label = tag.split(':', 1)[1]
    clusters = [c['name'] + '-control-plane' for c in native['clusters']]
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
    parser.add_argument('--mode', default='journey', choices=MODES)
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
    report = {'mode': args.mode, 'command': command, 'runnerSHA256': sha(Path(__file__)), 'bootID': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'sourceCount': len(baseline), 'sourceSnapshotSHA256': sha(output / 'sources.json'), 'expectedHarnessSourceCount': len(expected), 'requiredPassedTests': required, 'expectedSkippedTests': [], 'scratch': str(tmp), 'validationErrors': [], 'processJoined': False}
    code = 1
    try:
        report['diskBeforeBytes'] = shutil.disk_usage(ROOT).free
        report['tmpFreeBeforeBytes'] = shutil.disk_usage('/tmp').free
        if report['diskBeforeBytes'] < 32 * (1 << 30):
            raise RuntimeError('less than 32 GiB free before gate')
        old = {p.name: (p.stat().st_mtime_ns, sha(p)) for p in (ROOT / 'test/results').glob(prefix + '*') if p.is_file()}
        if snapshot() != baseline:
            raise RuntimeError('source changed before launch')
        source = (ROOT / 'test/integration/capture_admission_test.go').read_text()
        for marker in ('limit := 3 * time.Minute', 'ctx, stop = context.WithTimeout(ctx, limit)', 'name = "native-regional-api-" + regional'):
            if marker not in source:
                raise RuntimeError('original journey selection or parent budget changed')
        reviewed_path = Path(__file__).with_name('reviewed-payloads.json')
        reviewed = json.loads(reviewed_path.read_text())
        report['reviewedPayloadsSHA256'] = sha(reviewed_path)
        report['reviewedPayloadsMatch'] = all((baseline.get(p) == h for p, h in reviewed.items()))
        if not report['reviewedPayloadsMatch']:
            raise RuntimeError('reviewed journey payload changed before launch')
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
        archived_log = (output / 'context-storage.log').read_text()
        logged = re.findall('^\\s*--- PASS: (Test\\S+) \\([0-9]+(?:\\.[0-9]+)?s\\)$', archived_log, re.M)
        started = re.findall('^=== RUN   (Test\\S+)\\s*$', archived_log, re.M)
        failures = re.findall('^\\s*--- (?:FAIL|SKIP): (Test\\S+)', archived_log, re.M)
        report['requiredLogTests'] = JOURNEY_REQUIRED
        report['startedTests'] = started
        report['loggedPassedTests'] = logged
        report['exactSelectedRUNAndPASSNames'] = len(logged) == len(JOURNEY_REQUIRED) and set(logged) == set(JOURNEY_REQUIRED) and (len(started) == len(JOURNEY_REQUIRED)) and (set(started) == set(JOURNEY_REQUIRED)) and (names == [JOURNEY_LEAF])
        report['failedOrSkippedTests'] = failures
        if not report['exactSelectedRUNAndPASSNames'] or failures:
            errors.append('exact journey parent/leaf RUN/PASS inventory failed')
        if native.get('testPattern') != JOURNEY_PATTERN or native.get('testPackage') != './test/integration' or native.get('aggregateGoTimeout') != '10m (Go default)' or (native.get('bootstrapFixtureSeconds') is not None) or (native.get('regionalContextStartQualification') != 'journey') or (native.get('fixtureMigratesDatabase') is not True):
            errors.append('original journey path or aggregate budget changed')
        non_journey_flags = ('runtimeProviderPairQualification', 'runtimeProviderWorkerQualification', 'runtimeProviderOwnerQualification', 'runtimeObjectRoundTripQualification', 'ownerProviderAuthenticationQualification', 'initialHandoverQualification', 'initialSchemaHandoverQualification', 'initialBootstrapChainQualification', 'helmBootstrapQualification')
        if any((native.get(k) is not False for k in non_journey_flags)):
            errors.append('unselected native qualification flag enabled or absent')
        build = native.get('workerBuild', {})
        if not re.fullmatch('[a-f0-9]{64}', build.get('binarySHA256', '')) or not re.fullmatch('sha256:[a-f0-9]{64}', build.get('dockerImageID', '')):
            errors.append('actual built product binary/image identity absent')
        report['actualWorkerBuild'] = build
        tag = build.get('tag', '')
        if not re.fullmatch('asservat-context-worker:context-[a-z0-9-]+', tag):
            raise RuntimeError('journey owned fixture identity absent')
        label = tag.split(':', 1)[1]
        clusters = native.get('clusters', [])
        cluster_names = [c.get('name') for c in clusters]
        if cluster_names != ['asservat-' + label + '-' + str(i) for i in range(2)]:
            errors.append('exact two owned journey clusters absent or changed')
        for name in cluster_names:
            if not isinstance(name, str) or not name.startswith('asservat-' + label + '-'):
                continue
            diagnostic = ROOT / 'test/results' / (name + '-logs')
            if diagnostic.is_dir():
                shutil.copytree(diagnostic, output / diagnostic.name)
        # tempfile suffixes can contain '_' before the fixture normalizes its
        # Docker label. Check every exact normalization preimage, not just the
        # label-named path, to avoid falsely declaring original scratch absent.
        remaining_scratch = [str(p) for p in CACHE.glob('context-*')
                             if p.name.replace('_', '-') == label]
        report['fixtureScratchLabel'] = label
        report['remainingFixtureScratch'] = remaining_scratch
        report['fixtureScratchRemoved'] = not remaining_scratch
        if not report['fixtureScratchRemoved']:
            errors.append('owned journey fixture scratch still present')
        if native.get('buildScratch') is not None:
            errors.append('journey unexpectedly selected separate bootstrap build scratch')
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
