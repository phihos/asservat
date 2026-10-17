from pathlib import Path
import hashlib, json, os, re, shutil, signal, subprocess, tempfile, time

stage = Path(__file__).resolve().parent
repo = Path('/home/phil/Projekte/asservat')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
maps = {n: json.loads((stage / (n + '.json')).read_text()) for n in ['payload', 'bases', 'dependencies', 'freeze']}
mirror = None
mirror_map = {**maps['dependencies'], **maps['payload']}

def live_paths():
    paths = set(subprocess.check_output(['rg', '--files', '-g', '*.go', '-g', 'go.mod', '-g', 'go.sum'], cwd=repo, text=True).splitlines())
    for directory in ['internal', 'api', 'cmd', 'migrations', 'test/fixtures/sql']:
        paths.update(subprocess.check_output(['rg', '--files', directory], cwd=repo, text=True).splitlines())
    paths.update(['Makefile', 'scripts/check-go-architecture.py', 'docs/architecture/catalog.yaml', 'scripts/test-context-storage.py', 'scripts/helm_registry.py'])
    return paths

def check():
    state = {
        'dependencies': [k for k, v in maps['dependencies'].items() if sha(repo / k) != v],
        'bases': [k for k, v in maps['bases'].items() if sha(repo / k) != v],
        'payload': [k for k, v in maps['payload'].items() if sha(stage / 'files' / k) != v],
        'liveFileSet': sorted(live_paths() ^ set(maps['dependencies'])),
        'payloadFileSet': sorted({str(p.relative_to(stage / 'files')) for p in (stage / 'files').rglob('*') if p.is_file()} ^ set(maps['payload'])),
        'freeze': [k for k, v in maps['freeze'].items() if sha(stage / k) != v],
    }
    if mirror is not None:
        state['mirror'] = [k for k, v in mirror_map.items() if sha(mirror / k) != v]
        state['mirrorFileSet'] = sorted({str(p.relative_to(mirror)) for p in mirror.rglob('*') if p.is_file()} ^ set(mirror_map))
    return state

# Existing reports are never overwritten, even by a mistaken repeated launch.
evidence = stage / 'evidence'
evidence.mkdir(exist_ok=False)
initial = check()
(evidence / 'preflight.json').write_text(json.dumps(initial, indent=2) + '\n')
if any(initial.values()):
    raise SystemExit('immutable source preflight mismatch')
free = shutil.disk_usage('/tmp').free
if free < 4 * 1024**3 or subprocess.check_output(['stat', '-f', '-c', '%T', '/tmp'], text=True).strip() != 'tmpfs':
    raise SystemExit('owned tmpfs scratch requires at least 4 GiB free')
scratch = Path(tempfile.mkdtemp(prefix='asservat-direct-diagnostic-', dir='/tmp'))
if scratch.stat().st_uid != os.getuid() or scratch.stat().st_mode & 0o777 != 0o700:
    raise SystemExit('invalid owned scratch')
(evidence / 'scratch.json').write_text(json.dumps({'path': str(scratch), 'uid': os.getuid(), 'mode': '0700', 'freeBefore': free}, indent=2) + '\n')
env = os.environ.copy()
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(scratch), PYTHONDONTWRITEBYTECODE='1')
for key in list(env):
    if key.startswith('ASSERVAT_') and ('FIXTURE' in key or 'NATIVE' in key):
        del env[key]
reports, terminal = [], 1

def phase(name, command, cwd=None, additional_env=None):
    before = check()
    if any(before.values()):
        (evidence / (name + '-preflight.json')).write_text(json.dumps(before, indent=2) + '\n')
        raise RuntimeError('changed frozen source')
    start = time.monotonic()
    with (evidence / (name + '.log')).open('x') as log:
        child = subprocess.Popen(command, cwd=cwd or mirror, env={**env, **(additional_env or {})}, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
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
    text = (evidence / (name + '.log')).read_text()
    report = {'phase': name, 'command': command, 'exit': code, 'seconds': round(time.monotonic() - start, 3), 'before': before, 'after': after, 'namedPass': len(re.findall(r'^\s*--- PASS:', text, re.M)), 'skips': len(re.findall(r'^\s*--- SKIP:', text, re.M))}
    (evidence / (name + '.json')).write_text(json.dumps(report, indent=2) + '\n')
    reports.append(report)
    print(json.dumps(report), flush=True)
    if code != 0 or any(after.values()):
        raise RuntimeError('phase failed: ' + name)
    if name == 'fixture-tests' and (report['namedPass'] != 14 or report['skips']):
        raise RuntimeError('closed-label and parity tests not actually exercised')

try:
    mirror = scratch / 'mirror'
    mirror.mkdir()
    for path, digest in mirror_map.items():
        source = stage / 'files' / path if path in maps['payload'] else repo / path
        if sha(source) != digest:
            raise RuntimeError('changed mirror source: ' + path)
        target = mirror / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != digest:
            raise RuntimeError('mirror copy changed: ' + path)
    (evidence / 'mirror-manifest.json').write_text(json.dumps(mirror_map, indent=2, sort_keys=True) + '\n')
    sources = [str(mirror / 'test/fixtures/observation-native' / n) for n in ['data.go', 'enrollment.go', 'inputs.go', 'main.go', 'metrics.go', 'runtime.go']]
    phase('compile-helper', ['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(scratch / 'observation-native'), *sources], additional_env={'CGO_ENABLED': '0'})
    phase('compile-integration', ['go', 'test', '-c', '-vet=off', '-o', str(scratch / 'integration.test'), './test/integration'])
    phase('fixture-tests', [str(scratch / 'integration.test'), '-test.run=^TestDirectNativeFixture(WireParity|DiagnosticLabels)$', '-test.v', '-test.timeout=60s'], cwd=mirror / 'test/integration')
    phase('vet-helper', ['go', 'vet', *sources])
    phase('vet-integration', ['go', 'vet', './test/integration'])
    phase('go-architecture', ['python3', str(mirror / 'scripts/check-go-architecture.py')])
    terminal = 0
finally:
    final = check()
    shutil.rmtree(scratch)
    cleanup = {'removed': not scratch.exists(), 'freeAfter': shutil.disk_usage('/tmp').free}
    (evidence / 'scratch-cleanup.json').write_text(json.dumps(cleanup, indent=2) + '\n')
    result = {'terminal': terminal, 'phases': reports, 'finalHashes': final, 'cleanup': cleanup, 'nativeQualification': False, 'installedSelection': False}
    (evidence / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'terminal': terminal, 'phases': len(reports), 'finalHashes': final, 'cleanup': cleanup}), flush=True)
