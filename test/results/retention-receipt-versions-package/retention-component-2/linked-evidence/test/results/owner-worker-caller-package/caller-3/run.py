from pathlib import Path
import hashlib, json, os, shutil, signal, subprocess, tempfile, time

c = Path(__file__).parent
live = Path('/home/phil/Projekte/asservat')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json') == '56003a7dc8866b6302e599c863b44a2cc863e393ada9b398ec0e2f8b276c21aa'
assert sha(c/'dependencies.json') == '2198576c1a7663e7fb8e3523929a2326b5f995cd36a6b0b6d06c481d99ca4f48'
m = json.loads((c/'manifest.json').read_text())
deps = json.loads((c/'dependencies.json').read_text())
args = json.loads((c/'dependency-args.json').read_text())
exclude = set(json.loads((c/'dependency-exclusions.json').read_text()))
variants = []
previous = json.loads((c/'prior-evidence.json').read_text())
prior = json.loads((c.parent/'caller-1/manifest.json').read_text())
required = json.loads((c/'required-tests.json').read_text())

def verify():
    inventory = set(subprocess.check_output(['rg', '--files', *args], cwd=live, text=True).splitlines()) - exclude
    return {
        'payloads': [x['path'] for x in m if sha(c/'files'/x['path']) != x['payload_sha256']],
        'bases': [x['path'] for x in m if sha(live/x['path']) != x['base_sha256']],
        'dependencies': [p for p, v in deps.items() if sha(live/p) != v],
        'inventory': sorted(inventory ^ set(deps)),
        'variants': [x['variant']+'/'+x['path'] for x in variants if sha(c/x['variant']/x['path']) != x['sha256']],
        'qualified_prior_evidence': [p for p, v in previous.items() if sha(Path(p)) != v],
        'prior_unrun_payloads': [x['path'] for x in prior if sha(c.parent/'caller-1/files'/x['path']) != x['payload_sha256']],
    }

assert not (c/'result.json').exists()
r = {'started': time.time(), 'manifest': sha(c/'manifest.json'), 'dependencies': sha(c/'dependencies.json'), 'runner': sha(Path(__file__)), 'native': False, 'before': verify(), 'phases': [], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'excluded_live_paths': sorted(exclude)}
if any(r['before'].values()):
    (c/'preflight-failure.json').write_text(json.dumps(r, indent=2)+'\n')
    raise SystemExit(2)
free = shutil.disk_usage('/tmp').free
assert free >= 4*1024**3, 'less than 4GiB free in /tmp'
scratch = Path(tempfile.mkdtemp(prefix='asservat-owner-worker-caller-3-', dir='/tmp'))
tmp = scratch/'go-tmp'
tmp.mkdir()
mirror = scratch/'mirror'
r['tmpdir'], r['tmp_free_before'] = str(scratch), free
env = os.environ.copy()
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(tmp))
for k in list(env):
    if k.startswith('ASSERVAT_'):
        del env[k]
overlay = str(c/'overlay.json')
packages = ['./internal/adapters/kubernetes', './internal/bootstrap']
phases = [
    ('copy-race', ['go', 'test', '-race', '-vet=off', '-overlay', overlay, '-count=1', '-timeout=180s', '-v', './internal/adapters/kubernetes', '-run=^TestOwnerBootstrapWorkerCallerCloseAndCopyDeny$'], 0, live),
    ('vet', ['go', 'vet', '-overlay', overlay, *packages], 0, live),
    ('go-architecture', ['make', 'go-architecture-check', 'PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'], 0, mirror),
]
code = 2
mirror_hashes = {}
try:
    probe = scratch/'write-probe'
    with probe.open('xb') as f:
        f.write(bytes(1024**2)); f.flush(); os.fsync(f.fileno())
    probe.unlink()
    for rel in deps:
        p = mirror/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(live/rel, p)
    for x in m:
        p = mirror/x['path']
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(c/'files'/x['path'], p)
    mirror_hashes = {p.relative_to(mirror).as_posix(): sha(p) for p in mirror.rglob('*') if p.is_file()}
    (c/'mirror-manifest.json').write_text(json.dumps(mirror_hashes, indent=2)+'\n')
    for name, cmd, expected, cwd in phases:
        check = verify()
        if any(check.values()):
            r['phase_preflight'] = check
            code = 2
            break
        started = time.time()
        timed_out = False
        log = c/'evidence'/(name+'.log')
        with log.open('x') as f:
            p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
            print(json.dumps({'phase': name, 'pid': p.pid, 'started': started}), flush=True)
            try:
                while p.poll() is None:
                    if time.time()-started > 600 or log.stat().st_size > 32*1024**2 or shutil.disk_usage('/tmp').free < 256*1024**2:
                        raise subprocess.TimeoutExpired(cmd, 600)
                    time.sleep(.5)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
        text = log.read_text()
        entry = {'name': name, 'command': cmd, 'exit': p.returncode, 'expected_exit': expected, 'timed_out': timed_out, 'seconds': time.time()-started, 'log_sha256': sha(log), 'hashes': verify(), 'pass_entries': sum(s.lstrip().startswith('--- PASS:') for s in text.splitlines()), 'top_level_passes': sum(s.startswith('--- PASS:') for s in text.splitlines())}
        entry['missing_required_passes'] = [test for test in required.get(name, []) if '--- PASS: '+test+' (' not in text]
        if name == 'before-classification':
            entry['intended_assertion'] = all(s in text for s in ['unavailable final journal became changed identity', 'expired final return became changed identity', '--- FAIL: TestOwnerBootstrapWorkerCallerUnavailableFinalJournalStaysUnavailable', '--- FAIL: TestOwnerBootstrapWorkerCallerExpiredFinalReturnStaysUnavailable']) and '[build failed]' not in text
        elif name == 'before-final-journal':
            entry['intended_assertion'] = 'final original mutation returned caller provenance' in text and '--- FAIL: TestOwnerBootstrapWorkerCallerFinalJournalAndGuardAreCurrent/journal_changed' in text and '[build failed]' not in text
        r['phases'].append(entry)
        print(json.dumps(entry), flush=True)
        code = 0 if not timed_out and p.returncode == expected and (expected != 1 or entry.get('intended_assertion')) and not any(entry['hashes'].values()) and not entry['missing_required_passes'] else (124 if timed_out else p.returncode or 2)
        if code:
            break
except Exception as e:
    r['runner_error'] = repr(e)
    code = 2
finally:
    r['mirror_changed'] = [p for p, v in mirror_hashes.items() if sha(mirror/p) != v]
    shutil.rmtree(scratch)
    r.update(exit=code, ended=time.time(), after=verify(), tmpdir_removed=not scratch.exists())
    with (c/'result.json').open('x') as f:
        json.dump(r, f, indent=2); f.write('\n')
    print(json.dumps(r), flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] else 2)
