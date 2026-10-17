from pathlib import Path
import hashlib, json, os, shutil, signal, subprocess, tempfile, time

c = Path(__file__).parent
live = Path('/home/phil/Projekte/asservat')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(c/'manifest.json') == 'b8c2e17945d9f77270b43bd5e2ebbc2486866a8276b860ed632ee8b197a48ba8'
assert sha(c/'dependencies.json') == '9a464b117c9e22e6b8af66b41d6919138ddee4ebdd848940066640a442277444'
m = json.loads((c/'manifest.json').read_text())
deps = json.loads((c/'dependencies.json').read_text())
args = json.loads((c/'dependency-args.json').read_text())
exclude = set(json.loads((c/'dependency-exclusions.json').read_text()))
assert sha(c/'variants.json') == '877c055cef641741c451f67f42da725ec39b7fc282dab3e55a895cbf085fd4e0'
variants = json.loads((c/'variants.json').read_text())
required = {'owner-races': ['TestOwnerCurrentAuditReceiptsRequireImmutableVersions', 'TestOwnerVersionRequirementDoesNotReinterpretOtherReceiptFormats', 'TestOwnerConfigurationAcceptanceOrderingAndFailures'], 'bootstrap-races': ['TestProviderOwnerAuditStorageRequiresImmutableVersion', 'TestProviderConfigurationAuditStorageRequiresImmutableVersion', 'TestCaptureCleanupStorageCredentialsRemainSeparateAndDoNotFallback'], 'storage-races': ['TestVersionedAuditRejectsUnpinnedReceipts', 'TestVersionedAuditPinnedReadSurvivesLatestReplacement']}

supplement = json.loads((c/'supplement.json').read_text())
previous = json.loads((c/'prior-evidence.json').read_text())

def verify():
    inventory = set(subprocess.check_output(['rg', '--files', *args], cwd=live, text=True).splitlines()) - exclude
    return {
        'payloads': [x['path'] for x in m if sha(c/'files'/x['path']) != x['payload_sha256']],
        'bases': [x['path'] for x in m if sha(live/x['path']) != x['base_sha256']],
        'dependencies': [p for p, v in deps.items() if sha(live/p) != v],
        'inventory': sorted(inventory ^ set(deps)),
        'variants': [x['path'] for x in variants if sha(c/'before'/x['path']) != x['sha256']],
        'pinned_progress': [p for p,v in supplement.items() if sha(c/'supplement'/p)!=v or sha(live/p)!=v],
        'prior_evidence': [p for p,v in previous.items() if sha(Path(p))!=v],
    }

assert not (c/'result.json').exists()
r = {'started': time.time(), 'manifest': sha(c/'manifest.json'), 'dependencies': sha(c/'dependencies.json'), 'runner': sha(Path(__file__)), 'native': False, 'before': verify(), 'phases': [], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'excluded_live_paths': sorted(exclude)}
if any(r['before'].values()):
    (c/'preflight-failure.json').write_text(json.dumps(r, indent=2)+'\n')
    raise SystemExit(2)
free = shutil.disk_usage('/tmp').free
assert free >= 4*1024**3, 'less than 4GiB free in /tmp'
scratch = Path(tempfile.mkdtemp(prefix='asservat-owner-audit-versions-3-', dir='/tmp'))
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
packages = ['./internal/domain/audit', './internal/application/fleet', './internal/bootstrap', './internal/adapters/postgres', './test/integration']
phases = [('contracts', ['make', 'spec-check', 'architecture-check', 'design-check', 'PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'], 0, mirror)]
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
    for rel in supplement:
        p=mirror/rel
        p.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(c/'supplement'/rel,p)
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
        if name == 'before-history':
            entry['intended_assertion'] = all('--- FAIL: '+name in text for name in [
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/configuration/empty',
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/configuration/null',
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/enrollment/empty',
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/enrollment/null',
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/certificate/empty',
                'TestOwnerCurrentAuditReceiptsRequireImmutableVersions/certificate/null',
                'TestOwnerConfigurationAcceptanceOrderingAndFailures/empty-old-version',
                'TestOwnerConfigurationAcceptanceOrderingAndFailures/null-old-version',
            ]) and '[build failed]' not in text and 'current authority=true, want false' in text and 'unexpected result <nil>' in text
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
