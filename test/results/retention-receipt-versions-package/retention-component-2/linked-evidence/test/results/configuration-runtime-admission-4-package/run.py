from pathlib import Path
import hashlib, json, os, shutil, signal, subprocess, tempfile, time

c = Path(__file__).parent
live = Path('/home/phil/Projekte/asservat')
source = c
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
assert sha(source/'manifest.json') == '12f51be30ed49fa8ac70e651ef04894060a137dd021a87df8af5255b0ed19d05'
assert sha(source/'dependencies.json') == 'a5d0c4675474d15195509f56fc74739d1f611ca33b873042fbadc830f332186e'
assert sha(c/'auxiliary.json') == 'd23aef150eced0c5cf31dd930454c3a0118b8a32a333d13410501e6f1fb2f7be'
manifest = json.loads((source/'manifest.json').read_text())
deps = json.loads((source/'dependencies.json').read_text())
args = json.loads((source/'dependency-args.json').read_text())
aux = json.loads((c/'auxiliary.json').read_text())

def verify():
    inventory = set(subprocess.check_output(['rg', '--files', *args], cwd=live, text=True).splitlines())
    return {
        'payloads': [x['path'] for x in manifest if sha(source/'files'/x['path']) != x['payload_sha256']],
        'bases': [x['path'] for x in manifest if sha(live/x['path']) != x['base_sha256']],
        'dependencies': [p for p,v in deps.items() if sha(live/p) != v],
        'inventory': sorted(inventory ^ set(deps)),
        'auxiliary': [p for p,v in aux.items() if sha(Path(p)) != v],
    }

assert not (c/'result.json').exists()
r = {'started':time.time(), 'source':str(source), 'manifest':sha(source/'manifest.json'),
     'dependencies':sha(source/'dependencies.json'), 'runner':sha(Path(__file__)),
     'auxiliary':sha(c/'auxiliary.json'), 'native':False, 'runtime_enablement':False,
     'before':verify(), 'phases':[], 'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
if any(r['before'].values()):
    with (c/'preflight-failure.json').open('x') as f: json.dump(r,f,indent=2); f.write('\n')
    raise SystemExit(2)
free = shutil.disk_usage('/tmp').free
assert free >= 4*1024**3, 'less than 4GiB free in /tmp'
scratch = Path(tempfile.mkdtemp(prefix='asservat-runtime-admission-4-', dir='/tmp'))
tmp = scratch/'go-tmp'; tmp.mkdir()
mirror = scratch/'mirror'
r['scratch'],r['tmp_free_before'] = str(scratch),free
env = os.environ.copy()
env.update(GOMAXPROCS='2',GOFLAGS='-p=2',TMPDIR=str(tmp),PYTHONDONTWRITEBYTECODE='1')
for key in list(env):
    if key.startswith('ASSERVAT_'): del env[key]
overlay = str(c/'overlay.json')
packages = ['./internal/application/fleet','./internal/application/capacity',
            './internal/adapters/kubernetes','./internal/adapters/kms','./internal/bootstrap',
            './cmd/asservat','./test/integration']

def race(packages,selector=None,ov=overlay):
    cmd=['go','test','-race','-vet=off','-overlay',ov,'-count=1','-timeout=8m','-v',*packages]
    if selector: cmd.append('-run='+selector)
    return cmd

phases = [
    ('selectors',['python3','scripts/test-initial-bootstrap-selection.py'],mirror,0,None),
    ('compile',['go','test','-vet=off','-overlay',overlay,'-run=^$','-count=1',*packages],live,0,None),
    ('before-idle-close',race(['./internal/adapters/kubernetes'],
        '^TestConfigurationWorkerTokenTransportRetainsOriginalIdleClose$',str(c/'before-overlay.json')),live,1,
        'token observation hid the original transport close'),
    ('before-capacity-phase-parent',race(['./internal/bootstrap'],
        '^TestProviderCapacityNativeContextSurvivesPhaseReturnWithinOriginalEnd$',str(c/'phase-before-overlay.json')),live,1,
        'phase completion cancelled native bracket before final acceptance'),
    ('fleet-capacity-races',race(['./internal/application/fleet','./internal/application/capacity']),live,0,None),
    ('kubernetes-races',race(['./internal/adapters/kubernetes'],
        '^(TestConfigurationProviderRuntime|TestConfigurationWorker(Source|Token|Provider)|TestConfigurationMaterial|TestWorkerProjectionOperation|TestInstalledWorker)'),live,0,None),
    ('kms-races',race(['./internal/adapters/kms'],
        '^(TestConfiguration(Provider|Control)|TestOwnerProvider(Lifetime|Lifetimes|Lease|Control|Effects)|TestInstalledOwnerProvider)'),live,0,None),
    ('bootstrap-races',race(['./internal/bootstrap']),live,0,None),
    ('vet',['go','vet','-overlay',overlay,*packages],live,0,None),
    ('go-architecture',['make','go-architecture-check','PYTHON=/home/phil/.cache/asservat-build/spec-venv/bin/python'],mirror,0,None),
]
code=2
mirror_hashes={}
try:
    probe=scratch/'write-probe'
    with probe.open('xb') as f: f.write(bytes(1024**2));f.flush();os.fsync(f.fileno())
    probe.unlink()
    for rel in deps:
        p=mirror/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(live/rel,p)
    for item in manifest:
        p=mirror/item['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'files'/item['path'],p)
    mirror_hashes={p.relative_to(mirror).as_posix():sha(p) for p in mirror.rglob('*') if p.is_file()}
    with (c/'mirror-manifest.json').open('x') as f:json.dump(mirror_hashes,f,indent=2);f.write('\n')
    for name,cmd,cwd,expected,assertion in phases:
        check=verify()
        if any(check.values()):r['phase_preflight']=check;code=2;break
        start=time.time();stop_reason=None;log=c/'evidence'/(name+'.log')
        with log.open('x') as f:
            p=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
            print(json.dumps({'phase':name,'pid':p.pid,'started':start}),flush=True)
            while p.poll() is None:
                if time.time()-start>600:stop_reason='600-second infrastructure ceiling'
                elif log.stat().st_size>32*1024**2:stop_reason='32MiB output bound'
                elif shutil.disk_usage('/tmp').free<256*1024**2:stop_reason='scratch space below 256MiB'
                if stop_reason:
                    os.killpg(p.pid,signal.SIGTERM)
                    try:p.wait(timeout=10)
                    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
                    break
                time.sleep(.5)
        output=log.read_text()
        qualified=(name!='selectors' or 'Ran 6 tests' in output and '\nOK\n' in output)
        intended=expected!=1 or assertion in output and '[build failed]' not in output and 'panic: test timed out' not in output
        entry={'name':name,'command':cmd,'exit':p.returncode,'expected_exit':expected,
               'stop_reason':stop_reason,'seconds':time.time()-start,'log_sha256':sha(log),
               'hashes':verify(),'required_checks_present':qualified,'intended_assertion':intended,
               'top_level_pass':sum(line.startswith('--- PASS:') for line in output.splitlines()),
               'named_pass':sum(line.lstrip().startswith('--- PASS:') for line in output.splitlines())}
        r['phases'].append(entry);print(json.dumps(entry),flush=True)
        code=0 if not stop_reason and p.returncode==expected and qualified and intended and not any(entry['hashes'].values()) else (124 if stop_reason else p.returncode or 2)
        if code:break
except Exception as e:
    r['runner_error']=repr(e);code=2
finally:
    r['mirror_changed']=[p for p,v in mirror_hashes.items() if sha(mirror/p)!=v]
    shutil.rmtree(scratch)
    r.update(exit=code,ended=time.time(),after=verify(),scratch_removed=not scratch.exists())
    with (c/'result.json').open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r),flush=True)
raise SystemExit(code if not any(r['after'].values()) and not r['mirror_changed'] else 2)
