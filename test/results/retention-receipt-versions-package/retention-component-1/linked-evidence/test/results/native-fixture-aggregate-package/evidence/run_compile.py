from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

root = Path('/home/phil/Projekte/asservat')
stage = Path(__file__).resolve().parent
hash_file = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
for name in ['tmp', 'evidence']:
    (stage / name).mkdir(exist_ok=True)
payload = {str(p.relative_to(stage / 'changes')): hash_file(p)
           for p in sorted((stage / 'changes').rglob('*')) if p.is_file()}
bases = {p: hash_file(stage / 'originals' / p) for p in payload}
dependencies = {}
for prefix in ['internal', 'api', 'migrations', 'test/integration', 'web/dist']:
    for p in sorted((root / prefix).rglob('*')):
        if p.is_file():
            dependencies[str(p.relative_to(root))] = hash_file(p)
for name in ['go.mod', 'go.sum']:
    dependencies[name] = hash_file(root / name)
for name, value in [('bases.json', bases), ('dependencies.json', dependencies), ('payload-hashes.json', payload)]:
    (stage / name).write_text(json.dumps(value, indent=2) + '\n')
overlay = {'Replace': {str(root / p): str(stage / 'changes' / p) for p in payload}}
(stage / 'overlay.json').write_text(json.dumps(overlay, indent=2) + '\n')

def verify():
    return {
        'bases': [p for p, v in bases.items() if hash_file(root / p) != v],
        'dependencies': [p for p, v in dependencies.items() if hash_file(root / p) != v],
        'payload': [p for p, v in payload.items() if hash_file(stage / 'changes' / p) != v],
    }

before = verify()
assert not any(before.values()), before
env = os.environ.copy()
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(stage / 'tmp'))
command = ['go', 'test', '-overlay', str(stage / 'overlay.json'), './test/integration', '-run', '^$', '-count=1', '-timeout=60s']
started = time.time()
timed_out = False
with (stage / 'evidence/compile.log').open('w') as output:
    process = subprocess.Popen(command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    print(json.dumps({'pid': process.pid, 'command': command}), flush=True)
    try:
        exit_code = process.wait(timeout=180)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            exit_code = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            exit_code = process.wait()
after = verify()
report = {
    'command': command, 'exit': exit_code, 'harnessTimeout': timed_out,
    'seconds': round(time.time() - started, 3), 'before': before, 'after': after,
    'payloadSHA256': hash_file(stage / 'payload-hashes.json'),
    'dependencySHA256': hash_file(stage / 'dependencies.json'),
    'dependenciesCount': len(dependencies),
    'environment': {k: env[k] for k in ['GOMAXPROCS', 'GOFLAGS', 'TMPDIR']},
}
(stage / 'evidence/compile.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report), flush=True)
print((stage / 'evidence/compile.log').read_text(), flush=True)
sys.exit(0 if exit_code == 0 and not timed_out and not any(after.values()) else 1)
