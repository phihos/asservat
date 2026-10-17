from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

root = Path('/home/phil/Projekte/asservat')
stage = Path(__file__).resolve().parent
h = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
payload = {str(p.relative_to(stage / 'changes')): h(p) for p in sorted((stage / 'changes').rglob('*')) if p.is_file()}
bases = {p: h(stage / 'originals' / p) for p in payload}
deps = {}
for prefix in ['internal', 'api', 'migrations', 'test/integration', 'web/dist']:
    for p in sorted((root / prefix).rglob('*')):
        if p.is_file():
            deps[str(p.relative_to(root))] = h(p)
for name in ['go.mod', 'go.sum']:
    deps[name] = h(root / name)
for name, data in [('bases.json', bases), ('payload-hashes.json', payload), ('dependencies.json', deps)]:
    (stage / name).write_text(json.dumps(data, indent=2) + '\n')
before_path = 'internal/transport/native/admission_budget_test.go'
(stage / 'overlay-before.json').write_text(json.dumps({'Replace': {str(root / before_path): str(stage / 'changes' / before_path)}}, indent=2) + '\n')
(stage / 'overlay-after.json').write_text(json.dumps({'Replace': {str(root / p): str(stage / 'changes' / p) for p in payload}}, indent=2) + '\n')

def verify():
    return {'bases': [p for p, v in bases.items() if h(root / p) != v], 'dependencies': [p for p, v in deps.items() if h(root / p) != v], 'payload': [p for p, v in payload.items() if h(stage / 'changes' / p) != v]}

env = os.environ.copy()
env.update(GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(stage / 'tmp'))
steps = [
    ('before', ['go', 'test', '-race', '-overlay', str(stage / 'overlay-before.json'), './internal/transport/native', '-run', '^TestNativeRegistrationPreservesOriginalAdmissionBudget$', '-count=1', '-timeout=60s']),
    ('after', ['go', 'test', '-race', '-overlay', str(stage / 'overlay-after.json'), './internal/transport/native', '-count=1', '-timeout=60s']),
    ('vet', ['go', 'vet', '-overlay', str(stage / 'overlay-after.json'), './internal/transport/native', './internal/application/evidence']),
]
for name, command in steps:
    before = verify()
    assert not any(before.values()), before
    print(json.dumps({'phase': name, 'command': command}), flush=True)
    started = time.time()
    with (stage / 'evidence' / (name + '.log')).open('w') as output:
        process = subprocess.run(command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
    after = verify()
    report = {'phase': name, 'command': command, 'exit': process.returncode, 'seconds': round(time.time() - started, 3), 'before': before, 'after': after, 'dependenciesCount': len(deps), 'dependencySHA256': h(stage / 'dependencies.json'), 'payloadSHA256': h(stage / 'payload-hashes.json'), 'environment': {k: env[k] for k in ['GOMAXPROCS', 'GOFLAGS', 'TMPDIR']}}
    (stage / 'evidence' / (name + '.json')).write_text(json.dumps(report, indent=2) + '\n')
    output = (stage / 'evidence' / (name + '.log')).read_text()
    print(json.dumps(report), flush=True)
    print(output[-16000:], flush=True)
    expected = process.returncode != 0 and 'duplicate admission checks exhausted original bounded call' in output if name == 'before' else process.returncode == 0
    if not expected or any(after.values()):
        sys.exit(1)
