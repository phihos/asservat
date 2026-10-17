from pathlib import Path
import json
import shutil
from inventory import REPO, PROGRESS, authored_paths, link_closure, sha

stage = Path(__file__).resolve().parent
if (stage / 'source').exists() or (stage / 'freeze.json').exists():
    raise SystemExit('refusing to replace an existing source freeze')
payload = json.loads((stage / 'payload.json').read_text())
before = json.loads((stage / 'before-payload.json').read_text())
bases = json.loads((stage / 'bases.json').read_text())
assert all(sha(stage / 'files' / n) == h for n, h in payload.items())
assert all(sha(stage / 'before' / n) == h for n, h in before.items())
assert all(sha(REPO / n) == h for n, h in bases.items()), 'payload live base changed'
authored = authored_paths()
paths, directories, external = link_closure(authored | {PROGRESS})
if external:
    raise SystemExit('canonical mirror contains external filesystem links: ' + repr(sorted(external)))
source = {}
for n in sorted(paths):
    p, target = REPO / n, stage / 'source' / n
    digest = sha(p)
    if digest is None:
        raise SystemExit('source no longer exists: ' + n)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p, target)
    if sha(target) != digest or sha(p) != digest:
        raise SystemExit('source changed while freezing: ' + n)
    source[n] = digest
for n in sorted(bases):
    if bases[n] is not None:
        target = stage / 'base-files' / n
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / 'source' / n, target)
json_write = lambda name, value: (stage / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
json_write('source.json', source)
json_write('dependencies.json', {n: h for n, h in source.items() if n != PROGRESS})
json_write('authored-files.json', sorted(authored))
json_write('mirror-directories.json', sorted(directories))
json_write('snapshot-notes.json', {'progressSnapshot': {PROGRESS: source[PROGRESS]}, 'liveProgressHashExempt': True, 'allOtherSourceAndLinkedReportsMustRemainUnchanged': True, 'authoredFiles': len(authored), 'sourceFiles': len(source), 'payloads': len(payload), 'beforePayloads': len(before), 'externalFilesystemLinks': sorted(external)})
frozen = {str(p.relative_to(stage)): sha(p) for p in sorted(stage.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
json_write('freeze.json', frozen)
print(json.dumps({'stage': str(stage), 'source': len(source), 'dependencies': len(source) - 1, 'payloads': len(payload), 'freezeSHA256': sha(stage / 'freeze.json')}, indent=2))
