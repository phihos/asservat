"""Freeze authored/module/embed inputs and linked design dependencies; no builds."""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

assert len(sys.argv) == 3 and sys.argv[1] == '--parent-slot-allocated'
stage = Path(__file__).resolve().parents[1]
source = stage / 'epoch-source-checkpoint-3'
prior = stage / 'epoch-source-checkpoint-2'
repo = Path('/home/phil/Projekte/asservat')
out = Path(sys.argv[2])
assert out.parent == stage / 'checks' and not out.exists()
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
manifest = json.loads((source / 'manifest.json').read_text())
for item in manifest['files']:
    assert sha(repo / item['path']) == item['base']
    assert sha(source / 'files' / item['path']) == item['payload']
args = ['api', 'cmd', 'internal', 'migrations', 'test/integration', 'test/fixtures', 'scripts',
        'go.mod', 'go.sum', 'sqlc.yaml', 'Makefile', 'docs', 'specs', 'examples', 'design',
        'charts', 'README.md', 'requirements-spec.txt', 'AGENTS.md', '.gitignore', 'web',
        '-g', '!web/node_modules/**']
names = set(subprocess.check_output(['rg', '--files', *args], cwd=repo, text=True).splitlines())
paths = set(names)
overlays = {item['path'] for item in manifest['files']}
directories = {}
pending = [p for p in paths | overlays if p.endswith('.md')]
seen = set()
while pending:
    name = pending.pop()
    if name in seen:
        continue
    seen.add(name)
    document = source / 'files' / name if name in overlays else repo / name
    for match in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', document.read_text()):
        parsed = urlsplit(match.strip('<>').split(' "', 1)[0])
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        target = ((repo / name).parent / unquote(parsed.path)).resolve()
        assert target.is_relative_to(repo), (name, match)
        relative = target.relative_to(repo).as_posix()
        if target.is_dir():
            directories[relative] = sorted(p.name for p in target.iterdir())
        else:
            if relative not in overlays:
                assert target.is_file(), (name, match)
                paths.add(relative)
            if relative.endswith('.md'):
                pending.append(relative)
deps = {p: sha(repo / p) for p in sorted(paths)}
out.mkdir(parents=True)
shutil.copytree(source / 'files', out / 'files')
for name in ['manifest.json', 'REVIEW.md', 'SQL-PLAN.md', 'INSTALLED-PATH.md']:
    shutil.copyfile(source / name, out / name)
# The explicit draft-before artifact is not live/production behavior.
before = 'internal/domain/fleet/owner_audit_epoch_observation.go'
shutil.copyfile(prior / 'files' / before, out / 'draft-before.go.txt')
shutil.copyfile(Path(__file__), out / 'freeze.py')
shutil.copyfile(Path(__file__).with_name('run.py'), out / 'run.py')
for name, data in [('dependency-args.json', args), ('inventory.json', sorted(names)),
                   ('dependencies.json', deps), ('linked-directories.json', directories)]:
    (out / name).write_text(json.dumps(data, indent=2) + '\n')
freeze = {'source': str(source), 'manifest': sha(source / 'manifest.json'),
          'draftBeforePath': before, 'draftBeforeSHA256': sha(out / 'draft-before.go.txt'),
          'dependencyCount': len(deps), 'dependencies': sha(out / 'dependencies.json'),
          'runner': sha(out / 'run.py'), 'freezer': sha(out / 'freeze.py'), 'native': False,
          'scope': 'Unselected values and complete affected package checks; no production epoch implementation or SQL/runtime qualification'}
(out / 'freeze.json').write_text(json.dumps(freeze, indent=2) + '\n')
print(json.dumps(freeze), flush=True)
