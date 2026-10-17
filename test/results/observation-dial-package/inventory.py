from pathlib import Path
import hashlib
import re
import subprocess
from urllib.parse import unquote, urlsplit

REPO = Path('/home/phil/Projekte/asservat')
PROGRESS = 'docs/implementation-progress.md'
ROOT_FILES = {'AGENTS.md', 'README.md', 'Makefile', 'go.mod', 'go.sum', 'sqlc.yaml', 'requirements-spec.txt'}
ROOT_DIRS = {'api', 'cmd', 'internal', 'migrations', 'scripts', 'specs', 'docs', 'examples', 'design', 'charts', 'experiments', 'test', 'web'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def authored_paths():
    paths = subprocess.check_output(['rg', '--files'], cwd=REPO, text=True).splitlines()
    out = set()
    for name in paths:
        parts = Path(name).parts
        if name not in ROOT_FILES and parts[0] not in ROOT_DIRS:
            continue
        if name.startswith(('test/results/', 'web/node_modules/', 'web/dist/')) or any(p in {'__pycache__', '.venv', 'node_modules'} for p in parts):
            continue
        if name != PROGRESS and (REPO / name).is_file():
            out.add(name)
    return out


def link_closure(initial):
    files, directories, external = set(initial), set(), set()
    pending = [n for n in initial if n.endswith('.md')]
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path = REPO / name
        for dest in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', path.read_text()):
            parsed = urlsplit(dest.strip('<>').split(' "', 1)[0])
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (path.parent / unquote(parsed.path)).resolve()
            if not target.exists():
                raise RuntimeError('existing canonical link missing: ' + name + ' -> ' + dest)
            if not target.is_relative_to(REPO):
                external.add(str(target))
                continue
            relative = str(target.relative_to(REPO))
            if target.is_dir():
                directories.add(relative)
            elif relative not in files:
                files.add(relative)
                if relative.endswith('.md'):
                    pending.append(relative)
    return files, directories, external
