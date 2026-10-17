#!/usr/bin/env python3
from pathlib import Path
import datetime, hashlib, json, os, subprocess, sys
stage = Path(__file__).resolve().parent
repo = Path('/home/phil/Projekte/asservat')
label = sys.argv[1]
if not label.isalnum():
    raise SystemExit('bounded evidence label required')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
for item in json.loads((stage/'manifest-source-v4.json').read_text()):
    assert sha(stage/'changes'/item['path']) == item['sha256'], item['path']
assert sha(stage/'changes/web/tests/native-restart-journey.mjs') == sha(stage/'work/web/tests/native-restart-journey.mjs')
def snapshot():
    result = {}
    for name in ('internal', 'api', 'cmd', 'test/integration', 'migrations'):
        for p in sorted((repo/name).rglob('*')):
            if p.is_file(): result[str(p.relative_to(repo))] = sha(p)
    for name in ('go.mod', 'go.sum'):
        result[name] = sha(repo/name)
    for name in ('changes', 'work/web/src', 'work/web/dist', 'work/web/tests'):
        for p in sorted((stage/name).rglob('*')):
            if p.is_file(): result['stage/'+str(p.relative_to(stage))] = sha(p)
    return result
engine = Path('/home/phil/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell')
command = ['go', 'test', '-race', '-overlay='+str(stage/'overlay.json'), '-count=1', '-run', '^TestConsoleNativeRestartWithBuiltPackage$', '-v', './test/integration']
env = dict(os.environ, GOMAXPROCS='2', GOFLAGS='-p=2', TMPDIR=str(stage/'tmp'), ASSERVAT_CONSOLE_BROWSER_TEST='1', ASSERVAT_CONSOLE_RESTART_ROOT=str(stage/'work'), ASSERVAT_CHROMIUM=str(engine))
report = {'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'command': command, 'engine':str(engine), 'engine_sha256':sha(engine), 'engine_version':subprocess.check_output([str(engine),'--version'], text=True).strip(), 'authority':'Synthetic C14/session/file data. Actual built React, TLS/CSRF, canonical browser operations, failed native attachment and explicit restart. Not SQL/IdP/audit/regional/installed qualification.', 'before':snapshot()}
log = stage/'evidence'/('browser-'+label+'.log')
try:
    with log.open('w') as stream:
        result = subprocess.run(command, cwd=repo, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
    report['exit_code'] = result.returncode
except subprocess.TimeoutExpired:
    report['timeout_seconds'] = 120
    report['exit_code'] = 124
finally:
    report['after'] = snapshot()
    report['source_unchanged'] = report['before'] == report['after']
    report['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    (stage/'evidence'/('browser-'+label+'-environment.json')).write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('exit_code','source_unchanged','started_at','ended_at')}))
print(log.read_text()[-6000:])
sys.exit(report['exit_code'] if report['source_unchanged'] else 125)
