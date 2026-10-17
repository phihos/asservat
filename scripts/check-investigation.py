#!/usr/bin/env python3
"""Paired investigation contract fixtures; not a production authorization engine."""
import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
read = lambda path: yaml.safe_load((ROOT / path).read_text())
schemas = [read(path.relative_to(ROOT)) for path in (ROOT / 'specs/contracts').glob('*.schema.json')]
registry = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in schemas)
validator = lambda s: Draft202012Validator(s, registry=registry, format_checker=FormatChecker())
ref = lambda name: {'$ref': 'https://asservat.io/spec/v1/' + name + '.schema.json'}
tools = {t['name']: t for t in read('specs/contracts/mcp-tools.json')['tools']}
checks = rejected = 0

def valid(v, value):
    global checks
    v.validate(value)
    checks += 1

def invalid(v, value):
    global rejected
    try:
        v.validate(value)
    except ValidationError:
        rejected += 1
    else:
        raise AssertionError('Invalid contract accepted')

parent = read('examples/grant-investigation.yaml')
child = read('examples/grant-investigation-result.yaml')
capture = read('examples/capture-investigation.yaml')
request = read('examples/investigation-preview.json')
grantv = validator(ref('grant'))
for value in (parent, child):
    valid(grantv, value)
valid(validator(ref('capture')), capture)
valid(validator(tools['preview_capture']['inputSchema']), request)
assert request['result_access'] == capture['spec']['resultAccess']
assert capture['spec']['grantRef'] == parent['id']
checks += 2
# Regression U01 follows the same operation from a multi-GiB request into a grant.
raw = {'case_id': child['spec']['target']['caseID'], 'artifact_digests': [child['spec']['target']['artifacts'][0]['digest']], 'operations': ['download_artifact'], 'reason': 'Inspect with local GDB', 'max_bytes': 4 * 1024**3, 'expires_in_seconds': 1800, 'idempotency_key': 'local-gdb-download'}
valid(validator(tools['request_raw_access']['inputSchema']), raw)
approved = copy.deepcopy(child)
approved['spec']['operations'] = raw['operations']
approved['spec']['limits']['maxBytes'] = raw['max_bytes']
valid(grantv, approved)
# Authored plans cannot write resolved or issued authority.
for key, value in [('digest', 'a'*64), ('approver', parent['spec']['approver']), ('grantIDs', [child['id']])]:
    bad = copy.deepcopy(request)
    bad['result_access'][key] = value
    invalid(validator(tools['preview_capture']['inputSchema']), bad)
bad = {'preview_id': '00000000-0000-4000-8000-000000000001', 'idempotency_key': 'submit', 'result_access': request['result_access']}
invalid(validator(tools['request_capture']['inputSchema']), bad)
for value, prop, replacement in [(parent, 'grantType', 'policy'), (child, 'grantType', 'adHocCapture')]:
    bad = copy.deepcopy(value); bad['spec'][prop] = replacement; invalid(grantv, bad)
for field in ('actionIds', 'operations', 'clientIDs'):
    bad = copy.deepcopy(request); bad['result_access'][field] = []; invalid(validator(tools['preview_capture']['inputSchema']), bad)
bad = copy.deepcopy(child); bad['spec']['target']['artifacts'][0]['digest'] = 'future'; invalid(grantv, bad)

# Validate the relationship between reviewed and committed scopes. This checks
# fixture consistency, not SQL locking, actual caller entitlement or byte delivery.
ps = parent['spec']
commit = {'captureUID': ps['target']['captureUID'], 'executionDigest': ps['target']['executionDigest'], 'actionID': 'core', 'artifact': child['spec']['target']['artifacts'][0], 'readUntil': '2026-10-09T17:55:00Z'}

def consistent(p, c, output):
    p, c = p['spec'], c['spec']
    a, origin = p['resultAccess'], c['resultOrigin']
    authored = {k: v for k, v in a.items() if k != 'digest'}
    payload = {'captureUID': p['target']['captureUID'], 'executionDigest': p['target']['executionDigest'], 'resultAccess': authored}
    assert a['digest'] == hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert origin['parentGrantID'] == parent['id']
    for key in ('captureUID', 'executionDigest'):
        assert origin[key] == p['target'][key] == output[key]
    assert origin['resultAccessDigest'] == a['digest']
    assert origin['actionID'] == output['actionID'] and output['actionID'] in a['actionIds']
    assert c['target']['artifacts'] == [output['artifact']]
    assert all(c['requester'][key] == p['requester'][key] for key in ('issuer', 'subject', 'identityType'))
    assert c['requester']['clientID'] in a['clientIDs']
    assert set(c['operations']) <= set(a['operations'])
    assert c['approver'] == p['approver'] and c['issuedAt'] == p['issuedAt']
    assert datetime.fromisoformat(c['notAfter']) <= min(datetime.fromisoformat(a['notAfter']), datetime.fromisoformat(p['notAfter']), datetime.fromisoformat(output['readUntil']))
    assert c['limits']['maxBytes'] <= a['maxBytes']
    assert c['limits']['maxExecutions'] <= a['maxOperations']

consistent(parent, child, commit); checks += 1
for path, value in [(['resultOrigin', 'parentGrantID'], '00000000-0000-4000-8000-000000000099'), (['resultOrigin', 'captureUID'], 'another-capture'), (['resultOrigin', 'executionDigest'], 'f'*64), (['resultOrigin', 'actionID'], 'another-action'), (['requester', 'subject'], 'another-human'), (['requester', 'clientID'], 'unreviewed-client'), (['operations'], ['debugger_command']), (['notAfter'], '2026-10-09T13:00:00Z')]:
    bad = copy.deepcopy(child); target = bad['spec']
    for key in path[:-1]: target = target[key]
    target[path[-1]] = value
    try:
        consistent(parent, bad, commit)
    except AssertionError:
        rejected += 1
    else:
        raise AssertionError('Inconsistent parent/child fixture accepted')
report = {'scope': 'Synthetic paired request/grant/commit contracts only; real authorization, concurrency and local-tool workflow NOT RUN', 'positiveChecks': checks, 'rejectedInvalidCases': rejected}
(ROOT / 'docs/interfaces/investigation-validation.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS: ' + json.dumps(report))
