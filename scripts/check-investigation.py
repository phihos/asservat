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
capture = read('examples/capture-investigation.yaml')
request = read('examples/investigation-preview.json')
grantv = validator(ref('grant'))
valid(grantv, parent)
valid(validator(ref('capture')), capture)
valid(validator(tools['preview_capture']['inputSchema']), request)
assert request['result_access'] == capture['spec']['resultAccess']
# ADR-335 D5: the decided approval attaches itself to the capture scope it
# covers; the capture never names a grant.
assert 'grantRef' not in capture['spec'] and parent['spec']['target']['kind'] == 'capture'
checks += 2
# Regression U01: a multi-GiB raw request validates against the MCP tool input.
raw = {'case_id': '00000000-0000-4000-8000-000000000042', 'artifact_digests': ['a' * 64], 'operations': ['download_artifact'], 'reason': 'Inspect with local GDB', 'max_bytes': 4 * 1024**3, 'expires_in_seconds': 1800, 'idempotency_key': 'local-gdb-download'}
valid(validator(tools['request_raw_access']['inputSchema']), raw)
# Authored plans cannot write resolved or issued authority.
for key, value in [('digest', 'a'*64), ('approver', parent['spec']['approver']), ('grantIDs', ['00000000-0000-4000-8000-000000000099'])]:
    bad = copy.deepcopy(request)
    bad['result_access'][key] = value
    invalid(validator(tools['preview_capture']['inputSchema']), bad)
# ADR-249/ADR-330 D9: submit-by-preview carries the reviewed request, including
# its result access, and its plan digest; authored authority fields stay invalid.
submit = {'preview': request, 'expected_plan_digest': 'a' * 64, 'idempotency_key': 'submit'}
valid(validator(tools['request_capture']['inputSchema']), submit)
bad = copy.deepcopy(submit); bad['preview']['result_access']['approver'] = parent['spec']['approver']
invalid(validator(tools['request_capture']['inputSchema']), bad)
bad = copy.deepcopy(submit); bad['result_access'] = request['result_access']
invalid(validator(tools['request_capture']['inputSchema']), bad)
for value, prop, replacement in [(parent, 'grantType', 'policy')]:
    bad = copy.deepcopy(value); bad['spec'][prop] = replacement; invalid(grantv, bad)
# Clients act with their user's own access (maintainer decision): no client selection.
bad = copy.deepcopy(request); bad['result_access']['clientIDs'] = ['agent']; invalid(validator(tools['preview_capture']['inputSchema']), bad)
for field in ('actionIds', 'operations'):
    bad = copy.deepcopy(request); bad['result_access'][field] = []; invalid(validator(tools['preview_capture']['inputSchema']), bad)

report = {'scope': 'Synthetic request/grant contracts only; real authorization, concurrency and local-tool workflow NOT RUN', 'positiveChecks': checks, 'rejectedInvalidCases': rejected}
(ROOT / 'docs/interfaces/investigation-validation.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS: ' + json.dumps(report))
