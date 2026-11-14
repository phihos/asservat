#!/usr/bin/env python3
"""Download DTO regressions only; no HTTP, crypto, tool or runtime qualification."""
import copy
import json
import yaml
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
read = lambda p: json.loads((ROOT / p).read_text())
documents = [json.loads(p.read_text()) for p in (ROOT / 'specs/contracts').glob('*.schema.json')]
registry = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in documents)
tools = {t['name']: t for t in read('specs/contracts/mcp-tools.json')['tools']}
schema = read('specs/contracts/artifact-download.schema.json')
validator = lambda s: Draft202012Validator(s, registry=registry, format_checker=FormatChecker())
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
        raise AssertionError('Invalid download contract accepted')

# specs/mcp.md (ADR-335): one download_artifact tool with action = prepare|status|cancel.
tool = tools['download_artifact']
assert not any(n in tools for n in ('prepare_artifact_download', 'get_artifact_download', 'cancel_artifact_download'))
inputs = validator(tool['inputSchema'])
sample = read('examples/download-prepare.json')
valid(inputs, sample)
for key, value in [('destination_url', 'https://untrusted.invalid'), ('local_path', '/tmp/core'), ('raw_bytes', 'secret'), ('grant_id', '00000000-0000-4000-8000-000000000001'), ('download_id', sample['artifact_id']), ('representation', 'zip')]:
    bad = copy.deepcopy(sample); bad[key] = value; invalid(inputs, bad)
for missing in ('artifact_id', 'idempotency_key', 'action'):
    bad = copy.deepcopy(sample); del bad[missing]; invalid(inputs, bad)
bad = copy.deepcopy(sample); bad['action'] = 'status'; invalid(inputs, bad)

status = validator({'$ref': schema['$id'] + '#/$defs/status'})
ready = read('examples/download-ready.json')['data']
valid(status, ready)
for field, value in [('local_copy_managed', True), ('content_path', 'https://bucket.invalid/signed?token=secret'), ('content_path', '//external.invalid/core'), ('browser_url', 'https://evil.invalid/downloads/x'), ('filename', '../core'), ('filename', 'core\r\nInjected: yes'), ('filename', 'a' * 201), ('size_bytes', -1), ('emitted_bytes', -1), ('sha256', 'unknown'), ('native_format', ''), ('continue_preparation', True), ('expires_at', ready['access_until'])]:
    bad = copy.deepcopy(ready); bad[field] = value; invalid(status, bad)
# Ready carries both links; every other state carries neither.
for link in ('content_path', 'browser_url'):
    bad = copy.deepcopy(ready); del bad[link]; invalid(status, bad)
for state in ('Completed', 'Cancelled', 'Failed', 'Preparing'):
    bad = copy.deepcopy(ready); bad['state'] = state; invalid(status, bad)
terminal = copy.deepcopy(ready); del terminal['content_path']; del terminal['browser_url']
for state in ('Completed', 'Cancelled'):
    t = copy.deepcopy(terminal); t['state'] = state; valid(status, t)
failed = copy.deepcopy(terminal); failed['state'] = 'Failed'; invalid(status, failed)
failed['failure_reason'] = 'Expired'; valid(status, failed)
bad = copy.deepcopy(terminal); bad['state'] = 'Completed'; bad['failure_reason'] = 'Denied'; invalid(status, bad)
# Every status, including Preparing and terminal ones, carries the verified size and SHA-256.
native_fields = ('filename', 'native_format', 'etag', 'coverage_notice')
preparing = copy.deepcopy(terminal); preparing['state'] = 'Preparing'
for field in native_fields:
    preparing.pop(field)
valid(status, preparing)
for field in ('size_bytes', 'sha256'):
    for value in (preparing, terminal):
        bad = copy.deepcopy(value); del bad[field]; invalid(status, bad)
for field in native_fields:
    bad = copy.deepcopy(preparing); bad[field] = ready[field]; invalid(status, bad)
    bad = copy.deepcopy(ready); del bad[field]; invalid(status, bad)
# A terminal status stays explainable after AccessUntil without native metadata.
completed = copy.deepcopy(preparing); completed['state'] = 'Completed'; completed['access_until'] = '2000-01-01T00:00:00Z'
valid(status, completed)
browser = yaml.safe_load((ROOT / 'docs/interfaces/browser-openapi.yaml').read_text())
for output in (tool['outputSchema'], browser['components']['schemas']['McpOutput_download_artifact']):
    v = validator(output)
    for data in (ready, preparing, completed, failed):
        envelope = read('examples/download-ready.json'); envelope['data'] = data; valid(v, envelope)
    bad = read('examples/download-ready.json'); bad['data']['sha256'] = 'not-verified'; invalid(v, bad)
minimal = read('examples/download-ready.json')
minimal['data'] = {'download_id': ready['download_id'], 'state': 'AlreadyTerminal', 'audit_state': 'pending'}
for output in (tool['outputSchema'], browser['components']['schemas']['McpOutput_download_artifact']):
    v = validator(output); valid(v, minimal)
    for field, value in (('artifact_id', sample['artifact_id']), ('filename', 'private.core'), ('state', 'Completed'), ('audit_state', 'ignored')):
        bad = copy.deepcopy(minimal); bad['data'][field] = value; invalid(v, bad)
assert datetime.fromisoformat(ready['access_until']) > datetime.fromisoformat('2026-10-09T12:00:00+00:00')
assert ready['size_bytes'] == 4 * 1024**3  # Multi-GiB native core must fit the contract.
assert ready['browser_url'] == '/downloads/' + ready['download_id'] and ready['content_path'] == '/api/v1/downloads/' + ready['download_id'] + '/content'
checks += 3

raw = validator(tools['request_raw_access']['inputSchema'])
request = {'case_id': sample['artifact_id'], 'artifact_digests': ['a'*64], 'operations': ['download_artifact'], 'reason': 'Inspect with local GDB', 'max_bytes': 4 * 1024**3, 'expires_in_seconds': 3600, 'idempotency_key': 'download-access-1'}
valid(raw, request)
bad = copy.deepcopy(request); bad['operations'] = ['unknown_operation']; invalid(raw, bad)
bad = copy.deepcopy(request); bad['max_bytes'] = 9007199254740992; invalid(raw, bad)
for fixture in ('examples/download-get.json', 'examples/download-cancel.json'):
    value = read(fixture); valid(inputs, value)
    bad = copy.deepcopy(value); bad['actor'] = 'another-user'; invalid(inputs, bad)
bad = read('examples/download-get.json'); bad['idempotency_key'] = 'status-key'; invalid(inputs, bad)
bad = read('examples/download-cancel.json'); del bad['idempotency_key']; invalid(inputs, bad)
# U01 also crossed the future-sharing request/resolved/concrete boundary.
shared_request = yaml.safe_load((ROOT / 'examples/capture-with-raw-sharing.yaml').read_text())
shared_request['spec']['sharing']['outputSelection']['outputs'][1]['operations'] = ['download_artifact']
sharedv = validator({'$ref': 'https://asservat.io/spec/v1/capture.schema.json'})
valid(sharedv, shared_request)
bad = copy.deepcopy(shared_request); bad['spec']['sharing']['outputSelection']['outputs'][1]['dataClass'] = 'extract'; invalid(sharedv, bad)
intent = yaml.safe_load((ROOT / 'examples/sharing-intent.yaml').read_text())
intent['spec']['resolvedSelections'][1]['operations'] = ['download_artifact']
intentv = validator({'$ref': 'https://asservat.io/spec/v1/sharing-intent.schema.json'})
valid(intentv, intent)
bad = copy.deepcopy(intent); bad['spec']['resolvedSelections'][1]['independentApprovalRequired'] = False; invalid(intentv, bad)
share = yaml.safe_load((ROOT / 'examples/share-extract.yaml').read_text())
share['spec']['operations'] = ['download_artifact']; share['spec']['dataClasses'] = ['raw']
sharev = validator({'$ref': 'https://asservat.io/spec/v1/share.schema.json'})
valid(sharev, share)
bad = copy.deepcopy(share); bad['spec']['dataClasses'] = ['extract']; invalid(sharev, bad)
report = {'scope': 'Synthetic download DTO checks only; real streams/local tools NOT RUN', 'positiveChecks': checks, 'rejectedInvalidCases': rejected}
(ROOT / 'docs/interfaces/download-validation.json').write_text(json.dumps(report, indent=2)+'\n')
print('PASS: ' + json.dumps(report))
