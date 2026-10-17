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

prepare = validator(tools['prepare_artifact_download']['inputSchema'])
sample = read('examples/download-prepare.json')
valid(prepare, sample)
for key, value in [('destination_url', 'https://untrusted.invalid'), ('local_path', '/tmp/core'), ('raw_bytes', 'secret'), ('grant_id', 'not-a-uuid')]:
    bad = copy.deepcopy(sample); bad[key] = value; invalid(prepare, bad)
for missing in ('artifact_id', 'idempotency_key'):
    bad = copy.deepcopy(sample); del bad[missing]; invalid(prepare, bad)

status = validator({'$ref': schema['$id'] + '#/$defs/status'})
ready = read('examples/download-ready.json')['data']
valid(status, ready)
for field, value in [('local_copy_managed', True), ('content_path', 'https://bucket.invalid/signed?token=secret'), ('content_path', '//external.invalid/core'), ('filename', '../core'), ('filename', 'core\r\nInjected: yes'), ('size_bytes', -1), ('emitted_bytes', -1), ('sha256', 'unknown'), ('native_format', '')]:
    bad = copy.deepcopy(ready); bad[field] = value; invalid(status, bad)
for state in ('Completed', 'Cancelled', 'Expired', 'Denied', 'Failed'):
    bad = copy.deepcopy(ready); bad['state'] = state; invalid(status, bad)
    del bad['content_path']; bad['resume_available'] = False; valid(status, bad)
bad = copy.deepcopy(ready); del bad['content_path']; invalid(status, bad)
metadata_fields = ('filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice')
preparing = copy.deepcopy(ready)
preparing['state'] = 'Preparing'
preparing['resume_available'] = False
preparing.pop('content_path')
for field in metadata_fields:
    preparing.pop(field)
valid(status, preparing)
for state in ('Ready', 'Streaming', 'Interrupted'):
    bad = copy.deepcopy(preparing); bad['state'] = state; invalid(status, bad)
for field in metadata_fields:
    bad = copy.deepcopy(ready); del bad[field]; invalid(status, bad)
bad = copy.deepcopy(preparing); bad['sha256'] = '0'*64; invalid(status, bad)
# A completed transfer stays explainable after its transfer deadline without
# keeping a worker or native metadata cache alive. This is status, not access.
completed = copy.deepcopy(preparing)
completed['state'] = 'Completed'
completed['expires_at'] = '2000-01-01T00:00:00Z'
valid(status, completed)
browser = yaml.safe_load((ROOT / 'docs/interfaces/browser-openapi.yaml').read_text())
for name in ('prepare_artifact_download', 'get_artifact_download', 'cancel_artifact_download'):
    envelope = read('examples/download-ready.json')
    envelope['data'] = completed
    for output in (tools[name]['outputSchema'], browser['components']['schemas']['McpOutput_' + name]):
        v = validator(output)
        valid(v, envelope)
        for field in metadata_fields:
            partial = copy.deepcopy(envelope); partial['data'][field] = ready[field]; invalid(v, partial)
        complete = copy.deepcopy(envelope)
        for field in metadata_fields:
            complete['data'][field] = ready[field]
        valid(v, complete)
        for field in metadata_fields:
            partial = copy.deepcopy(complete); del partial['data'][field]; invalid(v, partial)
        for field, value in (('sha256', 'not-verified'), ('content_path', ready['content_path']), ('resume_available', True)):
            bad = copy.deepcopy(complete); bad['data'][field] = value; invalid(v, bad)

# Continuation is acknowledged preparation, never status polling.
continuing = read('examples/download-ready.json'); continuing['data'] = copy.deepcopy(preparing)
continuing['data']['continue_preparation'] = True
valid(validator(tools['prepare_artifact_download']['outputSchema']), continuing)
for name in ('get_artifact_download', 'cancel_artifact_download'):
    invalid(validator(tools[name]['outputSchema']), continuing)
for state in ('Ready', 'Completed', 'Failed'):
    bad = copy.deepcopy(continuing); bad['data']['state'] = state
    invalid(validator(tools['prepare_artifact_download']['outputSchema']), bad)
minimal = read('examples/download-ready.json')
minimal['data'] = {'download_id': ready['download_id'], 'state': 'AlreadyTerminal', 'audit_state': 'pending'}
for output in (tools['cancel_artifact_download']['outputSchema'], browser['components']['schemas']['McpOutput_cancel_artifact_download']):
    v=validator(output); valid(v,minimal)
    for field,value in (('artifact_id',sample['artifact_id']), ('filename','private.core'), ('state','Completed'), ('audit_state','ignored')):
        bad=copy.deepcopy(minimal);bad['data'][field]=value;invalid(v,bad)
for name in ('prepare_artifact_download','get_artifact_download'):
    invalid(validator(tools[name]['outputSchema']),minimal)

for state in ('Preparing', 'Completed', 'Cancelled', 'Expired', 'Denied', 'Failed'):
    bad = copy.deepcopy(preparing); bad['state'] = state; bad['resume_available'] = True; invalid(status, bad)
for etag in ('W/"old"', 'unquoted', '"bad\\r\\nheader"'):
    bad = copy.deepcopy(ready); bad['etag'] = etag; invalid(status, bad)
assert datetime.fromisoformat(ready['expires_at']) <= datetime.fromisoformat(ready['managed_read_until'])
assert ready['size_bytes'] == 4 * 1024**3  # Multi-GiB native core must fit the contract.
checks += 2

raw = validator(tools['request_raw_access']['inputSchema'])
request = {'case_id': sample['artifact_id'], 'artifact_digests': ['a'*64], 'operations': ['download_artifact'], 'reason': 'Inspect with local GDB', 'max_bytes': 4 * 1024**3, 'expires_in_seconds': 3600, 'idempotency_key': 'download-access-1'}
valid(raw, request)
bad = copy.deepcopy(request); bad['operations'] = ['read_memory']; invalid(raw, bad)
bad = copy.deepcopy(request); bad['max_bytes'] = 1099511627777; invalid(raw, bad)
for name, fixture in [('get_artifact_download', 'examples/download-get.json'), ('cancel_artifact_download', 'examples/download-cancel.json')]:
    v = validator(tools[name]['inputSchema']); value = read(fixture); valid(v, value)
    bad = copy.deepcopy(value); bad['actor'] = 'another-user'; invalid(v, bad)
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
