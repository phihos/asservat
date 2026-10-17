#!/usr/bin/env python3
"""Offline architecture/contract checks; not a runtime or cryptography test."""
from __future__ import annotations
import copy
import json
import re
from datetime import datetime
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[1]
checks = 0
rejections = 0

def require(value, message):
    global checks
    checks += 1
    if not value:
        raise ValueError(message)

def read(name):
    return yaml.safe_load((ROOT / name).read_text())

def rejected(fn, description):
    global rejections
    try:
        fn()
    except (ValueError, ValidationError):
        rejections += 1
    else:
        raise ValueError('Accepted invalid case: ' + description)

catalog = read('docs/architecture/catalog.yaml')
components = {c['id']: c for c in catalog['components']}
apps = {a['id']: a for a in catalog['applications']}
interfaces = {i['id']: i for i in catalog['interfaces']}
require(len(components) == len(catalog['components']), 'Duplicate component ID')
require(len(apps) == len(catalog['applications']), 'Duplicate application ID')
require(len(interfaces) == len(catalog['interfaces']), 'Duplicate interface ID')
paths = set()
for cid, component in components.items():
    require(component['responsibility'] and component['provided_ports'], f'Missing contract for {cid}')
    for path in component['package_roots']:
        require(path not in paths and not Path(path).is_absolute() and '..' not in Path(path).parts, f'Invalid path {path}')
        paths.add(path)
    for dep in component['allowed_dependencies']:
        require(dep in components and dep != cid, f'Bad dependency {cid} -> {dep}')
        if component['layer'] == 'application':
            require(components[dep]['layer'] in ('application', 'domain'), f'Application imports infrastructure: {cid}')
    if component['layer'] in ('domain', 'helper'):
        require(not component['allowed_dependencies'], f'Impure domain/helper: {cid}')

def acyclic(graph):
    seen, active = set(), set()
    def visit(node):
        if node in active:
            raise ValueError('Component dependency cycle at ' + node)
        if node in seen:
            return
        active.add(node)
        for dep in graph[node]:
            visit(dep)
        active.remove(node)
        seen.add(node)
    for node in graph:
        visit(node)

edges = {cid: c['allowed_dependencies'] for cid, c in components.items()}
acyclic(edges)
checks += 1
rejected(lambda: acyclic({'a': ['b'], 'b': ['a']}), 'cycle')
for aid, app in apps.items():
    require(all(c in components for c in app['components']), 'Unknown component in ' + aid)
    require(app['entrypoint'] and app['deployment'] and app['location'] and app['privilege'], 'Incomplete application')
require(apps['A-ANALYZE']['privilege'] == 'no-network', 'Offline analyzer lost isolation')
require('C-21' not in apps['A-ANALYZE']['components'], 'Offline analyzer includes persistence adapter component')
require(apps['A-MIGRATE']['privilege'] == 'database-ddl' and apps['A-MIGRATE']['deployment'] == 'Job', 'Migration authority is not a separate maintenance Job')
require(apps['A-NODE']['privilege'] == 'privileged', 'Node authority not explicit')
require(apps['A-CORE']['components'] == ['C-22'], 'Crash helper acquired dependencies')
require(set(components) == {cid for app in apps.values() for cid in app['components']}, 'Component has no runtime composition')
for iid, interface in interfaces.items():
    require(interface['caller'] in apps.keys() | components.keys(), 'Unknown caller ' + iid)
    require(interface['provider'] in apps.keys() | components.keys(), 'Unknown provider ' + iid)
    require((ROOT / interface['spec']).is_file(), 'Missing interface prose')
    if 'schema' in interface:
        require((ROOT / interface['schema']).is_file(), 'Missing interface schema')
    require(iid in (ROOT / interface['spec']).read_text(), 'Unexplained interface ' + iid)
entities = {e['name'] for e in read('docs/domain/model.yaml')['entities']}
requirements = {r['requirement'] for r in read('specs/traceability.yaml')['requirements']}
require(set(catalog['entity_owners']) == entities, 'Domain ownership coverage drift')
require(set(catalog['requirement_owners']) == requirements, 'Requirement ownership coverage drift')
for group in ('entity_owners', 'requirement_owners'):
    for item, owner in catalog[group].items():
        require(owner in components, 'Unknown owner for ' + item)
require(catalog['dependency_rules']['application_may_import_adapters'] is False, 'Adapter inversion removed')
require(catalog['dependency_rules']['domain_may_import_infrastructure'] is False, 'Domain purity removed')
for page in (ROOT / 'docs/architecture').glob('*.md'):
    for cid in re.findall(r'\bC-\d{2}\b', page.read_text()):
        require(cid in components, f'Unknown component {cid} in {page.name}')

schema = json.loads((ROOT / 'specs/contracts/internal-work.schema.json').read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
examples = [e for e in read('specs/examples.yaml')['examples'] if e.get('schema') == schema['$id']]
require(len(examples) == 8, 'Seven work purposes and receipt fixtures required')
fixtures = [json.loads((ROOT / e['file']).read_text()) for e in examples]
for fixture in fixtures:
    validator.validate(fixture)
    checks += 1
works = {f['purpose']: f for f in fixtures if f['kind'] == 'controlWork'}
require(set(works) == {'armSource', 'runAction', 'saveRecording', 'analysisStage', 'eraseCopy', 'projectLive', 'downloadArtifact'}, 'Purpose coverage drift')

def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))

# Semantic examples use an explicit synthetic peer/source context, not real grants.
peer_cluster = works['runAction']['clusterId']
peer_boot = works['runAction']['target']['nodeBootID']
now = timestamp('2026-10-09T12:00:10Z')

def validate_semantics(work):
    validator.validate(work)
    if work['clusterId'] != peer_cluster:
        raise ValueError('Wrong authenticated cluster')
    if not timestamp(work['issuedAt']) <= now < timestamp(work['notAfter']):
        raise ValueError('Invalid or expired start interval')
    if work['recipient'] == 'node' and work['target']['nodeBootID'] != peer_boot:
        raise ValueError('Wrong boot epoch')
    for name in ('scopeRef', 'authorityRef', 'budgetRef', 'auditRef'):
        if work[name]['region'] != 'eu-central' or timestamp(work[name]['expiresAt']) < timestamp(work['notAfter']):
            raise ValueError('Reference outlives fixture authority or leaves region')
    if work['purpose'] == 'saveRecording':
        if timestamp(work['payload']['windowEnd']) > timestamp(work['issuedAt']):
            raise ValueError('Save cannot use a future end')
        if work['payload']['lookbackMillis'] > 30000:
            raise ValueError('Exceeds synthetic source policy cap')

for work in works.values():
    validate_semantics(work)
    checks += 1
    for where in (None, 'payload'):
        for key in ('rawBody', 'command', 'callbackURL', 'unbounded'):
            bad = copy.deepcopy(work)
            (bad if where is None else bad[where])[key] = 'must not cross this boundary'
            rejected(lambda b=bad: validator.validate(b), key)
    for key, value in [('deliveryFence', 0), ('schemaVersion', 'internal-work/v9'), ('purpose', 'executeAnything'), ('recipient', 'anonymous')]:
        bad = copy.deepcopy(work); bad[key] = value
        rejected(lambda b=bad: validator.validate(b), key)
    for key, value in [('clusterId', '00000000-0000-4000-8000-000000000099'), ('notAfter', '2026-10-09T11:59:00Z')]:
        bad = copy.deepcopy(work); bad[key] = value
        rejected(lambda b=bad: validate_semantics(b), key)
    bad = copy.deepcopy(work); bad['authorityRef']['region'] = 'unapproved-region'
    rejected(lambda: validate_semantics(bad), 'reference region')

bad = copy.deepcopy(works['projectLive']); bad['payload']['projection'] = 'rawPackets'
rejected(lambda: validator.validate(bad), 'raw live projection')
bad = copy.deepcopy(works['saveRecording']); bad['payload']['lookbackMillis'] = 60000
rejected(lambda: validate_semantics(bad), 'effective source cap')
bad = copy.deepcopy(works['saveRecording']); bad['payload']['windowEnd'] = '2026-10-09T12:00:30Z'
rejected(lambda: validate_semantics(bad), 'future save end')
bad = copy.deepcopy(works['runAction']); bad['purpose'] = 'saveRecording'
rejected(lambda: validator.validate(bad), 'action masquerading as snapshot')
bad = copy.deepcopy(works['analysisStage']); bad['payload']['stage'] = 'runShell'
rejected(lambda: validator.validate(bad), 'arbitrary analysis stage')
bad = copy.deepcopy(works['eraseCopy']); bad['payload']['path'] = '/host'
rejected(lambda: validator.validate(bad), 'path in copy deletion')
bad = copy.deepcopy(works['runAction']); bad['target']['nodeBootID'] = '00000000-0000-4000-8000-000000000098'
rejected(lambda: validate_semantics(bad), 'boot substitution')
bad = copy.deepcopy(works['runAction']); bad['requiredCapabilities'] = ['control/v1'] * 33
rejected(lambda: validator.validate(bad), 'unbounded capabilities')

# A tiny specification model exercises the documented ambiguity rule. It is not
# the product journal and cannot prove distributed CAS, process or lease safety.
class StartModel:
    def __init__(self):
        self.records = {}
        self.starts = 0
        self.fence = 1
    def reserve(self, attempt, digest, boot):
        identity = (digest, boot)
        old = self.records.get(attempt)
        if old:
            if old['identity'] != identity:
                raise ValueError('Conflicting execution identity')
            return False
        self.records[attempt] = {'identity': identity, 'disposition': 'StartCommitted'}
        return True
    def dispatch(self, attempt, digest, boot, crash_before_effect=False):
        if self.reserve(attempt, digest, boot):
            if not crash_before_effect:
                self.starts += 1
            self.records[attempt]['disposition'] = 'Indeterminate'
    def complete(self, attempt, fence):
        if fence != self.fence:
            raise ValueError('Stale receipt fence')
        self.records[attempt]['disposition'] = 'Completed'

for crash in (False, True):
    model = StartModel()
    model.dispatch('attempt-1', 'scope-a', 'boot-a', crash)
    model.fence = 2
    model.dispatch('attempt-1', 'scope-a', 'boot-a')
    require(model.starts == (0 if crash else 1), 'Retry duplicated an effect')
    require(model.records['attempt-1']['disposition'] == 'Indeterminate', 'Uncertainty silently cleared')
    rejected(lambda: model.reserve('attempt-1', 'scope-b', 'boot-a'), 'scope drift')
    rejected(lambda: model.reserve('attempt-1', 'scope-a', 'boot-b'), 'boot drift')
    rejected(lambda: model.complete('attempt-1', 1), 'stale completion')
    require(len(model.records) == 1, 'Duplicate reservation')

report = {'date': '2026-10-09', 'scope': 'Design catalog, DTO and synthetic state checks only; no runtime/cryptographic qualification', 'applications': len(apps), 'components': len(components), 'interfaces': len(interfaces), 'domainEntitiesMapped': len(entities), 'requirementsMapped': len(requirements), 'positiveChecks': checks, 'rejectedInvalidCases': rejections}
(ROOT / 'docs/architecture/validation.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: ' + json.dumps(report))
