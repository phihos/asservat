"""Experimental local bundling/reference hoisting; never rewrites canonical schemas."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import yaml

parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
parser.add_argument('--hoist', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
spec = yaml.safe_load((root/'docs/interfaces/browser-openapi.yaml').read_text())
ids = {}
for path in sorted((root/'specs/contracts').glob('*.schema.json')):
    value = json.loads(path.read_text())
    name = 'Contract_' + path.stem.replace('.', '_').replace('-', '_')
    ids[value['$id']] = name
    spec['components']['schemas'][name] = value

def bundle(value):
    if isinstance(value, dict):
        if '$ref' in value:
            doc, _, fragment = value['$ref'].partition('#')
            if doc in ids:
                value['$ref'] = '#/components/schemas/' + ids[doc] + fragment
        value.pop('$id', None)
        for child in value.values():
            bundle(child)
    elif isinstance(value, list):
        for child in value:
            bundle(child)
bundle(spec)

if args.hoist:
    refs = set()
    def collect(value):
        if isinstance(value, dict):
            ref = value.get('$ref', '')
            if ref.startswith('#/components/schemas/') and len(ref.split('/')) > 4:
                refs.add(ref)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    collect(spec)
    mapping = {}
    for ref in sorted(refs):
        target = spec
        for token in ref[2:].split('/'):
            target = target[token.replace('~1', '/').replace('~0', '~')]
        name = 'Hoisted_' + hashlib.sha256(ref.encode()).hexdigest()[:16]
        assert name not in spec['components']['schemas']
        spec['components']['schemas'][name] = copy.deepcopy(target)
        mapping[ref] = '#/components/schemas/' + name
    def rewrite(value):
        if isinstance(value, dict):
            if value.get('$ref') in mapping:
                value['$ref'] = mapping[value['$ref']]
            for child in value.values():
                rewrite(child)
        elif isinstance(value, list):
            for child in value:
                rewrite(child)
    rewrite(spec)
args.output.write_text(json.dumps(spec, indent=2) + '\n')
