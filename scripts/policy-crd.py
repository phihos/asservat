#!/usr/bin/env python3
"""Synchronize composition and grant-reference fields in the DebugPolicy CRD.

The other ADR-228 detector/target fields remain hand-reviewed. Kubernetes cannot
express a structural string/integer/object/array union for override.value. Only
that leaf preserves JSON; the existing bounded canonical policy reader validates
its discriminator and exact value schema before compilation or acceptance.
"""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / 'specs/contracts'
DEST = ROOT / 'charts/asservat/crds/debugpolicies.yaml'


def resolve(ref):
    prefix = 'https://asservat.io/spec/v1/'
    base, _, fragment = ref.partition('#')
    if not base.startswith(prefix) or '/' in base[len(prefix):]:
        raise ValueError('nonlocal composition schema reference')
    value = json.loads((CONTRACTS / base[len(prefix):]).read_text())
    for key in fragment.removeprefix('/').split('/') if fragment else []:
        value = value[key]
    return value


def shape(node):
    if '$ref' in node:
        assert set(node) == {'$ref'}
        return shape(resolve(node['$ref']))
    out = {}
    for key, value in node.items():
        if key == 'additionalProperties':
            assert value is False  # Kubernetes prunes undeclared object fields.
        elif key == 'properties':
            out[key] = {name: shape(child) for name, child in value.items()}
        elif key == 'items':
            out[key] = shape(value)
        elif key in {'type', 'format', 'required', 'minItems', 'maxItems', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'enum'}:
            out[key] = copy.deepcopy(value)
        else:
            raise ValueError('unreviewed composition schema keyword ' + key)
    if 'enum' in out and 'type' not in out:
        assert all(isinstance(value, str) for value in out['enum'])
        out['type'] = 'string'
    return out


def composition_shape():
    source = json.loads((CONTRACTS / 'capture-composition.schema.json').read_text())
    variants = source['$defs']['override']['oneOf']
    fields = [v['properties']['field']['const'] for v in variants]
    assert len(fields) == len(set(fields))
    assert all(set(v['properties']) == {'actionID', 'field', 'value'} and v['required'] == ['actionID', 'field', 'value'] for v in variants)
    action = variants[0]['properties']['actionID']
    assert all(v['properties']['actionID'] == action for v in variants)
    override = {'type': 'object', 'required': ['actionID', 'field', 'value'], 'properties': {
        'actionID': shape(action), 'field': {'type': 'string', 'enum': fields},
        'value': {'x-kubernetes-preserve-unknown-fields': True}}}
    component = copy.deepcopy(source['$defs']['component'])
    component['properties']['overrides']['items'] = override
    # The leaf is deliberately the only exception to normal typed conversion.
    edits = component['properties'].pop('overrides')
    result = shape(component)
    result['properties']['overrides'] = {k: copy.deepcopy(v) for k, v in edits.items()}
    props = copy.deepcopy(source['properties'])
    props['components']['items'] = result
    top = {k: copy.deepcopy(source[k]) for k in ['type', 'required']}
    top['properties'] = {k: shape(v) for k, v in props.items() if k != 'components'}
    top['properties']['components'] = props['components']
    return top


def synchronize(crd):
    source = json.loads((CONTRACTS / 'policy.schema.json').read_text())['properties']['spec']['oneOf']
    recipe = next(v for v in source if 'recipeRef' in v.get('properties', {}))
    composed = next(v for v in source if 'profileComposition' in v.get('properties', {}))
    assert set(recipe['required']) - {'recipeRef'} == set(composed['required']) - {'profileComposition'}
    spec = crd['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']
    spec['required'] = [name for name in recipe['required'] if name != 'recipeRef']
    spec['oneOf'] = [{'required': ['recipeRef']}, {'required': ['profileComposition']}]
    spec['properties']['profileComposition'] = composition_shape()
    assert recipe['properties']['grantRef'] == composed['properties']['grantRef']
    spec['properties']['grantRef'] = shape(recipe['properties']['grantRef'])
    spec['description'] = 'Hub-held policy with exactly one recipeRef or bounded profileComposition. The current compiler admits its supported detector/action subset before independently audited acceptance; persisted configuration and status are not execution authority. Composition override values retain their original JSON types for canonical field-specific validation.'
    return crd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    actual = DEST.read_text()
    expected = json.dumps(synchronize(json.loads(actual)), indent=2) + '\n'
    if args.write:
        DEST.write_text(expected)
    elif actual != expected:
        raise SystemExit('Stale DebugPolicy composition projection; run scripts/policy-crd.py --write')
    print('DebugPolicy composition projection matches canonical fields, bounds and recipe/composition exclusivity')


if __name__ == '__main__':
    main()
