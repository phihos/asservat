#!/usr/bin/env python3
"""CaptureProfile CRD (REQ-CPR-001) from specs/contracts/capture-profile.schema.json.

Name, version and availability are structural. The definition's typed action
parameters are a per-kind union Kubernetes cannot express structurally, so it
is preserved JSON, like DebugPolicy override values; the hub's canonical
reader validates it against the embedded contract before any use. A
transition rule keeps identity and definition immutable (a new version is a
new object named <name>.<version>); only availability may change.
"""
import argparse
import copy
import json
from pathlib import Path

import implemented_contracts

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'charts/asservat/crds/captureprofiles.yaml'


def render():
    source = json.loads(implemented_contracts.path('capture-profile.schema.json').read_text())
    raw = source['properties']['spec']
    assert raw['additionalProperties'] is False and set(raw['properties']) == {'name', 'version', 'definition', 'availability'}
    availability = raw['properties']['availability']
    assert availability['additionalProperties'] is False
    spec = {
        'type': 'object',
        'required': copy.deepcopy(raw['required']),
        'properties': {
            'name': copy.deepcopy(raw['properties']['name']) | {'type': 'string'},
            'version': copy.deepcopy(raw['properties']['version']) | {'type': 'string'},
            # Validated canonically by the hub before resolution.
            'definition': {'type': 'object', 'x-kubernetes-preserve-unknown-fields': True},
            'availability': {'type': 'object', 'required': copy.deepcopy(availability['required']),
                             'properties': {k: {'type': 'boolean'} for k in availability['properties']}},
        },
        'x-kubernetes-validations': [{
            'rule': 'self.name == oldSelf.name && self.version == oldSelf.version && self.definition == oldSelf.definition',
            'message': 'A published profile version is immutable; publish a new version instead.'}],
    }
    root = {'type': 'object', 'required': ['spec'], 'properties': {
        'apiVersion': {'type': 'string'}, 'kind': {'type': 'string'}, 'metadata': {'type': 'object'}, 'spec': spec},
        'x-kubernetes-validations': [{
            'rule': 'self.metadata.name == self.spec.name + "." + self.spec.version',
            'message': 'The object name is <name>.<version>.'}]}
    return {'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition', 'metadata': {'name': 'captureprofiles.asservat.io'},
            'spec': {'group': 'asservat.io', 'scope': 'Namespaced',
                     'names': {'kind': 'CaptureProfile', 'plural': 'captureprofiles', 'singular': 'captureprofile', 'categories': ['asservat']},
                     'versions': [{'name': 'v1alpha1', 'served': True, 'storage': True,
                                   'additionalPrinterColumns': [
                                       {'name': 'Profile', 'type': 'string', 'jsonPath': '.spec.name'},
                                       {'name': 'Version', 'type': 'string', 'jsonPath': '.spec.version'},
                                       {'name': 'Enabled', 'type': 'boolean', 'jsonPath': '.spec.availability.enabled'},
                                       {'name': 'Deprecated', 'type': 'boolean', 'jsonPath': '.spec.availability.deprecated'}],
                                   'schema': {'openAPIV3Schema': root}}]}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--write', action='store_true')
    a = p.parse_args()
    data = json.dumps(render(), indent=2) + '\n'
    if a.write:
        DEST.write_text(data)
    elif not DEST.exists() or DEST.read_text() != data:
        raise SystemExit('Stale CaptureProfile CRD; run scripts/profile-crd.py --write')
    print('CaptureProfile CRD matches the reviewed contract')


if __name__ == '__main__':
    main()
