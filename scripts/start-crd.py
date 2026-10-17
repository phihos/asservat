#!/usr/bin/env python3
"""Reviewed initial local-start profile; bounded immutable spec and spend CAS.

This is not a generic JSON Schema translator. The status conditional is checked
explicitly before its CEL translation, so source changes cannot silently drift.
"""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def render():
    schema = json.loads((ROOT/'specs/contracts/local-start.schema.json').read_text())
    spec = copy.deepcopy(schema['properties']['spec'])
    status = copy.deepcopy(schema['properties']['status'])
    class_rules = spec.pop('allOf')
    assert class_rules == [{'if': {'properties': {'profile': {'const': 'apiContextStart/v1'}}}, 'then': {'required': ['executorPodUID', 'executorAccountUID'], 'properties': {'actionID': {'const': 'pod-status'}, 'nativeBytes': {'const': 4096}}, 'not': {'anyOf': [{'required': ['nodeUID']}, {'required': ['nodeBootID']}]}}, 'else': {'required': ['nodeUID', 'nodeBootID'], 'not': {'anyOf': [{'required': ['executorPodUID']}, {'required': ['executorAccountUID']}]}}}]
    assert spec['properties']['profile']['enum'] == ['onTriggerStart/v1', 'apiContextStart/v1']
    assert status.pop('allOf') == [{'if': {'properties': {'phase': {'const': 'StartCommitted'}}}, 'then': {'required': ['committedAt']}, 'else': {'not': {'required': ['committedAt']}}}]
    assert spec.pop('additionalProperties') is False
    assert status.pop('additionalProperties') is False
    spec['x-kubernetes-validations'] = [
        {'rule':'self == oldSelf','message':'A prepaid start binding is immutable.'},
        {'rule':'self.profile == "apiContextStart/v1" ? (has(self.executorPodUID) && has(self.executorAccountUID) && !has(self.nodeUID) && !has(self.nodeBootID) && self.actionID == "pod-status" && self.nativeBytes == 4096 && timestamp(self.notAfter) <= timestamp(self.notBefore) + duration("5s")) : (has(self.nodeUID) && has(self.nodeBootID) && !has(self.executorPodUID) && !has(self.executorAccountUID))','message':'Execution profile requires exactly its own identity and limits.'},
        {'rule':'timestamp(self.notAfter) > timestamp(self.notBefore) && timestamp(self.notAfter) <= timestamp(self.notBefore) + duration("60s")','message':'Start permit lifetime must be positive and at most 60 seconds.'}]
    status['x-kubernetes-validations'] = [{'rule':'self.phase == "StartCommitted" ? has(self.committedAt) : !has(self.committedAt)','message':'Only a consumed start has committedAt.'}]
    return {'apiVersion':'apiextensions.k8s.io/v1','kind':'CustomResourceDefinition','metadata':{'name':'capacityreservations.asservat.io'},'spec':{
        'group':'asservat.io','scope':'Namespaced','names':{'kind':'CapacityReservation','plural':'capacityreservations','singular':'capacityreservation','categories':['asservat']},
        'versions':[{'name':'v1alpha1','served':True,'storage':True,'subresources':{'status':{}},'additionalPrinterColumns':[{'name':'Phase','type':'string','jsonPath':'.status.phase'}],
        'schema':{'openAPIV3Schema':{'type':'object','required':['spec'],'properties':{'apiVersion':{'type':'string'},'kind':{'type':'string'},'metadata':{'type':'object'},'spec':spec,'status':status},
        'x-kubernetes-validations':[
            {'rule':'self.metadata.name == "start-" + self.spec.attemptID','message':'The name is bound to the immutable attempt.'},
            {'rule':'!has(oldSelf.status) || (has(self.status) && (self.status == oldSelf.status || (oldSelf.status.phase == "Ready" && self.status.phase == "StartCommitted")))','message':'Consumed starts cannot be reset or erased.'},
            {'rule':'has(oldSelf.status) || !has(self.status) || self.status.phase == "Ready"','message':'A reservation must become Ready before consumption.'},
            {'rule':'!has(self.status) || !has(self.status.committedAt) || (timestamp(self.status.committedAt) >= timestamp(self.spec.notBefore) && timestamp(self.status.committedAt) < timestamp(self.spec.notAfter))','message':'Recorded consumption must be within the original permit interval.'}
        ]}}}]}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');args=p.parse_args()
    path=ROOT/'charts/asservat/crds/capacityreservations.yaml'
    data=json.dumps(render(),indent=2)+'\n'
    if args.write:path.write_text(data)
    elif not path.exists() or path.read_text()!=data:raise SystemExit('Stale local-start CRD')
    print('Local-start CRD matches reviewed immutable spec and spend transitions')

if __name__=='__main__':main()
