#!/usr/bin/env python3
"""Reviewed structural EvidenceStoragePool and EvidenceBudgetPolicy CRDs (ADR-190).

Neither contract has a status: the capacity source reader ignores status, so
the CRDs declare no status subresource and the API server prunes any.
"""
import argparse
import importlib.util
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('permission_crds',ROOT/'scripts/permission-crds.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
# The budget policy carries one schema default, which CRDs apply at admission.
base.SCALARS=base.SCALARS|{'default'}

def single(value):
    """A JSON Schema const is exactly a one-value enum, which CRDs support."""
    if isinstance(value,dict):
        if 'const' in value:
            assert 'enum' not in value
            value['enum']=[value.pop('const')]
        if 'enum' in value and 'type' not in value:
            # Structural schemas need a type; the contract's values imply it.
            kinds={ {bool:'boolean',int:'integer',str:'string'}[type(v)] for v in value['enum'] }
            assert len(kinds)==1
            value['type']=kinds.pop()
        for v in value.values(): single(v)
    elif isinstance(value,list):
        for v in value: single(v)
    return value

def pool():
    raw=single(json.loads((ROOT/'specs/contracts/storage-pool.schema.json').read_text())['properties']['spec'])
    assert raw['properties']['protectedAllocations'].pop('uniqueItems') is True
    body=base.structural(raw)
    body['properties']['protectedAllocations']['x-kubernetes-list-type']='map'
    body['properties']['protectedAllocations']['x-kubernetes-list-map-keys']=['budgetPolicyRef']
    return body

def policy():
    raw=single(json.loads((ROOT/'specs/contracts/budget-policy.schema.json').read_text())['properties']['spec'])
    labels=raw['properties']['scope']['properties']['namespaceSelector']['properties']['matchLabels']
    assert labels.pop('propertyNames')=={'maxLength':253}
    body=base.structural(raw)
    labels=body['properties']['scope']['properties']['namespaceSelector']['properties']['matchLabels']
    labels['x-kubernetes-validations']=[{'rule':'self.all(k, size(k) <= 253)','message':'Label keys are at most 253 characters.'}]
    return body

def typed(value, path):
    """Every structural property needs a type; the API server rejects the CRD otherwise."""
    for key,child in value.get('properties',{}).items():
        if 'type' not in child: raise SystemExit('untyped structural property '+path+'.'+key)
        typed(child,path+'.'+key)
    if isinstance(value.get('items'),dict): typed(value['items'],path+'[]')
    if isinstance(value.get('additionalProperties'),dict): typed(value['additionalProperties'],path+'{}')

def render(kind, plural, singular, body):
    typed(body,kind)
    return {'apiVersion':'apiextensions.k8s.io/v1','kind':'CustomResourceDefinition','metadata':{'name':plural+'.asservat.io'},'spec':{
      'group':'asservat.io','scope':'Namespaced','names':{'plural':plural,'singular':singular,'kind':kind,'categories':['asservat']},
      'versions':[{'name':'v1alpha1','served':True,'storage':True,
        'additionalPrinterColumns':[{'name':'Age','type':'date','jsonPath':'.metadata.creationTimestamp'}],
        'schema':{'openAPIV3Schema':{'type':'object','required':['spec'],'properties':{'apiVersion':{'type':'string'},'kind':{'type':'string'},'metadata':{'type':'object'},'spec':body}}}}]}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
    for kind,plural,singular,body in [('EvidenceStoragePool','evidencestoragepools','evidencestoragepool',pool()),('EvidenceBudgetPolicy','evidencebudgetpolicies','evidencebudgetpolicy',policy())]:
        path=ROOT/'charts/asservat/crds'/(plural+'.yaml');data=json.dumps(render(kind,plural,singular,body),indent=2)+'\n'
        if a.write:path.write_text(data)
        elif not path.exists() or path.read_text()!=data:raise SystemExit('Stale capacity CRD: '+plural)
    print('Capacity CRDs match the reviewed storage pool and budget policy contracts')
if __name__=='__main__':main()
