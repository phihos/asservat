#!/usr/bin/env python3
"""Reviewed structural retention contract with explicit selector/list CEL rules."""
import argparse
import importlib.util
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('permission_crds',ROOT/'scripts/permission-crds.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def render():
    source=json.loads((ROOT/'specs/contracts/retention-policy.schema.json').read_text())
    raw=source['properties']['spec']
    for selector in ['namespaceSelector','workloadSelector']:
        labels=raw['properties']['scope']['properties'][selector]['properties']['matchLabels']
        assert labels.pop('propertyNames')=={'maxLength':253}
    assert raw['properties']['rules'].pop('uniqueItems') is True
    body=base.structural(raw)
    for selector in ['namespaceSelector','workloadSelector']:
        labels=body['properties']['scope']['properties'][selector]['properties']['matchLabels']
        labels['x-kubernetes-validations']=[{'rule':'self.all(k, size(k) <= 253)','message':'Label keys are at most 253 characters.'}]
    body['properties']['rules']['x-kubernetes-list-type']='map'
    body['properties']['rules']['x-kubernetes-list-map-keys']=['name']
    body['x-kubernetes-validations']=[{'rule':'self.deletionBudgetSeconds < self.maxima.evidenceSeconds && self.rules.all(r, self.deletionBudgetSeconds < r.maxAgeSeconds)','message':'Deletion budget must leave positive usable evidence lifetime.'}]
    status=base.structural(source['properties']['status'])
    status['properties']['clusterAcknowledgements']['x-kubernetes-list-type']='map'
    status['properties']['clusterAcknowledgements']['x-kubernetes-list-map-keys']=['clusterID']
    status['properties']['clusterAcknowledgements']['items']['x-kubernetes-validations']=[{'rule':'timestamp(self.validUntil) > timestamp(self.observedAt) && timestamp(self.validUntil) <= timestamp(self.observedAt) + duration("60s")','message':'Cluster acknowledgement freshness is positive and at most sixty seconds.'}]
    return {'apiVersion':'apiextensions.k8s.io/v1','kind':'CustomResourceDefinition','metadata':{'name':'evidenceretentionpolicies.asservat.io'},'spec':{'group':'asservat.io','scope':'Namespaced','names':{'kind':'EvidenceRetentionPolicy','plural':'evidenceretentionpolicies','singular':'evidenceretentionpolicy','categories':['asservat']},'versions':[{'name':'v1alpha1','served':True,'storage':True,'subresources':{'status':{}},'additionalPrinterColumns':[{'name':'Phase','type':'string','jsonPath':'.status.phase'},{'name':'Observed','type':'integer','jsonPath':'.status.observedGeneration'}],'schema':{'openAPIV3Schema':{'type':'object','required':['spec'],'properties':{'apiVersion':{'type':'string'},'kind':{'type':'string'},'metadata':{'type':'object'},'spec':body,'status':status}}}}]}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
    path=ROOT/'charts/asservat/crds/evidenceretentionpolicies.yaml';data=json.dumps(render(),indent=2)+'\n'
    if a.write:path.write_text(data)
    elif not path.exists() or path.read_text()!=data:raise SystemExit('Stale retention CRD')
    print('Retention CRD matches reviewed scope, limits and status contract')
if __name__=='__main__':main()
