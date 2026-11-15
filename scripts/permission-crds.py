#!/usr/bin/env python3
"""Generate the structural permission CRDs from reviewed JSON contracts.

Conditional JSON Schema rules have explicit reviewed CEL equivalents. A source
conditional change fails generation until its translation is reviewed again.
No network reference resolver and no generic lossy JSON Schema conversion.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import implemented_contracts

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / 'specs/contracts'
DEST = ROOT / 'charts/asservat/crds'
TRANSLATIONS = {
 '7ceba9ef9299bfe56788e24703579765cdf4de124e0838ea8c8779641771e51c': [
  ('!has(self.automation) || (self.effect == "Allow" && self.subjects.all(s, s.kind == "Group") && "workload-maintainer" in self.roles)', 'Automation requires an Allow binding for groups with the workload-maintainer role.')],
 'ca287d063477d7b26ea7baf558506ee209267ee643ca3878962688bdb65da21c': [
  ('self.mode == "valueMap" ? (has(self.values) && size(self.values) > 0 && !has(self.prefix)) : !has(self.values)', 'valueMap requires nonempty values and no prefix; groupName forbids values.')],
 'c5c0f535ae92ebab8faf39dcdb265edfd8132d1c73d01a99843d03ac94b5cb3e': [
  ('self.mode == "qualifiedAdapter" ? has(self.adapterRef) : !has(self.adapterRef)', 'Only qualifiedAdapter requires adapterRef.')],
 'e957001253571ad3cad5907644a920a0b7ca36016b669a29071f76b1d3b16262': [
  ('self.type in ["namespaceMetadata", "workloadMetadata"] ? (has(self.protection) && has(self.metadataMapping) && !has(self.identityMappingRef) && !has(self.admissionParity) && !has(self.accessReview)) : (has(self.identityMappingRef) && has(self.admissionParity) && !has(self.protection) && !has(self.metadataMapping) && !has(self.workloadSelector))', 'Metadata and access-review sources require their own qualification fields.'),
  ('self.type == "workloadMetadata" ? (has(self.workloadSelector) && self.protection.mode == "admissionEnforced") : !has(self.workloadSelector)', 'Workload metadata requires workloadSelector and admissionEnforced protection.'),
  ('self.type != "kubernetesExec" || self.role == "workload-maintainer"', 'Exec inheritance provides the maintainer role only.'),
  ('self.type == "kubernetesAccessReview" ? has(self.accessReview) : !has(self.accessReview)', 'Only kubernetesAccessReview requires accessReview.')],
}
SCALARS = {'type','format','pattern','minimum','maximum','minLength','maxLength','minItems','maxItems','minProperties','maxProperties','required','enum','description','title'}

def resolve(ref):
    base, _, fragment = ref.partition('#')
    if not base.startswith('https://asservat.io/spec/v1/'):
        raise ValueError('nonlocal schema reference')
    name = base.removeprefix('https://asservat.io/spec/v1/')
    if '/' in name or '..' in name: raise ValueError('invalid schema reference')
    value = json.loads(implemented_contracts.path(name).read_text())
    if fragment:
        for key in fragment.removeprefix('/').split('/'):
            value = value[key.replace('~1','/').replace('~0','~')]
    return value

def structural(value):
    if '$ref' in value:
        if set(value) - {'$ref','description'}: raise ValueError('unreviewed reference siblings')
        out = structural(resolve(value['$ref']))
        if 'description' in value: out['description'] = value['description']
        return out
    out = {}
    for key, item in value.items():
        if key in SCALARS:
            # The API omits empty `required`. CRD versions are an atomic SSA
            # field, so retaining [] conflicts with Helm's stored version even
            # when an administrator reapplies the same schema during upgrade.
            # Absence and [] have identical validation semantics.
            if key == 'required' and item == []: continue
            out[key] = copy.deepcopy(item)
        elif key in {'properties'}: out[key] = {k: structural(v) for k,v in item.items()}
        elif key == 'items': out[key] = structural(item)
        elif key == 'additionalProperties':
            if isinstance(item,dict): out[key] = structural(item)
            elif item is not False: raise ValueError('unbounded object')
        elif key == 'uniqueItems':
            if item is not True: raise ValueError('unreviewed list uniqueness')
            out['x-kubernetes-list-type'] = 'set'
        elif key == 'allOf':
            sha = hashlib.sha256(json.dumps(item,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if sha not in TRANSLATIONS: raise ValueError('unreviewed conditional '+sha)
            out['x-kubernetes-validations'] = [{'rule':rule,'message':message} for rule,message in TRANSLATIONS[sha]]
        else: raise ValueError('unsupported schema keyword '+key)
    if out.get('x-kubernetes-list-type') == 'set' and out['items']['type'] == 'object':
        # Object sets pass CRD admission but are not usable by structured merge
        # apply in the qualified server. Explicit identity keys preserve GitOps.
        fields=set(out['items'].get('properties',{}))
        # Map keys must be required properties: the optional issuer and uid
        # are not part of an entry's identity.
        if fields == {'kind','issuer','id'}: keys=['kind','id']
        elif fields == {'kind','name','uid'}: keys=['kind','name']
        else: raise ValueError('unreviewed object-list identity')
        out['x-kubernetes-list-type']='map'
        out['x-kubernetes-list-map-keys']=keys
    return out

def render(kind, plural, file, scope='Namespaced'):
    source=json.loads(implemented_contracts.path(file).read_text())
    spec=structural(source['properties']['spec'])
    spec['description']='Desired permission configuration. A successful write does not activate access; inspect current-generation status.'
    status=structural(source['properties']['status'])
    return {'apiVersion':'apiextensions.k8s.io/v1','kind':'CustomResourceDefinition','metadata':{'name':plural+'.asservat.io'},'spec':{
      'group':'asservat.io','scope':scope,'names':{'plural':plural,'singular':plural[:-1],'kind':kind,'categories':['asservat']},
      'versions':[{'name':'v1alpha1','served':True,'storage':True,'subresources':{'status':{}},
        'additionalPrinterColumns':[{'name':'Phase','type':'string','jsonPath':'.status.phase'},{'name':'Observed','type':'integer','jsonPath':'.status.observedGeneration'},{'name':'Age','type':'date','jsonPath':'.metadata.creationTimestamp'}],
        'schema':{'openAPIV3Schema':{'type':'object','required':['spec'],'properties':{'apiVersion':{'type':'string'},'kind':{'type':'string'},'metadata':{'type':'object'},'spec':spec,'status':status}}}}]}}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
    for kind,plural,file,scope in [('AccessBinding','accessbindings','access-binding.schema.json','Namespaced'),('ClusterAccessBinding','clusteraccessbindings','cluster-access-binding.schema.json','Cluster'),('PermissionSource','permissionsources','permission-source.schema.json','Namespaced')]:
        text=json.dumps(render(kind,plural,file,scope),indent=2)+'\n';path=DEST/(plural+'.yaml')
        if args.write: path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
        elif not path.exists() or path.read_text()!=text: raise SystemExit('Stale CRD: '+str(path.relative_to(ROOT)))
    print('Permission CRD contracts match reviewed structural/CEL translation')
if __name__=='__main__':main()
