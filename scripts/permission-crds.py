#!/usr/bin/env python3
"""Generate the two structural permission CRDs from reviewed JSON contracts.

Conditional JSON Schema rules have explicit reviewed CEL equivalents. A source
conditional change fails generation until its translation is reviewed again.
No network reference resolver and no generic lossy JSON Schema conversion.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / 'specs/contracts'
DEST = ROOT / 'charts/asservat/crds'
TRANSLATIONS = {
 '7ceba9ef9299bfe56788e24703579765cdf4de124e0838ea8c8779641771e51c': [
  ('!has(self.automation) || (self.effect == "Allow" && self.subjects.all(s, s.kind == "Group") && "workload-maintainer" in self.roles)', 'Automation requires an Allow binding for groups with the workload-maintainer role.')],
 '797abc97a213fd1b27fed6356963468486529357087c303292eff0fdc24fe7e2': [
  ('self.mode != "admissionEnforced" || has(self.guardRef)', 'An enforcing protection profile requires guardRef.')],
 'd0786f2c446c4c18017691e9faf8e06209e51839cfab4b6894bd21683cd8fc03': [
  ('self.mode == "valueMap" ? (has(self.values) && size(self.values) > 0) : !has(self.values)', 'valueMap requires nonempty values; groupID forbids values.')],
 'c5c0f535ae92ebab8faf39dcdb265edfd8132d1c73d01a99843d03ac94b5cb3e': [
  ('self.mode == "qualifiedAdapter" ? has(self.adapterRef) : !has(self.adapterRef)', 'Only qualifiedAdapter requires adapterRef.')],
 '4426b579ecc9e4f6c758e2491bd9f00de54a84b51dd73851fc1039496212f771': [
  ('self.type in ["namespaceMetadata", "workloadMetadata"] ? (has(self.protection) && has(self.metadataMapping) && !has(self.identityMappingRef) && !has(self.admissionParity) && !has(self.accessReview)) : (has(self.identityMappingRef) && has(self.admissionParity) && self.role in ["evidence-reader", "workload-maintainer"] && !has(self.protection) && !has(self.metadataMapping) && !has(self.workloadSelector))', 'Metadata and access-review sources require their own qualification fields.'),
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
    value = json.loads((CONTRACTS/name).read_text())
    if fragment:
        for key in fragment.removeprefix('/').split('/'):
            value = value[key.replace('~1','/').replace('~0','~')]
    return value

def structural(value):
    if '$ref' in value:
        if len(value) != 1: raise ValueError('unreviewed reference siblings')
        return structural(resolve(value['$ref']))
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
        if fields == {'kind','issuer','id'}: keys=['kind','issuer','id']
        elif fields == {'kind','name','uid'}: keys=['uid']
        else: raise ValueError('unreviewed object-list identity')
        out['x-kubernetes-list-type']='map'
        out['x-kubernetes-list-map-keys']=keys
    return out

def render(kind, plural, file):
    source=json.loads((CONTRACTS/file).read_text())
    spec=structural(source['properties']['spec'])
    spec['description']='Desired permission configuration. A successful write does not activate access; inspect current-generation status.'
    status=structural(source['properties']['status'])
    return {'apiVersion':'apiextensions.k8s.io/v1','kind':'CustomResourceDefinition','metadata':{'name':plural+'.asservat.io'},'spec':{
      'group':'asservat.io','scope':'Namespaced','names':{'plural':plural,'singular':plural[:-1],'kind':kind,'categories':['asservat']},
      'versions':[{'name':'v1alpha1','served':True,'storage':True,'subresources':{'status':{}},
        'additionalPrinterColumns':[{'name':'Phase','type':'string','jsonPath':'.status.phase'},{'name':'Observed','type':'integer','jsonPath':'.status.observedGeneration'},{'name':'Age','type':'date','jsonPath':'.metadata.creationTimestamp'}],
        'schema':{'openAPIV3Schema':{'type':'object','required':['spec'],'properties':{'apiVersion':{'type':'string'},'kind':{'type':'string'},'metadata':{'type':'object'},'spec':spec,'status':status}}}}]}}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
    for kind,plural,file in [('AccessBinding','accessbindings','access-binding.schema.json'),('PermissionSource','permissionsources','permission-source.schema.json')]:
        text=json.dumps(render(kind,plural,file),indent=2)+'\n';path=DEST/(plural+'.yaml')
        if args.write: path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
        elif not path.exists() or path.read_text()!=text: raise SystemExit('Stale CRD: '+str(path.relative_to(ROOT)))
    print('Permission CRD contracts match reviewed structural/CEL translation')
if __name__=='__main__':main()
