import { readFileSync, readdirSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv from 'ajv';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { parse } from 'yaml';
import { ManifestError, applyOverrides, nextVersion, profileManifest, type Definition } from './profile-manifest';
import type { Preview } from './http';

type Composition = NonNullable<Preview['profile_composition']>;
const repo = (path: string) => new URL('../../../' + path, import.meta.url);
const builtin = (name: string): Definition => JSON.parse(readFileSync(repo(`internal/application/planning/profiles/${name}-v1.json`), 'utf8')).definition;

// The actual CRD structural schema (x-kubernetes-* keywords are Kubernetes
// extensions; the immutability/name CEL rules are checked explicitly below).
function crdValidator() {
  const crd = parse(readFileSync(repo('charts/asservat/crds/captureprofiles.yaml'), 'utf8'));
  const version = crd.spec.versions.find((v: { name: string }) => v.name === 'v1alpha1');
  const strip = (value: unknown): unknown => Array.isArray(value) ? value.map(strip) : value && typeof value === 'object'
    ? Object.fromEntries(Object.entries(value).filter(([k]) => !k.startsWith('x-kubernetes-')).map(([k, v]) => [k, strip(v)])) : value;
  return { validate: new Ajv({ strict: false }).compile(strip(version.schema.openAPIV3Schema) as object), rules: version.schema.openAPIV3Schema['x-kubernetes-validations'] as { rule: string }[] };
}
// The canonical contract the hub admits definitions with.
function canonicalValidator() {
  const ajv = new Ajv2020({ strict: false });
  addFormats(ajv);
  const dir = 'specs/contracts/';
  for (const file of readdirSync(repo(dir)).filter(f => f.endsWith('.schema.json'))) ajv.addSchema(JSON.parse(readFileSync(repo(dir + file), 'utf8')));
  return ajv.getSchema('https://asservat.io/spec/v1/capture-profile.schema.json')!;
}

const composition = (overrides: Composition['authored']['components'][number]['overrides'], name = 'network-connections'): Composition => ({
  authored: { components: [{ id: 'net', profileRef: { catalog: 'builtin', name, version: 'v1' }, overrides }], maxTotalBytes: 8 << 20, maxDuration: '15s' } as Composition['authored'],
  resolvedProfiles: [{ componentID: 'net', profileRef: { catalog: 'builtin', name, version: 'v1' }, definitionDigest: 'a'.repeat(64) }],
  actionMap: [{ componentID: 'net', localActionID: 'sample', actionID: 'a' + '1'.repeat(24), deduplicated: false }],
});

describe('profileManifest (REQ-CPR-005 Save as profile)', () => {
  const edits = [
    { actionID: 'sample', field: 'packetFilter', value: 'tcp port 8443' },
    { actionID: 'sample', field: 'packetBefore', value: '0s' },
    { actionID: 'sample', field: 'actionExecutionMode', value: 'onTrigger' },
    { actionID: 'sample', field: 'actionTimeout', value: '20s' },
  ] as NonNullable<Composition['authored']['components'][number]['overrides']>;

  it('materializes reviewed edits as defaults in a manifest the CRD and canonical schema accept', () => {
    const source = builtin('network-connections');
    const m = profileManifest({ namespace: 'payments', name: 'net-8443', version: 'v1', displayName: 'TLS port traffic', source, composition: composition(edits) });
    const crd = crdValidator();
    expect(crd.validate(m), JSON.stringify(crd.validate.errors)).toBe(true);
    const canonical = canonicalValidator();
    expect(canonical(m), JSON.stringify(canonical.errors)).toBe(true);
    // Both validators are discriminating, not vacuous.
    expect(canonical({ ...m, spec: { ...m.spec, recipients: [] } })).toBe(false);
    expect(canonical({ ...m, spec: { ...m.spec, definition: { ...m.spec.definition, recipe: { ...m.spec.definition.recipe, maxTotalBytes: -1 } } } })).toBe(false);
    expect(crd.validate({ ...m, spec: { ...m.spec, version: 'latest' } })).toBe(false);
    // x-kubernetes-validations: object name and immutable identity.
    expect(crd.rules.map(r => r.rule)).toContain('self.metadata.name == self.spec.name + "." + self.spec.version');
    expect(m.metadata).toEqual({ name: 'net-8443.v1', namespace: 'payments' });
    expect(m.apiVersion).toBe('asservat.io/v1alpha1');
    expect(m.kind).toBe('CaptureProfile');
    expect(m.spec.availability).toEqual({ enabled: true, deprecated: false });
    const action = m.spec.definition.recipe.actions[0] as unknown as { executionMode: string; parameters: { filter: string; before: string; after: string }; limits: { timeout: string } };
    expect(action).toMatchObject({ executionMode: 'onTrigger', parameters: { filter: 'tcp port 8443', before: '0s', after: '10s' }, limits: { timeout: '20s' } });
    expect(m.spec.definition.editableFields).toEqual(source.editableFields);
    expect(m.spec.definition.recipe).toMatchObject({ maxTotalBytes: 8 << 20, maxDuration: '15s' });
    expect(m.spec.definition.displayName).toBe('TLS port traffic');
    expect(m.spec.definition.origins).toEqual([{ componentID: 'net', profileRef: { catalog: 'builtin', name: 'network-connections', version: 'v1' }, definitionDigest: 'a'.repeat(64) }]);
    // The source definition is not mutated.
    expect((source.recipe.actions[0] as unknown as { executionMode: string }).executionMode).toBe('ongoing');
    // Nothing beyond the definition contract: no grants, owners, recipients, sharing or approvals.
    expect(JSON.stringify(m)).not.toMatch(/grant|owner|recipient|sharing|approv|target/i);
  });

  it('saves syscall edits into their typed recipe locations', () => {
    const source = builtin('syscall-activity');
    const derived = applyOverrides(source, [
      { actionID: 'syscalls', field: 'syscallFilter', value: { mode: 'include', names: ['openat'] } },
      { actionID: 'syscalls', field: 'syscallMaxEvents', value: 5000 },
    ] as Parameters<typeof applyOverrides>[1]);
    expect(derived.recipe.actions[0]).toMatchObject({ parameters: { syscalls: { mode: 'include', names: ['openat'] }, maxEvents: 5000 } });
  });

  it('refuses existing versions, invalid names, unmodeled fields and multi-profile plans', () => {
    const source = builtin('network-connections');
    const base = { namespace: 'payments', name: 'net', version: 'v2', displayName: 'x', source, composition: composition([]) };
    expect(() => profileManifest({ ...base, existingVersions: ['v1', 'v2'] })).toThrow(/already exists/);
    expect(() => profileManifest({ ...base, name: 'Net' })).toThrow(ManifestError);
    expect(() => profileManifest({ ...base, version: '2' })).toThrow(ManifestError);
    expect(() => profileManifest({ ...base, namespace: 'Payments' })).toThrow(ManifestError);
    expect(() => profileManifest({ ...base, composition: composition([{ actionID: 'sample', field: 'commandArgv', value: ['sh'] }] as never) })).toThrow(/cannot be saved/);
    const two = composition([]);
    two.authored.components.push({ id: 'b', profileRef: { catalog: 'builtin', name: 'syscall-activity', version: 'v1' } });
    expect(() => profileManifest({ ...base, composition: two })).toThrow(/exactly one profile/);
  });

  it('proposes the next unused version', () => {
    expect(nextVersion([])).toBe('v1');
    expect(nextVersion(['v1', 'v3', 'latest'])).toBe('v4');
  });
});
