import type { Data, Preview } from './http';

// "Save as profile" (REQ-CPR-005): the console renders a new immutable
// CaptureProfile version for the user to publish with their own Kubernetes
// rights. Nothing is written by the server. The derived definition is the
// source definition with the reviewed edits materialized as new defaults; it
// keeps the editable-field list and records the source only as a
// non-executable origin. Grants, owners, recipients, approvals, target and
// sharing are not part of a definition and are never copied.

export type Definition = Data<'get_capture_profile'>['definition'];
type Composition = NonNullable<Preview['profile_composition']>;
type Override = NonNullable<Composition['authored']['components'][number]['overrides']>[number];

// Typed override field -> recipe action location (mirrors applyEdit in
// internal/application/planning/recorder.go). Fields the compiler does not
// model in this release are refused rather than guessed.
const locations: Record<string, readonly string[]> = {
  packetPeers: ['parameters', 'peers'], packetFilter: ['parameters', 'filter'], packetBefore: ['parameters', 'before'], packetAfter: ['parameters', 'after'], packetRing: ['parameters', 'ring'],
  syscallFilter: ['parameters', 'syscalls'], syscallMode: ['parameters', 'mode'], syscallBefore: ['parameters', 'before'], syscallAfter: ['parameters', 'after'], syscallRing: ['parameters', 'ring'],
  syscallMaxEvents: ['parameters', 'maxEvents'], syscallRate: ['parameters', 'maxEventsPerSecond'], syscallArguments: ['parameters', 'arguments'],
  actionMaxBytes: ['limits', 'maxBytes'], actionTimeout: ['limits', 'timeout'], actionExecutionMode: ['executionMode'],
};

export const namePattern = /^[a-z][a-z0-9-]{0,62}$/;
export const versionPattern = /^v[1-9][0-9]*$/;
const namespacePattern = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;

export class ManifestError extends Error {}

export function applyOverrides(definition: Definition, overrides: Override[]): Definition {
  const derived = structuredClone(definition);
  for (const o of overrides) {
    const path = locations[o.field];
    if (!path) throw new ManifestError(`${o.field} cannot be saved into a profile in this release.`);
    if (!definition.editableFields.some(f => f.actionID === o.actionID && f.field === o.field)) throw new ManifestError(`${o.actionID} / ${o.field} is not editable in the source profile.`);
    const action = derived.recipe.actions.find(a => (a as { id: string }).id === o.actionID) as Record<string, unknown> | undefined;
    if (!action) throw new ManifestError(`The source profile has no action ${o.actionID}.`);
    let node = action;
    for (const part of path.slice(0, -1)) node = (node[part] ??= {}) as Record<string, unknown>;
    node[path[path.length - 1]] = structuredClone(o.value);
  }
  return derived;
}

export function nextVersion(versions: string[]): string {
  const n = Math.max(0, ...versions.filter(v => versionPattern.test(v)).map(v => Number(v.slice(1))));
  return 'v' + (n + 1);
}

export type ManifestInput = {
  namespace: string; name: string; version: string; displayName: string;
  source: Definition; composition: Composition; existingVersions?: string[];
};

// Only a single-component reviewed plan can become one profile version.
export function profileManifest({ namespace, name, version, displayName, source, composition, existingVersions = [] }: ManifestInput) {
  if (!namespacePattern.test(namespace)) throw new ManifestError('Enter a Kubernetes namespace name (lowercase letters, digits and hyphens, at most 63 characters).');
  if (!namePattern.test(name)) throw new ManifestError('The profile name starts with a lowercase letter and uses at most 63 lowercase letters, digits and hyphens.');
  if (!versionPattern.test(version) || version.length > 32) throw new ManifestError('The version has the form v1, v2, …');
  if (existingVersions.includes(version)) throw new ManifestError(`${name} ${version} already exists. Published versions are immutable; choose a new version.`);
  const title = displayName.trim();
  if (title.length < 1 || title.length > 128) throw new ManifestError('Enter a display name of at most 128 characters.');
  const [component] = composition.authored.components;
  const resolved = composition.resolvedProfiles.find(p => p.componentID === component?.id);
  if (composition.authored.components.length !== 1 || !resolved) throw new ManifestError('Only a plan with exactly one profile can be saved as a profile.');
  const derived = applyOverrides(source, component.overrides ?? []);
  derived.displayName = title;
  // The reviewed aggregate bounds become the recipe's planning totals.
  derived.recipe.maxTotalBytes = composition.authored.maxTotalBytes;
  derived.recipe.maxDuration = composition.authored.maxDuration;
  derived.origins = [...(source.origins ?? []), structuredClone(resolved)].slice(-8);
  return {
    apiVersion: 'asservat.io/v1alpha1', kind: 'CaptureProfile',
    // The CRD requires metadata.name == spec.name + "." + spec.version.
    metadata: { name: `${name}.${version}`, namespace },
    spec: { name, version, definition: derived, availability: { enabled: true, deprecated: false } },
  };
}
