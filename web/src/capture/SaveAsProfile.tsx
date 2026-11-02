import { useState, type ChangeEvent } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operations, operationMessage, OperationFailure, type Operations, type Preview, type Target } from './http';
import { ManifestError, nextVersion, profileManifest, type Definition } from './profile-manifest';

type Composition = NonNullable<Preview['profile_composition']>;
type Loaded = { definition: Definition; versions: string[] };

// Renders a new immutable CaptureProfile version from a reviewed
// single-profile plan. The user publishes it with their own Kubernetes
// rights; the console never writes it.
export function SaveAsProfile({ session, scope, target, composition, client = operations }: { session: Session; scope: AbortSignal; target: Target; composition: Composition; client?: Operations }) {
  const component = composition.authored.components[0];
  const [loaded, setLoaded] = useState<Loaded>();
  const [form, setForm] = useState({ namespace: target.namespace, name: component.profileRef.name, version: '', displayName: '' });
  const [error, setError] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [loading, setLoading] = useState(false);
  const open = async () => {
    setLoading(true); setError(undefined);
    try {
      const profile = await client.call('get_capture_profile', { target_ref: structuredClone(target), profile_ref: structuredClone(component.profileRef) }, session.csrf_token, scope);
      if (profile.status !== 'ok') throw new OperationFailure(503, profile.status === 'error' ? profile.data.code : 'Pending', profile.status === 'error' ? profile.data.message : 'The profile is not ready yet.');
      // Known namespace-catalog versions of the target namespace; an
      // unavailable list leaves Kubernetes' create refusal as the check.
      let versions: string[] = [];
      try {
        const listed = await client.call('list_capture_profiles', { target_ref: structuredClone(target), catalog: 'namespace' }, session.csrf_token, scope);
        if (listed.status === 'ok') versions = listed.data.profiles.filter(p => p.profile_ref.catalog === 'namespace').map(p => p.profile_ref.name + '/' + p.profile_ref.version);
      } catch { /* versions stay unknown */ }
      setLoaded({ definition: profile.data.definition, versions });
      const known = versions.filter(v => v.startsWith(component.profileRef.name + '/')).map(v => v.split('/')[1]);
      setForm(f => ({ ...f, displayName: profile.data.definition.displayName, version: nextVersion(component.profileRef.catalog === 'namespace' ? [...known, component.profileRef.version] : known) }));
    } catch (e) { if (!scope.aborted) setError(operationMessage(e)); } finally { setLoading(false); }
  };
  if (!loaded) return <section className="review-section" aria-labelledby="save-profile-heading" aria-busy={loading}>
    <h2 id="save-profile-heading">Save as profile</h2>
    <p className="field-help">Save these reviewed settings as a new version of a namespace capture profile. You publish it yourself with Kubernetes.</p>
    {error && <p role="status" className="notice">{error}</p>}
    <Button className="button secondary" isDisabled={loading} onPress={() => void open()}>{loading ? 'Loading profile…' : 'Save as profile…'}</Button>
  </section>;
  const known = form.namespace === target.namespace ? loaded.versions.filter(v => v.startsWith(form.name + '/')).map(v => v.split('/')[1]) : [];
  let manifest: object | undefined, problem: string | undefined;
  try { manifest = profileManifest({ ...form, source: loaded.definition, composition, existingVersions: known }); }
  catch (e) { if (e instanceof ManifestError) problem = e.message; else throw e; }
  const text = manifest ? JSON.stringify(manifest, null, 2) + '\n' : '';
  const file = `${form.name}.${form.version}.json`;
  const set = (key: keyof typeof form) => (event: ChangeEvent<HTMLInputElement>) => { setStatus(undefined); setForm({ ...form, [key]: event.currentTarget.value }); };
  const copy = async () => { try { await navigator.clipboard.writeText(text); setStatus('Manifest copied.'); } catch { setStatus('Copy the manifest from the field.'); } };
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = file; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };
  return <section className="review-section" aria-labelledby="save-profile-heading">
    <h2 id="save-profile-heading">Save as profile</h2>
    <p>Based on {component.profileRef.catalog}/{component.profileRef.name} {component.profileRef.version}. Your edits become the new defaults; the editable settings stay the same. Execution grants, owners, recipients, sharing and approvals are not saved.</p>
    <div className="form-row">
      <label>Namespace<input value={form.namespace} onChange={set('namespace')} autoComplete="off" spellCheck={false} maxLength={63} required/></label>
      <label>Profile name<input value={form.name} onChange={set('name')} autoComplete="off" spellCheck={false} maxLength={63} required/></label>
    </div>
    <div className="form-row">
      <label>New version<input value={form.version} onChange={set('version')} autoComplete="off" spellCheck={false} maxLength={32} required aria-describedby="save-profile-version-help"/></label>
      <label>Display name<input value={form.displayName} onChange={set('displayName')} maxLength={128} required/></label>
    </div>
    <p className="field-help" id="save-profile-version-help">{known.length ? `Existing versions: ${known.join(', ')}. ` : ''}Published versions are immutable; each save needs a new version.</p>
    {problem ? <p role="alert" className="notice">{problem}</p> : <>
      <pre tabIndex={0} role="region" aria-label="CaptureProfile manifest" className="manifest">{text}</pre>
      <div className="actions">
        <Button className="button secondary" onPress={() => void copy()}>Copy manifest</Button>
        <Button className="button secondary" onPress={download}>Download {file}</Button>
      </div>
      {status && <p role="status">{status}</p>}
      <p>Publish it with your own Kubernetes access:</p>
      <pre tabIndex={0} role="region" aria-label="Publish command"><code>kubectl create -f {file} -n {form.namespace}</code></pre>
      <p className="field-help">Publication uses your current Kubernetes rights in that namespace; Asservat does not write it for you. <code>kubectl create</code> refuses an existing object, so a published version is never overwritten. Publishing is not approval: collections from this profile are reviewed like any other.</p>
    </>}
  </section>;
}
