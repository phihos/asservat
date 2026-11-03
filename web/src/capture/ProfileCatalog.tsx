import { useEffect, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operations, operationMessage, OperationFailure, type Data, type Input, type Operations, type Target } from './http';

export type Composition = NonNullable<Input<'preview_capture'>['profile_composition']>;
type Listed = Data<'list_capture_profiles'>['profiles'][number];
type Definition = Data<'get_capture_profile'>['definition'];
type Ref = Listed['profile_ref'];
type Field = NonNullable<Definition['editableFields']>[number];
type Override = NonNullable<Composition['components'][number]['overrides']>[number];
type ArgumentSettings = Extract<Override, { field: 'syscallArguments' }>['value'];
type Added = { id: string; ref: Ref; definition: Definition; values: Record<string, string> };
// Composer state the workspace keeps while the user reviews a plan, so
// "Change profiles" returns to the same selection and edits.
export type CatalogDraft = { added: Added[]; bounds?: { bytes: string; duration: string } };

// Typed edits this panel offers; other structured settings (rings, peers,
// filters, process selectors) keep the profile's reviewed defaults here.
const textFields = new Set(['packetFilter', 'packetBefore', 'packetAfter', 'syscallBefore', 'syscallAfter', 'syscallMode', 'actionTimeout', 'actionExecutionMode', 'profileDuration', 'filePath']);
const numberFields = new Set(['actionMaxBytes', 'syscallMaxEvents', 'syscallRate']);
const editable = (field: Field) => textFields.has(field.field) || numberFields.has(field.field) || field.field === 'syscallArguments';
const key = (field: Field) => field.actionID + '/' + field.field;

function argumentValues(a: Added, field: Field) {
  const action = a.definition.recipe.actions.find(action => action.id === field.actionID);
  const defaults = (action?.parameters as { arguments?: ArgumentSettings } | undefined)?.arguments;
  const bytes = a.values[key(field) + '/maxBytesPerEvent'] ?? String(defaults?.maxBytesPerEvent ?? '');
  const buffers = a.values[key(field) + '/captureBuffers'];
  const captureBuffers = buffers === undefined ? defaults?.captureBuffers ?? false : buffers === 'true';
  const changed = bytes !== String(defaults?.maxBytesPerEvent ?? '') || captureBuffers !== (defaults?.captureBuffers ?? false);
  return { bytes, captureBuffers, changed };
}

// The profile's own default for a scalar field, shown as the placeholder.
export function profileDefault(definition: Definition, field: Field): string {
  const action = definition.recipe.actions.find(a => a.id === field.actionID) as { parameters?: Record<string, unknown>; limits?: Record<string, unknown>; executionMode?: string } | undefined;
  const p = action?.parameters ?? {}, l = action?.limits ?? {};
  const value = ({ packetFilter: p.filter, packetBefore: p.before, packetAfter: p.after, syscallBefore: p.before, syscallAfter: p.after, syscallMode: p.mode, syscallMaxEvents: p.maxEvents, syscallRate: p.maxEventsPerSecond,
    actionTimeout: l.timeout, actionMaxBytes: l.maxBytes, actionExecutionMode: action?.executionMode } as Record<string, unknown>)[field.field];
  return typeof value === 'string' || typeof value === 'number' ? String(value) : '';
}

const units: Record<string, number> = { ms: 0.001, s: 1, m: 60, h: 3600, d: 86400 };
export function seconds(duration: string): number {
  const m = /^([0-9]+)(ms|s|m|h|d)$/.exec(duration);
  return m ? Number(m[1]) * units[m[2]] : 0;
}

// Initial aggregate bounds from the selected defaults (REQ-CPR-002): the sum
// of component bytes and the longest component duration. Users may lower them;
// the server validates every ceiling.
export function defaultBounds(added: Added[]): { bytes: number; duration: string } {
  const bytes = added.reduce((sum, a) => sum + a.definition.recipe.maxTotalBytes, 0);
  const longest = Math.max(0, ...added.map(a => seconds(a.definition.recipe.maxDuration)));
  return { bytes, duration: Math.ceil(longest) + 's' };
}

export function componentID(name: string, taken: string[]): string {
  const base = name.slice(0, 22).replace(/-+$/, '') || 'profile';
  let id = base, n = 2;
  while (taken.includes(id)) id = base.slice(0, 21) + '-' + n++;
  return id;
}

// The composition submitted for preview: only changed values become
// overrides; the server resolves every pin and validates the whole plan.
export function composition(added: Added[], bytes: number, duration: string): Composition {
  return {
    components: added.map(a => {
      const overrides = (a.definition.editableFields ?? []).filter(editable).flatMap<Override>(field => {
        if (field.field === 'syscallArguments') {
          const value = argumentValues(a, field);
          return value.changed ? [{ actionID: field.actionID, field: 'syscallArguments', value: { maxBytesPerEvent: Number(value.bytes), captureBuffers: value.captureBuffers } }] : [];
        }
        const raw = a.values[key(field)]?.trim();
        if (!raw || raw === profileDefault(a.definition, field)) return [];
        return [{ actionID: field.actionID, field: field.field, value: numberFields.has(field.field) ? Number(raw) : raw } as Override];
      });
      return { id: a.id, profileRef: structuredClone(a.ref), ...(overrides.length > 0 && { overrides }) };
    }),
    maxTotalBytes: bytes, maxDuration: duration,
  } as Composition;
}

export function ProfileCatalog({ session, scope, target, busy, onPreview, client = operations, initial, onDraft }: { session: Session; scope: AbortSignal; target: Target; busy: boolean; onPreview: (c: Composition) => void; client?: Operations; initial?: CatalogDraft; onDraft?: (draft: CatalogDraft) => void }) {
  const [profiles, setProfiles] = useState<Listed[]>();
  const [added, setAdded] = useState<Added[]>(initial?.added ?? []);
  const [bounds, setBounds] = useState<{ bytes: string; duration: string } | undefined>(initial?.bounds);
  useEffect(() => { onDraft?.({ added, bounds }); }, [added, bounds]); // eslint-disable-line react-hooks/exhaustive-deps
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);
  const call = async <N extends 'list_capture_profiles' | 'get_capture_profile'>(name: N, input: Input<N>): Promise<Data<N> | undefined> => {
    try {
      const result = await client.call(name, input, session.csrf_token, scope);
      if (result.status === 'ok') return result.data as Data<N>;
      throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'The catalog is not ready yet.');
    } catch (e) { if (!scope.aborted) setError(operationMessage(e)); }
  };
  useEffect(() => { void call('list_capture_profiles', { target_ref: structuredClone(target) }).then(data => data && setProfiles(data.profiles)); }, [JSON.stringify(target)]); // eslint-disable-line react-hooks/exhaustive-deps
  // Functional updates: a definition fetched for add() must not overwrite
  // edits or removals made while it was loading.
  const update = (change: (previous: Added[]) => Added[]) => setAdded(previous => {
    const next = change(previous);
    const b = defaultBounds(next);
    setBounds(next.length ? { bytes: String(b.bytes), duration: b.duration } : undefined);
    return next;
  });
  const add = async (profile: Listed) => {
    setLoading(true); setError(undefined);
    const data = await call('get_capture_profile', { target_ref: structuredClone(target), profile_ref: structuredClone(profile.profile_ref) });
    setLoading(false);
    if (data) update(previous => previous.length >= 8 ? previous : [...previous, { id: componentID(profile.profile_ref.name, previous.map(a => a.id)), ref: data.profile_ref, definition: data.definition, values: {} }]);
  };
  const setValue = (id: string, field: Field, value: string, member?: keyof ArgumentSettings) => setAdded(previous => previous.map(a => a.id === id ? { ...a, values: { ...a.values, [key(field) + (member ? '/' + member : '')]: value } } : a));
  // Actions switched to onTrigger whose history window is not yet 0s: the UI
  // proposes that coupled change explicitly, never applies it silently.
  const pending = added.flatMap(a => (a.definition.editableFields ?? []).filter(f => f.field === 'actionExecutionMode' && a.values[key(f)] === 'onTrigger').flatMap(mode =>
    (a.definition.editableFields ?? []).filter(f => f.actionID === mode.actionID && (f.field === 'packetBefore' || f.field === 'syscallBefore') && (a.values[key(f)] ?? profileDefault(a.definition, f)) !== '0s').map(field => ({ id: a.id, field }))));
  const submit = () => {
    if (!bounds) return;
    const bytes = Number(bounds.bytes);
    if (!Number.isSafeInteger(bytes) || bytes < 1 || seconds(bounds.duration) <= 0) { setError('Enter a positive byte limit and a duration such as 30s.'); return; }
    for (const a of added) for (const field of a.definition.editableFields ?? []) {
      if (field.field !== 'syscallArguments') continue;
      const value = argumentValues(a, field), limit = Number(value.bytes);
      if (value.changed && (!Number.isSafeInteger(limit) || limit < 1 || limit > 4096)) { setError('Argument bytes per event must be a whole number from 1 to 4096.'); return; }
    }
    setError(undefined);
    onPreview(composition(added, bytes, bounds.duration));
  };
  return <section className="review-section profile-catalog" aria-label="Capture profiles" aria-busy={loading || busy}>
    <h2>Capture profiles</h2>
    <p className="field-help">Combine profiles into one reviewed recording. Each profile supplies reviewed defaults; change only what you need. Nothing is collected until you confirm the review.</p>
    {error && <p role="status" className="notice">{error}</p>}
    {profiles?.length === 0 && <p>No capture profiles are available for this target.</p>}
    {profiles?.map(profile => <article className="diagnostic" key={profile.profile_ref.catalog + '/' + profile.profile_ref.name + '/' + profile.profile_ref.version}>
      <h3>{profile.display_name}</h3>
      <p>{profile.description}</p>
      <p className="field-help">{profile.profile_ref.catalog} catalog · {profile.profile_ref.name} {profile.profile_ref.version} · {profile.execution_modes.map(m => m === 'onTrigger' ? 'on trigger' : 'ongoing').join(', ')}{profile.approval_required ? ' · needs approval' : ''}{profile.deprecated ? ' · deprecated' : ''}</p>
      {profile.blockers.map((b, i) => <p className="notice" key={i}>{b.message}</p>)}
      <Button className="button secondary" isDisabled={busy || loading || !profile.available || added.length >= 8} onPress={() => void add(profile)}>Add profile</Button>
    </article>)}
    {added.length > 0 && <fieldset disabled={busy}><legend>Selected profiles</legend>
      {added.map(a => <div className="profile-card" key={a.id}>
        <h4>{a.definition.displayName} <span className="field-help">({a.id})</span></h4>
        {(a.definition.editableFields ?? []).map(field => field.field === 'syscallArguments'
          ? <fieldset key={key(field)}><legend>{field.label}</legend>
            <label>Maximum argument bytes per event<input type="number" min="1" max="4096" step="1" value={argumentValues(a, field).bytes} onChange={event => setValue(a.id, field, event.currentTarget.value, 'maxBytesPerEvent')} /></label>
            <label><input type="checkbox" checked={argumentValues(a, field).captureBuffers} onChange={event => setValue(a.id, field, String(event.currentTarget.checked), 'captureBuffers')} />Capture buffer contents</label>
            {field.description && <p className="field-help">{field.description}</p>}
          </fieldset>
          : editable(field)
          ? <label key={key(field)}>{field.label}<input type={numberFields.has(field.field) ? 'number' : 'text'} value={a.values[key(field)] ?? ''} placeholder={profileDefault(a.definition, field)} onChange={event => setValue(a.id, field, event.currentTarget.value)} />{field.description && <span className="field-help">{field.description}</span>}</label>
          : <p className="field-help" key={key(field)}>{field.label}: uses the profile's reviewed setting.</p>)}
        <Button className="button secondary" onPress={() => update(previous => previous.filter(other => other.id !== a.id))}>Remove</Button>
      </div>)}
      {pending.length > 0 && <div className="notice"><p>Starting on trigger keeps no earlier history, so its history window must be 0s.</p>
        <Button className="button secondary" onPress={() => { for (const p of pending) setValue(p.id, p.field, '0s'); }}>Set history window to 0s</Button></div>}
      {bounds && <><label>Maximum total bytes<input type="number" min="1" step="1" value={bounds.bytes} onChange={event => setBounds({ ...bounds, bytes: event.currentTarget.value })} /></label>
        <label>Maximum duration<input value={bounds.duration} onChange={event => setBounds({ ...bounds, duration: event.currentTarget.value })} /></label>
        <p className="field-help">Computed from the selected profiles. You may lower them; administrator limits still apply.</p></>}
      <Button className="button" isDisabled={busy} onPress={submit}>{busy ? 'Preparing review…' : 'Review combined recording'}</Button>
    </fieldset>}
  </section>;
}
