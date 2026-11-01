import type { Session } from '../auth/session';
import { OperationFailure, operationMessage, type Target } from '../capture/http';
import { operations, type Operations, type Operation, type Input, type Output, type Data, type Recording, type SavePreview } from './http';

export type Repeat = { policyUID: string; captureID: string; before?: string };
export type State = {
  busy: boolean; rows?: Recording[]; selected: Recording[]; cursor?: string; expiresAt?: string;
  captureEnabled: boolean; before: string; reason?: string; preview?: SavePreview; expired?: boolean; error?: string;
};
export function durationMilliseconds(value: string): number | undefined {
  const match = /^([1-9][0-9]*)(ms|s|m|h|d)$/.exec(value);
  if (!match) return;
  const result = Number(match[1]) * ({ ms: 1, s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2]] ?? 0);
  return Number.isSafeInteger(result) && result > 0 ? result : undefined;
}

// Preview IDs, capture IDs and observation timestamps are not disclosures.
// Compare the selected source/window and assessed handling before an immediate
// save; a material change remains visible for another explicit click.
function materialReview(preview: SavePreview): string {
  const { assessmentID: _id, planDigest: _digest, generatedAt: _at, validUntil: _until, ...assessment } = preview.capture_assessment;
  const rows = preview.selected_recordings.map(row => ({ handle: row.recording_handle, policy: row.policy_uid, pod: row.pod_uid, action: row.action_id, kind: row.kind, state: row.state, history: row.history, maximum: row.maximum_before, eligible: row.save_eligible, blockers: row.blockers, cap: row.incident_pod_cap })).sort((a, b) => (a.handle ?? '').localeCompare(b.handle ?? ''));
  const ordered = (value: unknown): unknown => Array.isArray(value) ? value.map(ordered) : value !== null && typeof value === 'object' ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, ordered(child)])) : value;
  return JSON.stringify(ordered({ rows, windows: [...preview.windows].sort((a, b) => a.recording_handle.localeCompare(b.recording_handle)), assessment, cap: preview.incident_pod_cap, enabled: preview.capture_enabled, blockers: preview.blockers }));
}

// Passive source metadata is owned by the current session scope. No source
// handles, selections or reviews survive scope loss; submission receipts belong
// to the existing Investigation controller instead.
export class Recordings {
  private state: State = { busy: false, selected: [], captureEnabled: false, before: '' };
  private listeners = new Set<() => void>();
  private session?: Session;
  private scope?: AbortSignal;
  private target?: Target;
  private repeat?: Repeat;
  private request?: AbortController;
  private generation = 0;
  private expiry?: ReturnType<typeof setTimeout>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations) {}
  private publish(patch: Partial<State>) { this.state = { ...this.state, ...patch }; for (const listener of this.listeners) listener(); }
  private invalidate() { ++this.generation; this.request?.abort(); }
  reset = () => { this.invalidate(); clearTimeout(this.expiry); this.session = undefined; this.scope = undefined; this.target = undefined; this.repeat = undefined; this.state = { busy: false, selected: [], captureEnabled: false, before: '' }; for (const listener of this.listeners) listener(); };
  attach(session: Session, scope: AbortSignal, target: Target, repeat?: Repeat) {
    this.reset(); this.session = session; this.scope = scope; this.target = structuredClone(target); this.repeat = repeat;
    this.publish({ before: repeat?.before ?? '' });
    const abort = () => this.reset();
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort(); else void this.load();
    return () => { scope.removeEventListener('abort', abort); this.reset(); };
  }
  private async run<N extends Operation>(name: N, input: Input<N>): Promise<Output<N> | undefined> {
    const session = this.session, scope = this.scope;
    if (!session || !scope || scope.aborted) return;
    this.invalidate(); const generation = this.generation;
    const request = new AbortController(); this.request = request;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    this.publish({ busy: true, error: undefined });
    try {
      const result = await this.client.call(name, input, session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted) return;
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'Recordings are not available yet. Refresh to check again.');
      return result;
    } catch (error) {
      if (generation === this.generation && !scope.aborted) this.publish({ error: operationMessage(error) });
    } finally {
      scope.removeEventListener('abort', abort);
      if (generation === this.generation) this.publish({ busy: false });
    }
  }
  private expire(at: string) {
    clearTimeout(this.expiry);
    this.expiry = setTimeout(() => this.publish({ rows: undefined, selected: [], preview: undefined, cursor: undefined, expired: true }), Math.max(0, Date.parse(at) - Date.now()));
  }
  load = async (cursor?: string) => {
    if (!this.target || this.state.busy || cursor && this.state.selected.length > 0) return;
    clearTimeout(this.expiry);
    const input: Input<'list_recordings'> = { target_ref: structuredClone(this.target), limit: 20, ...(this.repeat && { policy_uid: this.repeat.policyUID }), ...(cursor && { cursor }) };
    this.publish({ rows: undefined, selected: [], preview: undefined, expired: false });
    const response = await this.run('list_recordings', input);
    if (!response || response.status !== 'ok') return;
    const page = response.data;
    if (!Number.isFinite(Date.parse(page.expires_at)) || Date.parse(page.expires_at) <= Date.now()) { this.publish({ expired: true }); return; }
    this.publish({ rows: page.recordings, cursor: response.next_cursor ?? undefined, expiresAt: page.expires_at, captureEnabled: page.capture_enabled });
    this.expire(page.expires_at);
  };
  select = (row: Recording, checked: boolean) => {
    if (this.state.busy || !row.recording_handle || this.state.expired) return;
    const selected = this.state.selected.filter(old => old.recording_handle !== row.recording_handle);
    if (checked) {
      if (!row.save_eligible || row.blockers.length > 0 || durationMilliseconds(row.maximum_before) === undefined) return;
      if (selected.some(old => old.policy_uid !== row.policy_uid)) { this.publish({ error: 'Choose recordings from one policy. Clear the current selection before changing policies.' }); return; }
      const cap = Math.min(row.incident_pod_cap, ...selected.map(old => old.incident_pod_cap));
      if (selected.length >= 16 || new Set([...selected.map(old => old.pod_uid), row.pod_uid]).size > cap) { this.publish({ error: `This save supports at most ${cap} ${cap === 1 ? 'pod' : 'pods'} and 16 sources. Remove a selection before adding another.` }); return; }
      selected.push(row);
    }
    this.publish({ selected, preview: undefined, error: undefined });
  };
  clear = () => { if (!this.state.busy) this.publish({ selected: [], preview: undefined, reason: undefined, error: undefined }); };
  setReason = (reason: string) => { if (!this.state.busy) this.publish({ reason, preview: undefined, error: undefined }); };
  setBefore = (before: string) => { if (!this.state.busy) this.publish({ before, preview: undefined, error: undefined }); };
  review = async () => {
    const selected = this.state.selected;
    if (this.state.busy || selected.length < 1 || this.state.expired || !this.state.captureEnabled) return;
    const reason = this.state.reason ?? '';
    if (Array.from(reason).length > 512 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(reason)) { this.publish({ error: 'Reason must contain at most 512 Unicode characters.' }); return; }
    const before = this.state.before.trim();
    if (before !== '') {
      const milliseconds = durationMilliseconds(before);
      if (!milliseconds || selected.some(row => milliseconds > (durationMilliseconds(row.maximum_before) ?? 0))) { this.publish({ error: 'Lookback must be positive and no longer than each selected recording’s configured maximum, such as 10s.' }); return; }
    }
    this.publish({ preview: undefined });
    const response = await this.run('preview_recording_save', { recording_handles: selected.map(row => row.recording_handle!), ...(before && { before }), ...(reason !== '' && { reason }), ...(this.repeat && { repeated_from_capture_id: this.repeat.captureID }) });
    if (!response || response.status !== 'ok') return;
    const preview = response.data;
    const handles = selected.map(row => row.recording_handle!);
    const previewHandles = preview.selected_recordings.map(row => row.recording_handle);
    if (preview.capture_assessment.planDigest !== preview.save_scope_digest || preview.selected_recordings.length !== selected.length ||
      new Set(previewHandles).size !== handles.length || previewHandles.some(handle => !handle || !handles.includes(handle)) ||
      preview.windows.length !== handles.length || new Set(preview.windows.map(window => window.recording_handle)).size !== handles.length ||
      preview.windows.some(window => !handles.includes(window.recording_handle) || window.after !== '0s' || !durationMilliseconds(window.before) || (durationMilliseconds(window.before) ?? Infinity) > (durationMilliseconds(selected.find(row => row.recording_handle === window.recording_handle)?.maximum_before ?? '') ?? 0) || (before !== '' && durationMilliseconds(window.before) !== durationMilliseconds(before))) ||
      preview.selected_recordings.some(row => !selected.some(old => old.recording_handle === row.recording_handle && old.policy_uid === row.policy_uid && old.pod_uid === row.pod_uid && old.action_id === row.action_id)) ||
      new Set(preview.selected_recordings.map(row => row.pod_uid)).size > preview.incident_pod_cap ||
      preview.capture_assessment.actions.some(action => action.retention.anchorRule !== 'firstAcquisitionOrEarlierSource') || !Number.isFinite(Date.parse(preview.expires_at))) {
      this.publish({ error: 'The recording selection or window changed. Refresh recordings and prepare a new preview.' }); return;
    }
    const expired = Date.parse(preview.expires_at) <= Date.now();
    this.publish({ preview, expired }); this.expire(preview.expires_at);
  };
  save = async (submit: (previewID: string, captureID: string, expiresAt: string) => Promise<void>) => {
    const reviewed = this.state.preview;
    if (!reviewed || !this.submittable) return;
    const original = materialReview(reviewed);
    await this.review(); // Fresh passive preview; no admission or buffer pin.
    const fresh = this.state.preview;
    if (!fresh || !this.submittable) return;
    if (materialReview(fresh) !== original) { this.publish({ error: 'The source, window or data-handling assessment changed. Review the updated save before continuing.' }); return; }
    await submit(fresh.preview_id, fresh.capture_id, fresh.expires_at);
  };
  get submittable() { const p = this.state.preview; return !!p && p.capture_enabled && !this.state.busy && !this.state.expired && Date.now() < Date.parse(p.expires_at) && p.blockers.length === 0; }
}
