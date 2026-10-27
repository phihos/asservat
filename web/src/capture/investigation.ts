import { approvalPath, approvalSubmissionKey } from './approval-intent';
import type { Session } from '../auth/session';
import type { Recipient } from '../sharing/shares';
import { operations, OperationFailure, operationMessage, type Operations, type Target, type Diagnostic, type Preview, type Progress, type HistoryEntry, type Input, type Output, type Operation, type Data } from './http';

// sharing/shareHours: the optional capture-time share of the result (ADR-235);
// no hours means the server default (24 hours after publication).
export type Draft = { target: Target; retention: string; sharing?: Recipient[]; shareHours?: number };
export type State = {
  stage: 'target' | 'diagnostics' | 'review' | 'reviewed' | 'uncertain' | 'closed' | 'progress' | 'approval';
  busy: boolean; draft: Draft; diagnostics?: Diagnostic[]; preview?: Preview;
  progress?: Progress; captureID?: string; approvalURI?: string; error?: string; stale?: boolean; expired?: boolean; resolving?: boolean; canContinue?: boolean; continuing?: boolean;
  // ADR-236: recent captures of the draft target and the capture a review repeats.
  history?: HistoryEntry[]; historyMessage?: string; repeatedFrom?: string;
  historyOrigin?: 'manual' | 'policy' | 'discovery' | 'all'; historyCursor?: string; settings?: Data<'get_capture_settings'>;
};
export const historyPageSize = 10;
type Receipt = { preview_id: string; idempotency_key: string; captureID?: string; revision?: number; closed?: true; continuationBlocked?: true; approvalURI?: string };
type ReviewedHandle = { id: string; expiresAt: number; approvalRequired: boolean };
const emptyDraft = (): Draft => ({ target: { cluster_id: '', namespace: '', kind: 'Deployment', name: '' }, retention: '' });
const terminal = new Set(['Succeeded', 'Partial', 'Failed', 'Cancelled', 'Indeterminate']);

// UI coordination is not authority. The server rechecks every operation. Only
// a minimal retry receipt survives a same-user scope change, never protected
// previews, catalog rows or progress. No credentials/evidence enter storage.
export class Investigation {
  private state: State = { stage: 'target', busy: false, draft: emptyDraft() };
  private listeners = new Set<() => void>();
  private identity?: string;
  private session?: Session;
  private scope?: AbortSignal;
  private request?: AbortController;
  private generation = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private previewExpiry?: ReturnType<typeof setTimeout>;
  private receipt?: Receipt;
  private reviewed?: ReviewedHandle;
  private selected?: Diagnostic;
  private selectedComposition?: NonNullable<Input<'preview_capture'>['profile_composition']>;
  private repeatOf?: string;
  private repeatSelection?: 'currentEligiblePod';
  private repeatRetention?: string;
  private settingsExpiry?: ReturnType<typeof setTimeout>;
  private historyExpiry?: ReturnType<typeof setTimeout>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private newID: () => string = () => crypto.randomUUID()) {}
  private publish(patch: Partial<State>) {
    if ('history' in patch) {
      clearTimeout(this.historyExpiry);
      if (patch.history === undefined) { clearTimeout(this.settingsExpiry); patch.settings = undefined; patch.historyCursor = undefined; }
      else {
        const now = Date.now();
        const bounds = patch.history.flatMap(entry => [Date.parse(entry.summary_expires_at), ...(entry.settings_expires_at && Date.parse(entry.settings_expires_at) > now ? [Date.parse(entry.settings_expires_at)] : [])]);
        if (bounds.length) this.historyExpiry = setTimeout(() => this.publish({ history: undefined, historyMessage: 'Saved history availability changed. Refresh history to check current entries.' }), Math.min(2_147_483_647, Math.max(0, Math.min(...bounds) - now)));
      }
    }
    this.state = { ...this.state, ...patch };
    this.state.canContinue = !!(this.session && this.scope && !this.scope.aborted && this.receipt?.captureID && this.receipt.preview_id && this.receipt.idempotency_key && !this.receipt.continuationBlocked && this.state.progress?.phase === 'Pending');
    for (const listener of this.listeners) listener();
  }
  private invalidate() { ++this.generation; this.request?.abort(); clearTimeout(this.timer); clearTimeout(this.previewExpiry); clearTimeout(this.settingsExpiry); this.state = { ...this.state, settings: undefined }; }
  private receiptStage(): State['stage'] { return this.receipt?.captureID ? 'progress' : this.receipt?.closed ? 'closed' : this.receipt?.approvalURI ? 'approval' : 'uncertain'; }

  attach(session: Session, scope: AbortSignal, captureID?: string) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    this.invalidate();
    this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = undefined;
    if (captureID && !this.receipt) this.receipt = { preview_id: '', idempotency_key: '', captureID };
    this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, error: undefined, busy: false, resolving: false, continuing: false, history: undefined, historyMessage: undefined,
      captureID: this.receipt?.captureID, approvalURI: this.receipt?.approvalURI, stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target', expired: this.reviewed ? this.reviewed.expiresAt <= Date.now() : false });
    this.expireReview();
    const abort = () => {
      this.invalidate(); this.session = undefined; this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = undefined;
      this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, busy: false, resolving: false, continuing: false, history: undefined, historyMessage: undefined,
        stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target' });
    };
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    else if (this.receipt?.captureID) void this.refreshProgress();
    return () => { scope.removeEventListener('abort', abort); abort(); };
  }

  reset = () => {
    this.invalidate(); this.identity = undefined; this.session = undefined; this.scope = undefined;
    clearTimeout(this.historyExpiry);
    this.receipt = undefined; this.selected = undefined; this.selectedComposition = undefined; this.reviewed = undefined; this.repeatOf = undefined;
    this.state = { stage: 'target', busy: false, draft: emptyDraft() };
    for (const listener of this.listeners) listener();
  };
  setDraft = (draft: Draft) => {
    if (this.receipt || this.state.busy) return;
    this.invalidate(); this.selected = undefined; this.selectedComposition = undefined; this.reviewed = undefined; this.repeatOf = undefined;
    this.publish({ draft: structuredClone(draft), stage: 'target', preview: undefined, diagnostics: undefined, error: undefined, history: undefined, historyMessage: undefined });
  };
  edit = () => { if (!this.receipt) { this.invalidate(); this.reviewed = undefined; this.repeatOf = undefined; this.publish({ stage: 'target', preview: undefined, diagnostics: undefined, approvalURI: undefined, error: undefined, busy: false, history: undefined, historyMessage: undefined }); } };
  editClosedRequest = () => {
    if (!this.receipt?.closed || this.receipt.captureID || this.state.busy) return;
    this.receipt = undefined; this.selected = undefined; this.selectedComposition = undefined;
    this.edit(); // Explicit user navigation only; no preview, key or capture is created.
  };
  private expireReview() {
    clearTimeout(this.previewExpiry);
    if (this.reviewed) this.previewExpiry = setTimeout(() => this.publish({ expired: true }), Math.max(0, this.reviewed.expiresAt - Date.now()));
  }

  private async run<N extends Operation>(name: N, input: Input<N>): Promise<Data<N> | undefined> {
    if (!this.session || !this.scope || this.scope.aborted) return;
    this.invalidate();
    const generation = this.generation;
    const request = new AbortController(); this.request = request;
    const abort = () => request.abort(); this.scope.addEventListener('abort', abort, { once: true });
    const scope = this.scope;
    this.publish({ busy: true, error: undefined });
    try {
      const result: Output<N> = await this.client.call(name, input, this.session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted) return;
      if (name === 'request_capture' && result.status === 'error' && result.data.code === 'ApprovalRequired' && this.receipt) {
        const path = approvalPath('navigation_uri' in result.data ? result.data.navigation_uri : undefined);
        if (path) {
          this.receipt.approvalURI = path;
          this.publish({ stage: 'approval', approvalURI: path, error: undefined });
          return;
        }
      }
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This operation is still pending. Check it again before continuing.');
      if (name === 'list_capture_history') this.publish({ historyCursor: result.next_cursor ?? undefined });
      return result.data as Data<N>;
    } catch (error) {
      if (generation === this.generation && !scope.aborted) {
        if (this.state.continuing && this.receipt && error instanceof OperationFailure && ['AcquisitionClosed', 'AcquisitionUncertain'].includes(error.code)) this.receipt.continuationBlocked = true;
        const message = operationMessage(error);
        // AcquisitionNotStarted is known to precede every start effect.
        const notStarted = error instanceof OperationFailure && error.code === 'AcquisitionNotStarted';
        this.publish({ error: this.state.continuing && !this.receipt?.continuationBlocked && !notStarted ? message + " Collection may already have started. Check its status before retrying this same request." : message });
      }
      return;
    } finally {
      scope.removeEventListener('abort', abort);
      if (generation === this.generation) this.publish({ busy: false });
    }
  }

  discover = async () => {
    if (this.receipt || this.state.busy) return;
    const data = await this.run('list_diagnostics', { target_ref: structuredClone(this.state.draft.target) });
    if (!data) return;
    this.publish({ stage: 'diagnostics', diagnostics: data.diagnostics, history: undefined, historyMessage: undefined });
    await this.loadHistory();
  };
  // Recent captures of the draft target (ADR-236). Its own failure leaves the
  // diagnostics usable; the server decides visibility for every entry.
  private async loadHistory() {
    const session = this.session, scope = this.scope, request = this.request;
    if (!session || !scope || scope.aborted || !request) return;
    const generation = this.generation;
    let history: HistoryEntry[] | undefined, historyMessage: string | undefined, historyCursor: string | undefined;
    try {
      const result = await this.client.call('list_capture_history', { target_ref: structuredClone(this.state.draft.target), limit: historyPageSize, ...(this.state.historyOrigin && this.state.historyOrigin !== 'manual' ? { origin: this.state.historyOrigin } : {}) }, session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted) return;
      if (result.status === 'ok') { history = result.data.history; historyCursor = result.next_cursor ?? undefined; }
      else historyMessage = result.status === 'error' ? result.data.message : 'Recent captures are not available yet. Find diagnostics again to retry.';
    } catch (error) {
      if (generation !== this.generation || scope.aborted) return;
      historyMessage = operationMessage(error);
    }
    this.publish({ history, historyMessage, historyCursor });
  }
  showSettings = async (captureID: string) => {
    if (this.state.busy || (this.receipt && this.receipt.captureID !== captureID)) return;
    this.publish({ settings: undefined });
    const data = await this.run('get_capture_settings', { capture_id: captureID });
    if (!data) return;
    if (data.capture_id !== captureID || (!this.receipt && data.cluster_id !== this.state.draft.target.cluster_id) || Date.parse(data.expires_at) <= Date.now()) {
      this.publish({ error: 'The saved settings could not be verified. Refresh the history before continuing.' }); return;
    }
    this.publish({ settings: data });
    this.settingsExpiry = setTimeout(() => this.publish({ settings: undefined }), Math.min(2_147_483_647, Date.parse(data.expires_at) - Date.now()));
  };
  closeSettings = () => { clearTimeout(this.settingsExpiry); this.publish({ settings: undefined }); };
  private prepareHistoryRepeat(captureID: string) {
    if (!this.receipt) return true;
    const saved = this.state.settings;
    const workload = saved?.settings.target.workloadRef;
    if (this.receipt.captureID !== captureID || saved?.capture_id !== captureID || !workload || Date.parse(saved.expires_at) <= Date.now()) {
      this.publish({ error: 'View the available saved settings before preparing a new request.' }); return false;
    }
    // Only this explicit review action leaves the original progress view.
    // Current selection/approval happen on the server; the old request continues
    // independently and its retry receipt/grant/sharing is never reused.
    const target: Target = { cluster_id: saved.cluster_id, namespace: saved.settings.target.namespace, kind: workload.kind, name: workload.name };
    this.invalidate(); this.receipt = undefined;
    this.publish({ draft: { target, retention: '' }, captureID: undefined, progress: undefined, approvalURI: undefined, history: undefined, stage: 'diagnostics' });
    return true;
  }
  historyOrigin = async (origin: 'manual' | 'policy' | 'discovery' | 'all') => {
    if (this.receipt || this.state.busy) return;
    this.publish({ historyOrigin: origin, history: undefined, historyMessage: undefined });
    const data = await this.run('list_capture_history', { target_ref: structuredClone(this.state.draft.target), origin, limit: historyPageSize });
    this.publish({ history: data?.history, historyMessage: data ? undefined : this.state.error ?? 'History is unavailable.' });
  };
  moreHistory = async () => {
    if (this.receipt || this.state.busy || !this.state.historyCursor) return;
    const previous = this.state.history ?? [];
    const data = await this.run('list_capture_history', { target_ref: structuredClone(this.state.draft.target), origin: this.state.historyOrigin ?? 'manual', cursor: this.state.historyCursor, limit: historyPageSize });
    if (!data) return;
    const existing = new Set(previous.map(entry => entry.capture_id));
    this.publish({ history: [...previous, ...data.history.filter(entry => !existing.has(entry.capture_id))].slice(-100) });
  };
  // "Collect again": the server restores the capture's target and requested
  // retention into a fresh preview and runs every current check.
  repeat = async (captureID: string, selection?: 'currentEligiblePod') => {
    if (this.state.busy || !this.prepareHistoryRepeat(captureID)) return;
    this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = captureID; this.reviewed = undefined;
    this.repeatSelection = selection;
    this.repeatRetention = undefined;
    const requested = structuredClone(this.state.draft.target);
    this.publish({ stage: 'diagnostics', preview: undefined });
    const data = await this.run('preview_capture', { history_capture_id: captureID, ...(selection && { history_selection: selection }) });
    if (!data || this.repeatOf !== captureID) return;
    if (data.repeated_from_capture_id !== captureID) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    this.acceptPreview(data, requested);
  };
  preview = async (diagnostic = this.selected) => {
    if (!diagnostic && this.selectedComposition) return this.previewComposition(this.selectedComposition, this.repeatOf, this.repeatSelection, this.repeatRetention);
    if (!diagnostic && this.repeatOf) return this.repeat(this.repeatOf, this.repeatSelection);
    if (this.receipt || this.state.busy || !diagnostic) return;
    this.repeatOf = undefined;
    if (diagnostic.preset_ref?.name !== 'pod-status' || diagnostic.preset_ref.version !== 'v1') {
      this.publish({ error: 'This diagnostic is not supported by this console yet.' }); return;
    }
    this.selected = diagnostic;
    const input: Input<'preview_capture'> = { target_ref: structuredClone(this.state.draft.target), preset_ref: diagnostic.preset_ref };
    const retention = this.state.draft.retention;
    if (retention !== '') {
      const seconds = Number(retention);
      if (!/^[1-9][0-9]*$/.test(retention) || !Number.isSafeInteger(seconds) || seconds > 315360000) {
        this.publish({ error: 'Retention must be a whole number of seconds between 1 and 315360000.' }); return;
      }
      input.requested_retention_seconds = seconds;
    }
    const sharing = this.state.draft.sharing ?? [];
    if (sharing.length > 0 && this.session) {
      const issuer = this.session.principal.issuer;
      const share: { recipients: { kind: Recipient['kind']; issuer: string; id: string }[]; notAfter?: string } = { recipients: sharing.map(r => ({ kind: r.kind, issuer, id: r.id })) };
      const hours = this.state.draft.shareHours;
      if (hours !== undefined) {
        if (!Number.isInteger(hours) || hours < 1 || hours > 168) { this.publish({ error: 'Sharing must last between 1 and 168 whole hours.' }); return; }
        share.notAfter = new Date(Date.now() + hours * 3_600_000).toISOString();
      }
      // The generated type marks the defaulted maxArtifactsPerCapture required;
      // the implemented subset (ADR-235) rejects it, so it is never sent.
      input.sharing = share as NonNullable<Input<'preview_capture'>['sharing']>;
    }
    this.reviewed = undefined;
    this.publish({ stage: 'diagnostics', preview: undefined });
    const data = await this.run('preview_capture', input);
    if (!data) return;
    if (data.repeated_from_capture_id !== undefined) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    this.acceptPreview(data, input.target_ref!);
  };
  // An already-authored/restored typed composition, not a profile editor or
  // a catalog entry invented by the browser. The server resolves every pin.
  previewComposition = async (composition: NonNullable<Input<'preview_capture'>['profile_composition']>, repeatedFrom?: string, selection?: 'currentEligiblePod', requestedRetention?: string) => {
    if (this.state.busy || (this.receipt && !repeatedFrom)) return;
    if (!this.receipt && this.state.draft.sharing?.length) {
      this.publish({ error: 'Capture-time sharing is not available for this recording review. Remove that instruction before preparing it.' }); return;
    }
    const retention = repeatedFrom ? requestedRetention ?? '' : this.state.draft.retention;
    let requestedSeconds: number | undefined;
    if (retention !== '') {
      const seconds = Number(retention);
      if (!/^[1-9][0-9]*$/.test(retention) || !Number.isSafeInteger(seconds) || seconds > 315360000) {
        this.publish({ error: 'Retention must be a whole number of seconds between 1 and 315360000.' }); return;
      }
      requestedSeconds = seconds;
    }
    // Validate edits before leaving the original progress/settings view, so a
    // typo can be corrected without losing the snapshot or retry handle.
    if (this.receipt && !this.prepareHistoryRepeat(repeatedFrom!)) return;
    const input: Input<'preview_capture'> = { target_ref: structuredClone(this.state.draft.target), profile_composition: structuredClone(composition) };
    if (repeatedFrom) input.repeated_from_capture_id = repeatedFrom;
    if (selection) input.history_selection = selection;
    if (requestedSeconds !== undefined) input.requested_retention_seconds = requestedSeconds;
    this.selected = undefined; this.repeatOf = repeatedFrom; this.reviewed = undefined;
    this.repeatSelection = selection;
    this.repeatRetention = requestedRetention;
    this.selectedComposition = structuredClone(composition);
    this.publish({ stage: 'diagnostics', preview: undefined });
    const data = await this.run('preview_capture', input);
    if (!data) return;
    if (data.profile_composition === undefined || data.repeated_from_capture_id !== repeatedFrom) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    this.acceptPreview(data, input.target_ref!);
  };
  private acceptPreview(data: Preview, requested: Target) {
    const pod = data.selected_pods?.[0];
    const recording = data.profile_composition !== undefined;
    if ((!recording && data.preset_ref?.name !== 'pod-status') || data.selected_pods?.length !== 1 ||
        data.capture_assessment.planDigest !== data.execution_digest || !data.target_ref ||
        data.capture_assessment.actions.some(action => action.retention.anchorRule !== 'submissionPreparation') ||
        !(['cluster_id', 'namespace', 'kind', 'name'] as const).every(key => data.target_ref![key] === requested[key]) ||
        pod?.cluster_id !== requested.cluster_id || pod.namespace !== requested.namespace ||
        (requested.kind === 'Pod' ? pod.name !== requested.name || (!recording || data.pod_selection !== undefined) && data.pod_selection !== 'explicitPod' :
          pod.workload.kind !== requested.kind || pod.workload.name !== requested.name || (!recording || data.pod_selection !== undefined) && data.pod_selection !== 'lexicalEligiblePod')) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    const remaining = Math.min(5_000, Date.parse(data.capture_assessment.validUntil) - Date.now(), Date.parse(data.expires_at) - Date.now());
    if (requestablePreview(data)) this.reviewed = { id: data.preview_id, expiresAt: Date.parse(data.expires_at), approvalRequired: data.approval_required };
    this.publish({ stage: 'review', preview: data, repeatedFrom: data.repeated_from_capture_id, stale: remaining <= 0, expired: Date.parse(data.expires_at) <= Date.now() });
    this.timer = setTimeout(() => this.publish({ stale: true }), Math.max(0, remaining));
    this.previewExpiry = setTimeout(() => this.publish({ expired: true }), Math.max(0, Date.parse(data.expires_at) - Date.now()));
  }
  submit = async () => {
    if (this.receipt || this.state.busy) return;
    const preview = this.state.preview;
    const reviewed = this.reviewed;
    if (!reviewed || (this.state.stage !== 'reviewed' && (!preview || !requestablePreview(preview)))) return;
    if (this.state.expired || reviewed.expiresAt <= Date.now()) {
      this.publish({ expired: true }); return;
    }
    this.receipt = { preview_id: reviewed.id, idempotency_key: reviewed.approvalRequired ? approvalSubmissionKey(reviewed.id) : this.newID() };
    this.reviewed = undefined;
    await this.retrySubmission();
  };
  retrySubmission = async () => {
    if (!this.receipt || this.receipt.captureID || this.receipt.closed || this.state.busy) return;
    // Persist the receipt in memory before network I/O. Even a server error may
    // follow a commit; only this exact retry is allowed until resolved.
    const receipt = this.receipt;
    this.publish({ stage: 'uncertain', preview: undefined, diagnostics: undefined, resolving: false });
    const data = await this.run('request_capture', { preview_id: receipt.preview_id, idempotency_key: receipt.idempotency_key });
    if (!data || receipt !== this.receipt) return;
    await this.openAccepted(receipt, data.capture_id);
  };
  continueAcquisition = async () => {
    const receipt = this.receipt;
    if (!receipt || !this.state.canContinue || this.state.busy) return;
    this.publish({ continuing: true });
    const data = await this.run('request_capture', { preview_id: receipt.preview_id, idempotency_key: receipt.idempotency_key, continue_acquisition: true });
    if (receipt !== this.receipt) return;
    this.publish({ continuing: false });
    if (!data) return; // Keep the accepted receipt even if the start reply was lost.
    await this.openAccepted(receipt, data.capture_id);
  };
  resolveBeforeEditing = async () => {
    const receipt = this.receipt;
    if (!receipt || receipt.captureID || receipt.closed || this.state.busy) return;
    this.publish({ stage: 'uncertain', preview: undefined, diagnostics: undefined, resolving: true });
    const data = await this.run('resolve_capture_request', { preview_id: receipt.preview_id, idempotency_key: receipt.idempotency_key });
    if (receipt !== this.receipt) return;
    this.publish({ resolving: false });
    if (!data) return; // Errors and unknown closure replies never prove non-admission.
    if (data.state === 'accepted') {
      await this.openAccepted(receipt, data.capture_id);
    } else if (data.state === 'closed' && !receipt.captureID) {
      receipt.closed = true; this.reviewed = undefined; this.selected = undefined; this.selectedComposition = undefined;
      this.publish({ stage: 'closed', preview: undefined, diagnostics: undefined, progress: undefined, error: undefined });
    }
  };
  private async openAccepted(receipt: Receipt, captureID: string) {
    if (receipt !== this.receipt) return;
    if (receipt.captureID && receipt.captureID !== captureID) {
      this.publish({ error: 'The request outcome could not be verified. Keep the original request and check it again.' }); return;
    }
    receipt.captureID = captureID; delete receipt.closed; delete receipt.approvalURI;
    this.publish({ stage: 'progress', captureID, error: undefined, resolving: false });
    window.history.replaceState(null, '', '/captures/' + captureID);
    await this.refreshProgress();
  }
  refreshProgress = async () => {
    const id = this.receipt?.captureID;
    if (!id || this.state.busy) return;
    const data = await this.run('get_capture', { capture_id: id });
    if (!data) { this.publish({ progress: undefined }); return; }
    if (data.capture_id !== id || data.revision < (this.receipt?.revision ?? 0)) {
      this.publish({ progress: undefined, error: 'The collection status could not be verified. Try checking it again.' }); return;
    }
    if (this.receipt?.captureID !== id) return;
    this.receipt.revision = data.revision;
    this.publish({ stage: 'progress', progress: data });
    if (!terminal.has(data.phase)) this.timer = setTimeout(() => void this.refreshProgress(), 1000 * (data.retry_after_seconds ?? 5));
  };
}

// Button eligibility only; current server authority decides every submission.
export function requestablePreview(preview: Preview): boolean {
  return preview.approval_required ? preview.blockers.every(b => b.code === 'ApprovalRequired') : preview.capture_enabled && preview.blockers.length === 0;
}
