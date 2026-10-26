import type { Session } from '../auth/session';
import type { Recipient } from '../sharing/shares';
import { operations, OperationFailure, operationMessage, type Operations, type Target, type Diagnostic, type Preview, type Progress, type Input, type Output, type Operation, type Data } from './http';

// sharing/shareHours: the optional capture-time share of the result (ADR-235);
// no hours means the server default (24 hours after publication).
export type Draft = { target: Target; retention: string; sharing?: Recipient[]; shareHours?: number };
export type State = {
  stage: 'target' | 'diagnostics' | 'review' | 'reviewed' | 'uncertain' | 'closed' | 'progress';
  busy: boolean; draft: Draft; diagnostics?: Diagnostic[]; preview?: Preview;
  progress?: Progress; captureID?: string; error?: string; stale?: boolean; expired?: boolean; resolving?: boolean; canContinue?: boolean; continuing?: boolean;
};
type Receipt = { preview_id: string; idempotency_key: string; captureID?: string; revision?: number; closed?: true; continuationBlocked?: true };
type ReviewedHandle = { id: string; expiresAt: number };
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
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private newID: () => string = () => crypto.randomUUID()) {}
  private publish(patch: Partial<State>) { this.state = { ...this.state, ...patch }; this.state.canContinue = !!(this.session && this.scope && !this.scope.aborted && this.receipt?.captureID && this.receipt.preview_id && this.receipt.idempotency_key && !this.receipt.continuationBlocked && this.state.progress?.phase === 'Pending'); for (const listener of this.listeners) listener(); }
  private invalidate() { ++this.generation; this.request?.abort(); clearTimeout(this.timer); clearTimeout(this.previewExpiry); }
  private receiptStage(): State['stage'] { return this.receipt?.captureID ? 'progress' : this.receipt?.closed ? 'closed' : 'uncertain'; }

  attach(session: Session, scope: AbortSignal, captureID?: string) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    this.invalidate();
    this.selected = undefined;
    if (captureID && !this.receipt) this.receipt = { preview_id: '', idempotency_key: '', captureID };
    this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, error: undefined, busy: false, resolving: false, continuing: false,
      captureID: this.receipt?.captureID, stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target', expired: this.reviewed ? this.reviewed.expiresAt <= Date.now() : false });
    this.expireReview();
    const abort = () => {
      this.invalidate(); this.session = undefined; this.selected = undefined;
      this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, busy: false, resolving: false, continuing: false,
        stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target' });
    };
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    else if (this.receipt?.captureID) void this.refreshProgress();
    return () => { scope.removeEventListener('abort', abort); abort(); };
  }

  reset = () => {
    this.invalidate(); this.identity = undefined; this.session = undefined; this.scope = undefined;
    this.receipt = undefined; this.selected = undefined; this.reviewed = undefined;
    this.state = { stage: 'target', busy: false, draft: emptyDraft() };
    for (const listener of this.listeners) listener();
  };
  setDraft = (draft: Draft) => {
    if (this.receipt || this.state.busy) return;
    this.invalidate(); this.selected = undefined; this.reviewed = undefined;
    this.publish({ draft: structuredClone(draft), stage: 'target', preview: undefined, diagnostics: undefined, error: undefined });
  };
  edit = () => { if (!this.receipt) { this.invalidate(); this.reviewed = undefined; this.publish({ stage: 'target', preview: undefined, diagnostics: undefined, error: undefined, busy: false }); } };
  editClosedRequest = () => {
    if (!this.receipt?.closed || this.receipt.captureID || this.state.busy) return;
    this.receipt = undefined; this.selected = undefined;
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
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This operation is still pending. Check it again before continuing.');
      return result.data as Data<N>;
    } catch (error) {
      if (generation === this.generation && !scope.aborted) {
        if (this.state.continuing && this.receipt && error instanceof OperationFailure && ['AcquisitionClosed', 'AcquisitionUncertain'].includes(error.code)) this.receipt.continuationBlocked = true;
        const message = operationMessage(error);
        this.publish({ error: this.state.continuing && !this.receipt?.continuationBlocked ? message + " Collection may already have started. Check its status before retrying this same request." : message });
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
    if (data) this.publish({ stage: 'diagnostics', diagnostics: data.diagnostics });
  };
  preview = async (diagnostic = this.selected) => {
    if (this.receipt || this.state.busy || !diagnostic) return;
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
    const pod = data.selected_pods?.[0];
    const requested = input.target_ref!;
    if (data.preset_ref?.name !== 'pod-status' || data.selected_pods?.length !== 1 ||
        data.capture_assessment.planDigest !== data.execution_digest || !data.target_ref ||
        data.capture_assessment.actions.some(action => action.retention.anchorRule !== 'submissionPreparation') ||
        !(['cluster_id', 'namespace', 'kind', 'name'] as const).every(key => data.target_ref![key] === requested[key]) ||
        pod?.cluster_id !== requested.cluster_id || pod.namespace !== requested.namespace ||
        (requested.kind === 'Pod' ? pod.name !== requested.name || data.pod_selection !== 'explicitPod' :
          pod.workload.kind !== requested.kind || pod.workload.name !== requested.name || data.pod_selection !== 'lexicalEligiblePod')) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    const remaining = Math.min(5_000, Date.parse(data.capture_assessment.validUntil) - Date.now(), Date.parse(data.expires_at) - Date.now());
    if (data.capture_enabled && data.blockers.length === 0 && !data.approval_required) this.reviewed = { id: data.preview_id, expiresAt: Date.parse(data.expires_at) };
    this.publish({ stage: 'review', preview: data, stale: remaining <= 0, expired: Date.parse(data.expires_at) <= Date.now() });
    this.timer = setTimeout(() => this.publish({ stale: true }), Math.max(0, remaining));
    this.previewExpiry = setTimeout(() => this.publish({ expired: true }), Math.max(0, Date.parse(data.expires_at) - Date.now()));
  };
  submit = async () => {
    if (this.receipt || this.state.busy) return;
    const preview = this.state.preview;
    const reviewed = this.reviewed;
    if (!reviewed || (this.state.stage !== 'reviewed' && (!preview || !preview.capture_enabled || preview.blockers.length || preview.approval_required))) return;
    if (this.state.expired || reviewed.expiresAt <= Date.now()) {
      this.publish({ expired: true }); return;
    }
    this.receipt = { preview_id: reviewed.id, idempotency_key: this.newID() };
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
      receipt.closed = true; this.reviewed = undefined; this.selected = undefined;
      this.publish({ stage: 'closed', preview: undefined, diagnostics: undefined, progress: undefined, error: undefined });
    }
  };
  private async openAccepted(receipt: Receipt, captureID: string) {
    if (receipt !== this.receipt) return;
    if (receipt.captureID && receipt.captureID !== captureID) {
      this.publish({ error: 'The request outcome could not be verified. Keep the original request and check it again.' }); return;
    }
    receipt.captureID = captureID; delete receipt.closed;
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
