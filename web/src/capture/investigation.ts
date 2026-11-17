import { approvalPath } from './approval-intent';
import { operations as grantOperations, type Operations as GrantOperations } from '../approvals/http';
import type { Session } from '../auth/session';
import type { Recipient } from '../sharing/shares';
import { planFromPreview, planFromSettings, type PlanSnapshot, type PreviousPlan } from './plan-diff';
import { operations, OperationFailure, operationMessage, type Operations, type Target, type Diagnostic, type Preview, type Progress, type HistoryEntry, type Input, type Output, type Operation, type Data } from './http';

// sharing/shareHours: the optional capture-time share of the result (ADR-235);
// no hours means the server default (24 hours after publication).
export type Draft = { target: Target; retention: string; sharing?: Recipient[]; shareHours?: number };
export type State = {
  stage: 'target' | 'diagnostics' | 'recordings' | 'review' | 'reviewed' | 'uncertain' | 'progress' | 'approval';
  busy: boolean; draft: Draft; diagnostics?: Diagnostic[]; preview?: Preview;
  cancellationStatus?: 'requested' | 'unconfirmed'; progress?: Progress; captureID?: string; approvalURI?: string; error?: string; stale?: boolean;
  // ADR-335 D5: resubmit only when approval came after the requester's sign-in ended.
  resubmit?: boolean;
  // ADR-236: recent captures of the draft target and the capture a review repeats.
  history?: HistoryEntry[]; historyMessage?: string; repeatedFrom?: string;
  recordingRepeat?: { policyUID: string; captureID: string; before?: string };
  historyOrigin?: 'manual' | 'policy' | 'discovery' | 'all'; historyCursor?: string; settings?: Data<'get_capture_settings'>;
  // REQ-CPR-005: the plan an edited composition preview is compared with.
  previousPlan?: PreviousPlan;
};
export const historyPageSize = 10;
export type PreviewRequest = NonNullable<Input<'request_capture'>['preview']>;
// ADR-330 D9: previews are stateless. The reviewed preview input and its
// plan_digest are resubmitted; the server recomputes the plan (ReviewChanged).
type Reviewed = { preview: PreviewRequest; expected_plan_digest: string };
// The submission keeps its idempotency key so a retry never recollects.
type Receipt = { submission?: Input<'request_capture'>; operation?: 'recordingSave'; captureID?: string; revision?: number; approvalURI?: string };
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
  private events?: EventSource;
  private receipt?: Receipt;
  private cancellation?: Input<'cancel_capture'>;
  private reviewed?: Reviewed;
  private selected?: Diagnostic;
  private selectedComposition?: NonNullable<Input<'preview_capture'>['profile_composition']>;
  private repeatOf?: string;
  private repeatSelection?: 'currentEligiblePod';
  private repeatRetention?: string;
  // The last reviewed composition when the user went back to change profiles.
  private priorPlan?: PlanSnapshot;
  private settingsExpiry?: ReturnType<typeof setTimeout>;
  private historyExpiry?: ReturnType<typeof setTimeout>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(readonly client: Operations = operations, private newID: () => string = () => crypto.randomUUID(), private grants: GrantOperations = grantOperations) {}
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
    for (const listener of this.listeners) listener();
  }
  private invalidate() { ++this.generation; this.request?.abort(); clearTimeout(this.timer); this.closeEvents(); clearTimeout(this.settingsExpiry); this.state = { ...this.state, settings: undefined }; }
  private receiptStage(): State['stage'] { return this.receipt?.captureID ? 'progress' : this.receipt?.approvalURI ? 'approval' : 'uncertain'; }

  attach(session: Session, scope: AbortSignal, captureID?: string) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    this.invalidate();
    this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = undefined;
    if (captureID && !this.receipt) this.receipt = { captureID };
    this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, error: undefined, busy: false, history: undefined, historyMessage: undefined,
      recordingRepeat: undefined, captureID: this.receipt?.captureID, approvalURI: this.receipt?.approvalURI, stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target' });
    const abort = () => {
      this.invalidate(); this.session = undefined; this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = undefined;
      this.publish({ diagnostics: undefined, preview: undefined, progress: undefined, busy: false, history: undefined, historyMessage: undefined,
        recordingRepeat: undefined, stage: this.receipt ? this.receiptStage() : this.reviewed ? 'reviewed' : 'target' });
    };
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    else if (this.receipt?.captureID) void this.refreshProgress();
    else if (this.receipt?.approvalURI) void this.checkApproval();
    return () => { scope.removeEventListener('abort', abort); abort(); };
  }

  reset = () => {
    this.invalidate(); this.identity = undefined; this.session = undefined; this.scope = undefined;
    clearTimeout(this.historyExpiry);
    this.receipt = undefined; this.cancellation = undefined; this.selected = undefined; this.selectedComposition = undefined; this.reviewed = undefined; this.repeatOf = undefined; this.priorPlan = undefined;
    this.state = { stage: 'target', busy: false, draft: emptyDraft() };
    for (const listener of this.listeners) listener();
  };
  setDraft = (draft: Draft) => {
    if (this.receipt || this.state.busy) return;
    this.invalidate(); this.selected = undefined; this.selectedComposition = undefined; this.reviewed = undefined; this.repeatOf = undefined; this.priorPlan = undefined;
    this.publish({ draft: structuredClone(draft), stage: 'target', preview: undefined, diagnostics: undefined, error: undefined, history: undefined, historyMessage: undefined });
  };
  edit = () => { if (!this.receipt) { this.invalidate(); this.reviewed = undefined; this.repeatOf = undefined; this.priorPlan = undefined; this.publish({ stage: 'target', preview: undefined, previousPlan: undefined, diagnostics: undefined, approvalURI: undefined, error: undefined, busy: false, history: undefined, historyMessage: undefined }); } };
  // ApprovalRequired admitted nothing, so the pending submission can be dropped.
  discardApprovalRequest = () => { if (this.receipt?.approvalURI && !this.receipt.captureID && !this.state.busy) { this.receipt = undefined; this.edit(); } };
  // Back to the profile composer with the reviewed plan kept for comparison;
  // the next composition preview shows a before/after diff (REQ-CPR-005).
  changeProfiles = () => {
    const preview = this.state.preview;
    if (this.receipt || this.state.busy || this.state.stage !== 'review' || !preview?.profile_composition || this.repeatOf) return;
    this.priorPlan = planFromPreview(preview);
    this.invalidate(); this.reviewed = undefined; this.selectedComposition = undefined;
    this.publish({ stage: 'diagnostics', preview: undefined, previousPlan: undefined, error: undefined });
  };

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
          this.publish({ stage: 'approval', approvalURI: path, error: undefined, resubmit: undefined });
          return;
        }
      }
      // Every accepted request returns its capture on retry, so a final error
      // proves non-admission: the receipt is released for a new review.
      if (name === 'request_capture' && result.status === 'error' && !result.data.retryable && this.receipt && !this.receipt.captureID) {
        this.receipt = undefined; this.reviewed = undefined;
        this.publish({ stage: 'target', approvalURI: undefined, preview: undefined });
      }
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This operation is still pending. Check it again before continuing.');
      if (name === 'list_capture_history') this.publish({ historyCursor: result.next_cursor ?? undefined });
      return result.data as Data<N>;
    } catch (error) {
      if (generation === this.generation && !scope.aborted) {
        this.publish({ error: operationMessage(error) });
      }
      return;
    } finally {
      scope.removeEventListener('abort', abort);
      if (generation === this.generation) this.publish({ busy: false });
    }
  }

  showRecordings = () => {
    if (this.receipt || this.state.busy) return;
    this.invalidate(); this.selected = undefined; this.selectedComposition = undefined; this.reviewed = undefined;
    this.publish({ stage: 'recordings', diagnostics: undefined, preview: undefined, error: undefined, recordingRepeat: undefined });
  };
  // The recordings view already verified its passive preview; the receipt
  // exists before I/O so an uncertain reply retries the same key.
  submitRecordingSave = async (preview: PreviewRequest, digest: string) => {
    if (this.receipt || this.state.busy || this.state.stage !== 'recordings' || !this.session || !this.scope || this.scope.aborted) return;
    this.cancellation = undefined;
    this.receipt = { operation: 'recordingSave', submission: { preview: structuredClone(preview), expected_plan_digest: digest, idempotency_key: this.newID() } };
    await this.retrySubmission();
  };
  selectRecordingsAgain = (settings: Data<'get_capture_settings'>) => {
    if (this.state.busy || settings.kind !== 'recordingSaveSettings' || Date.parse(settings.expires_at) <= Date.now()) return;
    const workload = settings.settings.target.workloadRef;
    if (!workload || this.receipt && this.receipt.captureID !== settings.capture_id) return;
    this.invalidate(); this.receipt = undefined; this.cancellation = undefined; this.reviewed = undefined;
    this.publish({ stage: 'recordings', draft: { target: { cluster_id: settings.cluster_id, namespace: settings.settings.target.namespace, kind: workload.kind, name: workload.name }, retention: '' },
      recordingRepeat: { policyUID: settings.settings.policy.policyUID, captureID: settings.capture_id, ...(settings.settings.action_windows.length === 1 && { before: settings.settings.action_windows[0].before }) },
      captureID: undefined, progress: undefined, settings: undefined, preview: undefined, diagnostics: undefined, error: undefined });
  };
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
    if (this.state.busy) return;
    if (this.state.history?.some(entry => entry.capture_id === captureID && entry.operation === 'recordingSave') || this.state.settings?.kind === 'recordingSaveSettings' && this.state.settings.capture_id === captureID) {
      if (this.state.settings?.capture_id !== captureID) await this.showSettings(captureID);
      const saved = this.state.settings;
      if (saved?.kind === 'recordingSaveSettings' && saved.capture_id === captureID) this.selectRecordingsAgain(saved);
      return;
    }
    if (!this.prepareHistoryRepeat(captureID)) return;
    this.selected = undefined; this.selectedComposition = undefined; this.repeatOf = captureID; this.reviewed = undefined;
    this.repeatSelection = selection;
    this.repeatRetention = undefined;
    const requested = structuredClone(this.state.draft.target);
    this.publish({ stage: 'diagnostics', preview: undefined });
    const input: Input<'preview_capture'> = { history_capture_id: captureID, ...(selection && { history_selection: selection }) };
    const data = await this.run('preview_capture', input);
    if (!data || this.repeatOf !== captureID) return;
    if (data.repeated_from_capture_id !== captureID) {
      this.publish({ error: 'The review response could not be verified. Refresh the review before continuing.' }); return;
    }
    this.acceptPreview(data, input, requested);
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
    this.acceptPreview(data, input, input.target_ref!);
  };
  // An already-authored/restored typed composition, not a profile editor or
  // a catalog entry invented by the browser. The server resolves every pin.
  previewComposition = async (composition: NonNullable<Input<'preview_capture'>['profile_composition']>, repeatedFrom?: string, selection?: 'currentEligiblePod', requestedRetention?: string) => {
    if (this.state.busy || (this.receipt && !repeatedFrom)) return;
    // The comparison baseline: the saved settings being edited, the review the
    // user went back from, or (on refresh) the comparison already shown.
    const saved = this.state.settings;
    const previousPlan: PreviousPlan | undefined = repeatedFrom
      ? saved?.kind === 'captureSettings' && saved.capture_id === repeatedFrom && saved.settings.profile_composition ? { from: 'settings', captureID: repeatedFrom, plan: planFromSettings(saved)! }
        : this.state.stage === 'review' && this.state.previousPlan?.captureID === repeatedFrom ? this.state.previousPlan : undefined
      : this.priorPlan ? { from: 'preview', plan: this.priorPlan } : this.state.stage === 'review' && this.state.previousPlan?.from === 'preview' ? this.state.previousPlan : undefined;
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
    this.priorPlan = undefined;
    this.acceptPreview(data, input, input.target_ref!, previousPlan);
  };
  private acceptPreview(data: Preview, input: Input<'preview_capture'>, requested: Target, previousPlan?: PreviousPlan) {
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
    const remaining = Math.min(5_000, Date.parse(data.capture_assessment.validUntil) - Date.now());
    if (requestablePreview(data)) this.reviewed = { preview: structuredClone(input) as PreviewRequest, expected_plan_digest: data.plan_digest };
    this.publish({ stage: 'review', preview: data, previousPlan, repeatedFrom: data.repeated_from_capture_id, stale: remaining <= 0 });
    this.timer = setTimeout(() => this.publish({ stale: true }), Math.max(0, remaining));
  }
  submit = async (resultAccess?: Input<'request_capture'>['result_access']) => {
    if (this.receipt || this.state.busy) return;
    const preview = this.state.preview;
    const reviewed = this.reviewed;
    if (!reviewed || (this.state.stage !== 'reviewed' && (!preview || !requestablePreview(preview)))) return;
    this.receipt = { submission: { ...structuredClone(reviewed), idempotency_key: this.newID(), ...(resultAccess && { result_access: structuredClone(resultAccess) }) } };
    this.reviewed = undefined;
    await this.retrySubmission();
  };
  retrySubmission = async () => {
    const receipt = this.receipt;
    if (!receipt?.submission || receipt.captureID || this.state.busy) return;
    // The receipt is held in memory before network I/O: a lost reply may follow
    // a commit, and only this exact retry (same request and key) is offered.
    this.publish({ stage: 'uncertain', preview: undefined, diagnostics: undefined });
    const data = await this.run('request_capture', structuredClone(receipt.submission));
    if (!data && receipt === this.receipt && this.state.stage === 'approval') void this.checkApproval();
    if (!data || receipt !== this.receipt) return;
    if (receipt.operation && data.operation !== receipt.operation) { this.publish({ error: 'The saved recording outcome could not be verified. Retry the same request.' }); return; }
    await this.openAccepted(receipt, data.capture_id);
  };
  // ADR-335 D5: approval submits the stored request itself. While the review
  // is pending the tab waits for its capture. An approved request is read
  // back with the same key, which never collects twice. Only an approval
  // after the requester's sign-in ended needs a new submission.
  checkApproval = async () => {
    const receipt = this.receipt, session = this.session, scope = this.scope;
    const grantID = receipt?.approvalURI?.split('/').pop();
    if (!receipt || receipt.captureID || !grantID || !session || !scope || scope.aborted || this.state.busy) return;
    let result: Awaited<ReturnType<GrantOperations['call']>>;
    this.publish({ busy: true, error: undefined });
    try { result = await this.grants.call('get_grant', { grant_id: grantID }, session.csrf_token, scope); }
    catch (error) { if (receipt === this.receipt) this.publish({ busy: false, error: operationMessage(error) }); return; }
    if (receipt !== this.receipt || scope.aborted) return;
    this.publish({ busy: false });
    const grant = result.status === 'ok' && 'capture_id' in result.data ? result.data : undefined;
    if (!grant?.capture_id) { this.publish({ error: result.status === 'error' ? result.data.message : 'The approval could not be read. Check it again.' }); return; }
    if (grant.phase === 'Pending') { this.awaitCapture(grant.capture_id); return; }
    if (grant.phase !== 'Approved') { this.closeEvents(); this.publish({ error: 'The approval ended (' + grant.phase + '). Nothing was collected. Review a new preview to ask again.' }); return; }
    if (grant.can_resume) { this.closeEvents(); this.publish({ resubmit: true }); return; }
    await this.retrySubmission();
  };
  private awaitCapture(id: string) {
    if (this.events) return;
    const events = new EventSource('/api/v1/events?capture_id=' + encodeURIComponent(id));
    this.events = events;
    events.addEventListener('capture', () => {
      if (this.events !== events || !this.receipt) return;
      this.closeEvents();
      void this.openAccepted(this.receipt, id);
    });
    events.addEventListener('error', () => { if (this.events === events && events.readyState === EventSource.CLOSED) this.events = undefined; });
  }
  private async openAccepted(receipt: Receipt, captureID: string) {
    if (receipt !== this.receipt) return;
    if (receipt.captureID && receipt.captureID !== captureID) {
      this.publish({ error: 'The request outcome could not be verified. Keep the original request and check it again.' }); return;
    }
    receipt.captureID = captureID; delete receipt.approvalURI;
    this.publish({ stage: 'progress', captureID, error: undefined, resubmit: undefined });
    window.history.replaceState(null, '', '/captures/' + captureID);
    await this.refreshProgress();
  }
  cancelRecordingSave = async () => {
    const progress = this.state.progress;
    if (!progress || progress.operation !== 'recordingSave' || !progress.can_cancel || progress.cancellation_requested || terminal.has(progress.phase) || this.state.busy || progress.capture_id !== this.receipt?.captureID) return;
    this.cancellation ??= { capture_id: progress.capture_id, expected_revision: progress.revision, idempotency_key: this.newID() };
    if (this.cancellation.capture_id !== progress.capture_id) return;
    const scope = this.scope;
    const decision = await this.run('cancel_capture', this.cancellation);
    if (scope !== this.scope || scope?.aborted || !this.session || this.receipt?.captureID !== progress.capture_id) return;
    if (!decision) { this.publish({ cancellationStatus: 'unconfirmed', error: 'Cancellation delivery is unconfirmed. Retry the same cancellation or check the parent save status.' }); return; }
    if (decision.capture_id !== progress.capture_id || decision.revision < progress.revision) {
      this.publish({ cancellationStatus: 'unconfirmed', error: 'The cancellation response could not be verified. Check the parent save status.' }); return;
    }
    if (this.receipt?.captureID === decision.capture_id) this.receipt.revision = Math.max(this.receipt.revision ?? 0, decision.revision);
    this.publish({ cancellationStatus: decision.cancellation_requested ? 'requested' : undefined });
    // Only current parent progress establishes joined cancellation or stored
    // results. The acknowledgement never substitutes a terminal outcome.
    await this.refreshProgress();
  };
  refreshProgress = async () => {
    const id = this.receipt?.captureID;
    if (!id || this.state.busy) return;
    const data = await this.run('get_capture', { capture_id: id });
    if (!data) { this.publish({ progress: undefined }); return; }
    if (this.applyProgress(id, data) && !this.events) this.follow(id);
  };
  // Server-Sent Events push each committed progress change (REQ-INT-003);
  // the console sends no status polls.
  private follow(id: string) {
    const events = new EventSource('/api/v1/events?capture_id=' + encodeURIComponent(id));
    this.events = events;
    events.addEventListener('capture', message => {
      if (this.events !== events) return;
      let envelope: { status: string; data: Data<'get_capture'> } | undefined;
      try { envelope = JSON.parse((message as MessageEvent<string>).data).result; } catch { envelope = undefined; }
      if (!envelope || envelope.status !== 'ok' || !this.applyProgress(id, envelope.data)) this.closeEvents();
    });
    // EventSource retries a dropped connection itself; a refused reconnect
    // closes it. Resynchronize once and follow again, or say updates stopped.
    events.addEventListener('error', () => {
      if (this.events !== events || events.readyState !== EventSource.CLOSED) return;
      this.events = undefined;
      void this.resync(id);
    });
    events.addEventListener('accessLost', () => {
      if (this.events !== events) return;
      this.closeEvents();
      this.publish({ progress: undefined, error: 'You no longer have access to this collection status.' });
    });
  }
  private async resync(id: string) {
    const data = this.receipt?.captureID === id ? await this.run('get_capture', { capture_id: id }) : undefined;
    if (this.receipt?.captureID !== id) return;
    if (!data) { this.publish({ error: 'Collection status updates stopped. Check status again to resume them.' }); return; }
    if (this.applyProgress(id, data) && !this.events) this.follow(id);
  }
  private closeEvents() { this.events?.close(); this.events = undefined; }
  // Applies one verified status; true while the capture is still running.
  private applyProgress(id: string, data: Data<'get_capture'>): boolean {
    if (!validActionInstances(data) || data.capture_id !== id || this.receipt?.operation && data.operation !== this.receipt.operation || data.revision < (this.receipt?.revision ?? 0)) {
      this.publish({ progress: undefined, error: 'The collection status could not be verified. Try checking it again.' }); return false;
    }
    if (this.receipt?.captureID !== id) return false;
    this.receipt.revision = data.revision;
    if (terminal.has(data.phase)) this.cancellation = undefined;
    this.publish({ stage: 'progress', progress: data, cancellationStatus: data.cancellation_requested && !terminal.has(data.phase) ? 'requested' : this.state.cancellationStatus === 'unconfirmed' && !terminal.has(data.phase) ? 'unconfirmed' : undefined });
    return !terminal.has(data.phase);
  }
}

// Button eligibility only; current server authority decides every submission.
export function requestablePreview(preview: Preview): boolean {
  return preview.approval_required ? preview.blockers.every(b => b.code === 'ApprovalRequired') : preview.capture_enabled && preview.blockers.length === 0;
}

function validActionInstances(progress: Progress): boolean {
  if (!progress.actions.some(action => action.action_instance_id !== undefined)) return true;
  return progress.operation === 'recordingSave' && progress.actions.length >= 1 && progress.actions.length <= 16 &&
    progress.actions.every(action => !!action.action_instance_id && action.action_instance_id !== progress.capture_id && !!action.pod_uid && !!action.pod_name) &&
    new Set(progress.actions.map(action => action.action_instance_id)).size === progress.actions.length;
}
