import type { Session } from '../auth/session';
import { operations, operationMessage, OperationFailure, type Operations, type Operation, type Input, type Data, type CaseDetails, type Artifact, type Download, type CancellationReceipt } from './http';

export type State = { busy: boolean; caseID?: string; details?: CaseDetails; download?: Download; error?: string; preparingArtifact?: string; uncertain?: boolean; cancelling?: boolean; started?: boolean; cancellation?: CancellationReceipt };
type Receipt = { artifactID: string; prepareKey: string; downloadID?: string; cancelKey?: string; terminal?: true; continueUntil?: number; restartKey?: string; previousStop?: { downloadID: string; cancelKey: string } };
const hasArtifactStatus = (value: Data<'cancel_artifact_download'>): value is Download => typeof value.artifact_id === 'string';
const terminal = new Set(['Completed', 'Cancelled', 'Expired', 'Denied', 'Failed']);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// Metadata coordination only. No file bytes, provider tokens or plaintext file
// caches are held here. The server authorizes every metadata/content request.
export class Evidence {
  private state: State = { busy: false };
  private listeners = new Set<() => void>();
  private identity?: string;
  private session?: Session;
  private scope?: AbortSignal;
  private active?: AbortController;
  private generation = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private caseExpiryTimer?: ReturnType<typeof setTimeout>;
  private receipt?: Receipt;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private newID: () => string = () => crypto.randomUUID()) {}
  private publish(patch: Partial<State>) { this.state = { ...this.state, ...patch }; for (const listener of this.listeners) listener(); }
  private invalidate() { this.generation++; this.active?.abort(); clearTimeout(this.timer); }
  reset = () => { this.invalidate(); clearTimeout(this.caseExpiryTimer); this.identity = undefined; this.session = undefined; this.scope = undefined; this.receipt = undefined; this.state = { busy: false }; for (const listener of this.listeners) listener(); };
  attach(session: Session, scope: AbortSignal, caseID: string) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity || this.state.caseID !== caseID) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    this.invalidate(); clearTimeout(this.caseExpiryTimer);
    this.publish({ caseID, busy: false, details: undefined, download: undefined, cancellation: undefined, error: undefined, started: false, preparingArtifact: this.receipt?.artifactID, uncertain: !!this.receipt && !this.receipt.downloadID, cancelling: !!this.receipt?.cancelKey });
    const abort = () => { this.invalidate(); clearTimeout(this.caseExpiryTimer); this.session = undefined; this.publish({ busy: false, details: undefined, download: undefined, cancellation: undefined, error: undefined, started: false }); };
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort(); else void this.refresh();
    return () => { scope.removeEventListener('abort', abort); abort(); };
  }
  private async run<N extends Operation>(name: N, input: Input<N>): Promise<Data<N> | undefined> {
    if (!this.session || !this.scope || this.scope.aborted) return;
    this.invalidate(); const generation = this.generation; const scope = this.scope;
    const request = new AbortController(); this.active = request;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    this.publish({ busy: true, error: undefined });
    try {
      const result = await this.client.call(name, input, this.session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted) return;
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This evidence request is still being prepared. Check the same request again shortly.');
      return result.data as Data<N>;
    } catch (error) { if (generation === this.generation && !scope.aborted) this.publish({ error: operationMessage(error) }); }
    finally { scope.removeEventListener('abort', abort); if (generation === this.generation) this.publish({ busy: false }); }
  }
  refresh = async () => {
    const id = this.state.caseID;
    if (!id || !uuid.test(id) || this.state.busy) return;
    clearTimeout(this.caseExpiryTimer);
    this.publish({ details: undefined, download: undefined });
    const data = await this.run('get_case', { case_id: id });
    if (!data) return;
    if (data.case.case_id !== id || new Set(data.artifacts.map(a => a.artifact_id)).size !== data.artifacts.length || data.artifacts.some(a => Date.parse(a.expires_at) !== Date.parse(a.handling_notice.expiresAt) || Date.parse(a.handling_notice.deleteBy) <= Date.parse(a.expires_at))) {
      this.publish({ error: 'The evidence details could not be verified. Try checking them again.' }); return;
    }
    this.publish({ details: data });
    this.scheduleCaseExpiry(data);
    if (this.receipt?.downloadID) await this.checkDownload();
  };
  // Expiry changes only the visible affordance. It never refreshes authority,
  // changes managed dates, prepares a download or polls the network.
  private scheduleCaseExpiry(details: CaseDetails) {
    clearTimeout(this.caseExpiryTimer);
    const now = Date.now();
    const next = Math.min(...details.artifacts.map(a => Date.parse(a.expires_at)).filter(at => at > now));
    if (!Number.isFinite(next)) return;
    this.caseExpiryTimer = setTimeout(() => {
      if (this.state.details !== details || !this.session || this.scope?.aborted) return;
      this.publish({});
      this.scheduleCaseExpiry(details);
    }, Math.min(2_147_483_647, Math.max(1, next - now)));
  }
  prepare = async (artifact: Artifact) => {
    if (this.state.busy || this.receipt || !this.state.details?.artifacts.some(a => a.artifact_id === artifact.artifact_id) || Date.parse(artifact.expires_at) <= Date.now()) return;
    this.receipt = { artifactID: artifact.artifact_id, prepareKey: this.newID() };
    this.publish({ preparingArtifact: artifact.artifact_id, uncertain: true, started: false });
    await this.retryPreparation();
  };
  retryPreparation = async () => {
    const receipt = this.receipt;
    if (!receipt || receipt.terminal || receipt.cancelKey || this.state.busy) return;
    receipt.continueUntil = undefined; // Unknown outcomes never continue automatically.
    this.publish({ uncertain: true });
    const data = await this.run('prepare_artifact_download', { artifact_id: receipt.artifactID, idempotency_key: receipt.prepareKey });
    if (data && this.receipt === receipt) this.acceptStatus(receipt, data, true);
  };
  checkDownload = async () => {
    const receipt = this.receipt;
    if (!receipt?.downloadID || this.state.busy) return;
    this.publish({ download: undefined });
    const data = await this.run('get_artifact_download', { download_id: receipt.downloadID });
    if (data && this.receipt === receipt) this.acceptStatus(receipt, data);
  };
  private acceptStatus(receipt: Receipt, data: Download, prepare = false) {
    if ((receipt.terminal && !terminal.has(data.state)) || !uuid.test(data.download_id) || data.artifact_id !== receipt.artifactID || (receipt.downloadID && data.download_id !== receipt.downloadID) || Date.parse(data.expires_at) > Date.parse(data.managed_read_until) || (data.content_path && data.content_path !== `/api/v1/downloads/${data.download_id}/content`) || (data.state === 'Preparing' && data.filename !== undefined) || ('continue_preparation' in data && (!prepare || data.state !== 'Preparing'))) {
      this.publish({ download: undefined, error: 'The download response could not be verified. Keep this tab open and check the same request again.' }); return;
    }
    receipt.downloadID = data.download_id;
    // Positive new admission resolves the preceding stop/new-prepare handoff.
    receipt.previousStop = undefined;
    if (prepare) receipt.continueUntil = 'continue_preparation' in data && data.continue_preparation ? Math.min(Date.parse(data.expires_at), Date.parse(this.session!.expires_at)) : undefined;
    if (terminal.has(data.state)) receipt.terminal = true;
    this.publish({ download: data, cancellation: undefined, uncertain: false, cancelling: !!receipt.cancelKey });
    clearTimeout(this.timer);
    // Terminal status uses the existing authorized managed-read interval,
    // independently of the already elapsed transfer deadline. Absent native
    // fields replace (and clear) any earlier native metadata; no cache is revived.
    const isTerminal = terminal.has(data.state);
    const remaining = (isTerminal ? Date.parse(data.managed_read_until) : Math.min(Date.parse(data.expires_at), Date.parse(data.managed_read_until))) - Date.now();
    if (remaining <= 0) { if (isTerminal) this.publish({ download: undefined }); return; }
    this.timer = setTimeout(() => {
      this.publish({ download: undefined });
      if (data.state === 'Preparing' && receipt.continueUntil && Date.now() < receipt.continueUntil) void this.retryPreparation(); else void this.checkDownload();
    }, data.state === 'Ready' && !this.state.started ? remaining : Math.min(remaining, terminal.has(data.state) || data.state === 'Interrupted' ? 60_000 : 2_000));
  }
  // A browser attachment request is explicit, same-origin and outside the JSON
  // metadata transport. This records intent, not receipt or file persistence.
  startDownload = () => {
    if (!this.canStart()) return;
    this.publish({ started: true });
    clearTimeout(this.timer); this.timer = setTimeout(() => void this.checkDownload(), 2_000);
  };
  canStart = () => {
    const d = this.state.download;
    return !!d && !this.state.busy && !this.receipt?.cancelKey && ['Ready', 'Interrupted'].includes(d.state) && !!d.content_path && Date.now() < Math.min(Date.parse(d.expires_at), Date.parse(d.managed_read_until));
  };
  canCancel = () => !!this.receipt?.downloadID && !this.receipt.terminal;
  cancel = async () => {
    const receipt = this.receipt;
    if (!receipt?.downloadID || receipt.terminal || this.state.busy || (this.state.download && terminal.has(this.state.download.state))) return;
    receipt.cancelKey ??= this.newID();
    receipt.continueUntil = undefined; clearTimeout(this.timer);
    this.publish({ cancelling: true, download: undefined });
    const data = await this.run('cancel_artifact_download', { download_id: receipt.downloadID, idempotency_key: receipt.cancelKey });
    if (data && this.receipt === receipt) {
      if (hasArtifactStatus(data)) this.acceptStatus(receipt, data);
      else if (data.download_id === receipt.downloadID && ['Cancelled', 'AlreadyTerminal'].includes(data.state)) {
        receipt.terminal = true; receipt.continueUntil = undefined; clearTimeout(this.timer);
        this.publish({ download: undefined, cancellation: data, cancelling: false, uncertain: false });
        // No artifact retention or native-cache lifetime is invented for this
        // minimal receipt. Keep it only within the existing page/session bound.
        this.timer = setTimeout(() => this.newDownload(), Math.max(1, Math.min(60_000, Date.parse(this.session!.expires_at) - Date.now())));
      } else this.publish({ download: undefined, error: 'The stop receipt could not be verified. Retry the original cancellation request.' });
    }
  };
  // This is a full browser restart. A native anchor cannot append to the
  // browser's partial file; compatible authenticated clients retain Range and
  // If-Match themselves. Old reservations are never refunded or rewritten.
  canRestart = () => {
    const receipt = this.receipt;
    return !!receipt?.downloadID && (!receipt.terminal || !!receipt.restartKey) && !this.state.busy &&
      (!!receipt.restartKey || !!this.state.started || this.state.download?.state === 'Interrupted' || !!this.state.error) &&
      !!this.state.details?.artifacts.some(a => a.artifact_id === receipt.artifactID && Date.parse(a.expires_at) > Date.now());
  };
  restartDownload = async () => {
    if (!this.canRestart()) return;
    const previous = this.receipt!;
    previous.cancelKey ??= this.newID();
    previous.restartKey ??= this.newID();
    previous.continueUntil = undefined;
    clearTimeout(this.timer);
    this.publish({ cancelling: true, download: undefined, error: undefined });
    const stopped = await this.run('cancel_artifact_download', { download_id: previous.downloadID!, idempotency_key: previous.cancelKey });
    if (!stopped || this.receipt !== previous) return;
    const confirmed = hasArtifactStatus(stopped)
      ? stopped.download_id === previous.downloadID && stopped.artifact_id === previous.artifactID && terminal.has(stopped.state)
      : stopped.download_id === previous.downloadID && ['Cancelled', 'AlreadyTerminal'].includes(stopped.state);
    if (!confirmed) {
      this.publish({ error: 'The previous download has not been confirmed stopped. Try starting the new download again; the same requests will be used.' });
      return;
    }
    // Keep both original operation keys until this new preparation is positively
    // acknowledged. Lost replies cannot create a succession of fresh sessions.
    this.receipt = { artifactID: previous.artifactID, prepareKey: previous.restartKey!, previousStop: { downloadID: previous.downloadID!, cancelKey: previous.cancelKey } };
    this.publish({ cancelling: false, cancellation: undefined, uncertain: true, started: false });
    await this.retryPreparation();
  };
  newDownload = () => {
    if (this.state.busy || !this.receipt?.terminal) return;
    this.receipt = undefined; clearTimeout(this.timer);
    this.publish({ download: undefined, cancellation: undefined, preparingArtifact: undefined, uncertain: false, cancelling: false, started: false, error: undefined });
  };
}
