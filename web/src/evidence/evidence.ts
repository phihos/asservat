import type { Session } from '../auth/session';
import { operations, operationMessage, OperationFailure, type Operations, type Operation, type Input, type Output, type CaseDetails, type Artifact, type Download, type CancellationReceipt } from './http';

export type State = { busy: boolean; rawApprovalArtifact?: string; caseID?: string; details?: CaseDetails; download?: Download; error?: string; preparingArtifact?: string; uncertain?: boolean; cancelling?: boolean; started?: boolean; cancellation?: CancellationReceipt };
type Receipt = { artifactID: string; prepareKey: string; downloadID?: string; cancelKey?: string; terminal?: true; restartKey?: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isStatus = (value: unknown): value is Download => typeof (value as Download).artifact_id === 'string';

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
    this.publish({ caseID, busy: false, rawApprovalArtifact: undefined, details: undefined, download: undefined, cancellation: undefined, error: undefined, started: false, preparingArtifact: this.receipt?.artifactID, uncertain: !!this.receipt && !this.receipt.downloadID, cancelling: !!this.receipt?.cancelKey });
    const abort = () => { this.invalidate(); clearTimeout(this.caseExpiryTimer); this.session = undefined; this.publish({ busy: false, rawApprovalArtifact: undefined, details: undefined, download: undefined, cancellation: undefined, error: undefined, started: false }); };
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort(); else void this.refresh();
    return () => { scope.removeEventListener('abort', abort); abort(); };
  }
  // Returns the validated result, error results included; transport failures
  // publish their message and return undefined.
  private async run<N extends Operation>(name: N, input: Input<N>): Promise<Output<N> | undefined> {
    if (!this.session || !this.scope || this.scope.aborted) return;
    this.invalidate(); const generation = this.generation; const scope = this.scope;
    const request = new AbortController(); this.active = request;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    this.publish({ busy: true, error: undefined });
    try {
      const result = await this.client.call(name, input, this.session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted) return;
      return result;
    } catch (error) { if (generation === this.generation && !scope.aborted) this.publish({ error: operationMessage(error) }); }
    finally { scope.removeEventListener('abort', abort); if (generation === this.generation) this.publish({ busy: false }); }
  }
  private fail(result: Output<Operation>) {
    if (result.status === 'error') this.publish({ error: operationMessage(new OperationFailure(503, result.data.code, result.data.message)) });
    else this.publish({ error: 'This evidence request is still being prepared. Check the same request again shortly.' });
  }
  refresh = async () => {
    const id = this.state.caseID;
    if (!id || !uuid.test(id) || this.state.busy) return;
    clearTimeout(this.caseExpiryTimer);
    this.publish({ details: undefined, download: undefined });
    const result = await this.run('get_case', { case_id: id });
    if (!result) return;
    if (result.status !== 'ok') { this.fail(result); return; }
    const data = result.data;
    if (data.case.case_id !== id || new Set(data.artifacts.map(a => a.artifact_id)).size !== data.artifacts.length || data.artifacts.some(a => Date.parse(a.expires_at) !== Date.parse(a.handling_notice.expiresAt) || Date.parse(a.handling_notice.deleteBy) <= Date.parse(a.expires_at))) {
      this.publish({ error: 'The evidence details could not be verified. Try checking them again.' }); return;
    }
    this.publish({ details: data });
    this.scheduleCaseExpiry(data);
    if (this.receipt?.downloadID && !this.receipt.terminal) await this.checkDownload();
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
    this.publish({ rawApprovalArtifact: undefined, preparingArtifact: artifact.artifact_id, uncertain: true, started: false });
    await this.retryPreparation();
  };
  retryPreparation = async () => {
    const receipt = this.receipt;
    if (!receipt || receipt.terminal || receipt.cancelKey || this.state.busy) return;
    this.publish({ uncertain: true, rawApprovalArtifact: undefined });
    const result = await this.run('download_artifact', { action: 'prepare', artifact_id: receipt.artifactID, idempotency_key: receipt.prepareKey });
    if (!result || this.receipt !== receipt) return;
    if (result.status === 'error' && result.data.code === 'RawApprovalRequired') { this.publish({ rawApprovalArtifact: receipt.artifactID }); return; }
    this.accept(receipt, result);
  };
  checkDownload = async () => {
    const receipt = this.receipt;
    if (!receipt?.downloadID || this.state.busy) return;
    const result = await this.run('download_artifact', { action: 'status', download_id: receipt.downloadID });
    if (result && this.receipt === receipt) this.accept(receipt, result);
  };
  // Waits server-side for the next state of a Preparing session (status with
  // after_revision); the server resumes the preparation when its worker
  // advances. No busy state, so Cancel stays available; Cancel aborts it.
  private async follow(receipt: Receipt, download: Download) {
    if (!this.session || !this.scope || this.scope.aborted) return;
    const generation = this.generation; const request = new AbortController(); this.active = request;
    const abort = () => request.abort(); const scope = this.scope; scope.addEventListener('abort', abort, { once: true });
    try {
      const result = await this.client.call('download_artifact', { action: 'status', download_id: download.download_id, after_revision: download.revision }, this.session.csrf_token, request.signal);
      if (generation === this.generation && this.receipt === receipt && !scope.aborted) this.accept(receipt, result);
    } catch (error) { if (generation === this.generation && !scope.aborted) this.publish({ error: operationMessage(error) }); }
    finally { scope.removeEventListener('abort', abort); }
  }
  private accept(receipt: Receipt, result: Output<'download_artifact'>) {
    if (result.status !== 'ok') { this.fail(result); return; }
    const data = result.data;
    if (!isStatus(data) || !uuid.test(data.download_id) || data.artifact_id !== receipt.artifactID || (receipt.downloadID && data.download_id !== receipt.downloadID) || (data.content_path && data.content_path !== `/api/v1/downloads/${data.download_id}/content`)) {
      this.publish({ download: undefined, error: 'The download response could not be verified. Keep this tab open and check the same request again.' }); return;
    }
    receipt.downloadID = data.download_id;
    if (data.state !== 'Ready' && data.state !== 'Preparing') receipt.terminal = true;
    this.publish({ download: data, cancellation: undefined, uncertain: false, cancelling: !!receipt.cancelKey });
    clearTimeout(this.timer);
    if (data.state === 'Preparing') { if (!receipt.cancelKey) void this.follow(receipt, data); return; }
    const remaining = Date.parse(data.access_until) - Date.now();
    if (remaining <= 0) { this.publish({ download: undefined }); return; }
    // The link stays usable until access_until; afterwards the view refreshes.
    if (data.state === 'Ready') this.timer = setTimeout(() => { this.publish({ download: undefined }); void this.checkDownload(); }, Math.min(remaining, 2_147_483_647));
  }
  // A browser attachment request is explicit, same-origin and outside the JSON
  // metadata transport. This records intent, not receipt or file persistence.
  startDownload = () => { if (this.canStart()) this.publish({ started: true }); };
  canStart = () => {
    const d = this.state.download;
    return !!d && !this.state.busy && !this.receipt?.cancelKey && d.state === 'Ready' && !!d.content_path && Date.now() < Date.parse(d.access_until);
  };
  canCancel = () => !!this.receipt?.downloadID && !this.receipt.terminal;
  cancel = async () => {
    const receipt = this.receipt;
    if (!receipt?.downloadID || receipt.terminal || this.state.busy) return;
    receipt.cancelKey ??= this.newID();
    clearTimeout(this.timer);
    this.publish({ cancelling: true, download: undefined });
    const result = await this.run('download_artifact', { action: 'cancel', download_id: receipt.downloadID, idempotency_key: receipt.cancelKey });
    if (!result || this.receipt !== receipt) return;
    if (result.status !== 'ok') { this.fail(result); return; }
    const data = result.data;
    if (!isStatus(data) && data.download_id === receipt.downloadID && ['Cancelled', 'AlreadyTerminal'].includes(data.state)) {
      receipt.terminal = true; clearTimeout(this.timer);
      this.publish({ download: undefined, cancellation: data, cancelling: false, uncertain: false });
    } else this.publish({ download: undefined, error: 'The stop receipt could not be verified. Retry the original cancellation request.' });
  };
  // A full browser restart: stop the previous session, then prepare a new one.
  // A native anchor cannot append to the browser's partial file; compatible
  // authenticated clients retain Range and If-Match themselves.
  canRestart = () => {
    const receipt = this.receipt;
    return !!receipt?.downloadID && !this.state.busy && (!!receipt.restartKey || !!this.state.started || !!this.state.error || !!receipt.terminal) &&
      !!this.state.details?.artifacts.some(a => a.artifact_id === receipt.artifactID && Date.parse(a.expires_at) > Date.now());
  };
  restartDownload = async () => {
    if (!this.canRestart()) return;
    const previous = this.receipt!;
    previous.restartKey ??= this.newID();
    if (!previous.terminal) {
      previous.cancelKey ??= this.newID();
      clearTimeout(this.timer);
      this.publish({ cancelling: true, download: undefined, error: undefined });
      const stopped = await this.run('download_artifact', { action: 'cancel', download_id: previous.downloadID!, idempotency_key: previous.cancelKey });
      if (!stopped || this.receipt !== previous) return;
      if (stopped.status !== 'ok' || isStatus(stopped.data) || stopped.data.download_id !== previous.downloadID) {
        this.publish({ error: 'The previous download has not been confirmed stopped. Try starting the new download again; the same requests will be used.' });
        return;
      }
    }
    this.receipt = { artifactID: previous.artifactID, prepareKey: previous.restartKey };
    this.publish({ cancelling: false, cancellation: undefined, uncertain: true, started: false });
    await this.retryPreparation();
  };
  newDownload = () => {
    if (this.state.busy || !this.receipt?.terminal) return;
    this.receipt = undefined; clearTimeout(this.timer);
    this.publish({ download: undefined, cancellation: undefined, preparingArtifact: undefined, uncertain: false, cancelling: false, started: false, error: undefined });
  };
}
