import type { Session } from '../auth/session';
import { validInput_get_logs, validOutput_get_logs, validOutput_get_query_result } from '../generated/validate-projection';
import { operations, type Operations, type Input, type Output } from './http';

export type LogQuerySource = { caseID: string; artifactID: string; version: string; grantID?: string; podUID?: string };
export type LogQuerySelection = Pick<Input<'get_logs'>, 'limit'>;
export type LogQueryData = Extract<Output<'get_logs'>, { status: 'ok' }>['data'];
export type LogQueryState = {
  phase: 'idle' | 'loading' | 'pending' | 'result' | 'uncertain' | 'approval-required' | 'unavailable' | 'expired';
  result?: LogQueryData; warnings?: string[]; nextCursor?: string; canCheck?: boolean;
};
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// A receipt owns one selected saved artifact and one explicit query. Next-page
// Begin is separate; retry of an unknown Begin cannot select a successor key.
export class LogQuery {
  private state: LogQueryState = { phase: 'idle' };
  private listeners = new Set<() => void>();
  private session?: Session; private scope?: AbortSignal; private source?: LogQuerySource;
  private active?: AbortController; private detach?: () => void; private generation = 0;
  private attempt?: Input<'get_logs'>; private selection?: LogQuerySelection;
  private handle?: string; private serverExpiry?: string;
  private cutoff = Infinity; private retryAt = Infinity;
  private timer?: ReturnType<typeof setTimeout>; private pollTimer?: ReturnType<typeof setTimeout>;
  constructor(private client: Operations = operations, private now = () => performance.now(), private newID: () => string = () => crypto.randomUUID()) {}
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(state: LogQueryState) { this.state = state; for (const fn of this.listeners) fn(); }
  close = () => {
    ++this.generation; this.active?.abort(); this.active = undefined;
    clearTimeout(this.timer); clearTimeout(this.pollTimer);
    this.attempt = undefined; this.selection = undefined; this.handle = undefined; this.serverExpiry = undefined;
    this.cutoff = Infinity; this.retryAt = Infinity; this.publish({ phase: 'idle' });
  };
  isAttachedTo(session: Session, scope: AbortSignal, source: LogQuerySource) {
    return this.session === session && this.scope === scope && !scope.aborted && JSON.stringify(this.source) === JSON.stringify(source);
  }
  attach(session: Session, scope: AbortSignal, source: LogQuerySource) {
    this.detach?.(); this.close(); this.session = session; this.scope = scope;
    this.source = uuid.test(source.caseID) && uuid.test(source.artifactID) && /^[0-9a-f]{64}$/.test(source.version) && (source.grantID === undefined || uuid.test(source.grantID)) ? { ...source } : undefined;
    const abort = () => { this.session = undefined; this.source = undefined; this.close(); };
    const detach = () => { if (this.detach !== detach) return; scope.removeEventListener('abort', abort); this.detach = undefined; abort(); };
    this.detach = detach; scope.addEventListener('abort', abort, { once: true }); if (scope.aborted) abort(); return detach;
  }
  run = async (selection: LogQuerySelection) => {
    if (['loading', 'pending', 'uncertain'].includes(this.state.phase)) return;
    await this.begin(selection);
  };
  nextPage = async () => {
    if (this.state.phase !== 'result' || !this.state.nextCursor || !this.selection) return;
    await this.begin(this.selection, this.state.nextCursor);
  };
  private async begin(selection: LogQuerySelection, cursor?: string) {
    if (!this.source || !this.session || this.scope?.aborted) return;
    this.close();
    if (!this.source.grantID) { this.publish({ phase: 'approval-required' }); return; }
    const selected: LogQuerySelection = structuredClone(selection);
    const input: Input<'get_logs'> = { ...selected, case_id: this.source.caseID, artifact_id: this.source.artifactID, grant_id: this.source.grantID, idempotency_key: this.newID(), ...(cursor ? { cursor } : {}) };
    if (!validInput_get_logs(input)) { this.publish({ phase: 'unavailable' }); return; }
    this.selection = selected; this.attempt = input; this.cutoff = this.now() + 60_000; this.arm(); await this.read(false);
  }
  retryBegin = async () => { if (this.state.phase === 'uncertain' && this.attempt) await this.read(false); };
  check = async () => { if (this.state.phase === 'pending' && this.handle && this.now() >= this.retryAt) await this.read(true); };
  private arm() {
    clearTimeout(this.timer); this.timer = setTimeout(() => { this.close(); this.publish({ phase: 'expired' }); }, Math.max(0, this.cutoff - this.now()));
  }
  private async read(poll: boolean) {
    if (!this.session || !this.scope || !this.source || !this.attempt || this.now() >= this.cutoff) return;
    const generation = ++this.generation, scope = this.scope, request = new AbortController(), started = this.now();
    this.active = request; const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true }); clearTimeout(this.pollTimer); this.publish({ phase: 'loading' });
    let received = false;
    try {
      const outer = poll ? await this.client.call('get_query_result', { query_handle: this.handle! }, this.session.csrf_token, request.signal) : await this.client.call('get_logs', this.attempt, this.session.csrf_token, request.signal);
      received = true;
      if (generation !== this.generation || scope.aborted || request.signal.aborted) return;
      if (!(poll ? validOutput_get_query_result(outer) : validOutput_get_logs(outer))) throw new Error('Query unavailable');
      if (outer.status === 'error') {
        this.attempt = undefined; this.publish({ phase: outer.data.code === 'RawApprovalRequired' ? 'approval-required' : 'unavailable' }); return;
      }
      if (poll && (!('query_handle' in outer.data) || outer.data.query_handle !== this.handle || outer.provenance.length !== 0 || outer.next_cursor !== null || outer.truncated)) throw new Error('Query changed');
      const expiry = outer.data.query_expires_at, observed = outer.data.query_observed_at;
      const duration = Date.parse(expiry) - Date.parse(observed);
      if (!Number.isFinite(duration) || duration <= 1 || duration > 60_000 || this.serverExpiry !== undefined && this.serverExpiry !== expiry) throw new Error('Query time changed');
      this.serverExpiry = expiry; this.cutoff = Math.min(this.cutoff, started + duration - 1); this.arm();
      if (this.now() >= this.cutoff) { this.close(); this.publish({ phase: 'expired' }); return; }
      if (outer.status === 'pending') {
        if (outer.data_class !== 'metadata' || outer.truncated || outer.next_cursor !== null || outer.provenance.length !== 0 || this.handle && this.handle !== outer.data.query_handle) throw new Error('Pending changed');
        this.handle = outer.data.query_handle; this.retryAt = this.now() + outer.data.retry_after_seconds * 1000;
        this.publish({ phase: 'pending', canCheck: false });
        this.pollTimer = setTimeout(() => { if (generation === this.generation && !scope.aborted && this.now() < this.cutoff) this.publish({ phase: 'pending', canCheck: true }); }, Math.max(0, this.retryAt - this.now())); return;
      }
      const page: unknown = poll && 'result' in outer.data ? outer.data.result : outer;
      if (poll && (!('tool_name' in outer.data) || outer.data.tool_name !== 'get_logs')) throw new Error('Tool changed');
      if (!validOutput_get_logs(page) || page.status !== 'ok' || page.request_id !== outer.request_id || page.data_class !== 'raw' || outer.data_class !== 'raw' || page.provenance.length !== 1 || page.provenance[0].artifactID !== this.source.artifactID || page.provenance[0].digest !== this.source.version || page.data.query_observed_at !== observed || page.data.query_expires_at !== expiry || page.data.kind !== 'logs') throw new Error('Result association changed');
      const data = page.data, c = data.coverage;
      if (data.entries.length > (this.attempt.limit ?? 100) || this.source.podUID !== undefined && data.pod_uid !== this.source.podUID || !Number.isFinite(Date.parse(data.window_start)) || !Number.isFinite(Date.parse(data.window_end)) || Date.parse(data.window_end) < Date.parse(data.window_start) || c.complete_origins + c.partial_origins + c.unavailable_origins !== c.origins || c.unknown_timestamp_origins > c.origins || c.gapped_origins > c.origins || c.total_fragments > c.source_bytes || data.entries.some(e => !validEntry(e, c.origins, c.total_fragments, c.source_bytes, data.window_start, data.window_end)) || page.truncated !== (page.next_cursor !== null) || page.next_cursor === this.attempt.cursor) throw new Error('Query selection changed');
      this.attempt = undefined;
      this.publish({ phase: 'result', result: structuredClone(page.data), warnings: [...page.warnings], ...(page.next_cursor !== null ? { nextCursor: page.next_cursor } : {}) });
    } catch {
      if (generation === this.generation && !scope.aborted) this.publish({ phase: !poll && !received && this.attempt ? 'uncertain' : 'unavailable' });
    } finally { scope.removeEventListener('abort', abort); if (this.active === request) this.active = undefined; }
  }
}

function validEntry(e: LogQueryData['entries'][number], origins: number, fragments: number, total: number, start: string, end: string) {
 if (e.origin.origin_id >= origins || e.fragment >= fragments || e.line < 1 || e.line_offset > e.offset || e.continuation !== (e.line_offset > 0) || e.source_time !== null && (Date.parse(e.source_time) < Date.parse(start) || Date.parse(e.source_time) > Date.parse(end))) return false;
 let bytes: Uint8Array;
 if (e.text !== null) { bytes = new TextEncoder().encode(e.text); if (new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== e.text) return false; }
 else { try { const raw = atob(e.bytes_base64!); if (btoa(raw) !== e.bytes_base64) return false; bytes = Uint8Array.from(raw, c => c.charCodeAt(0)); } catch { return false; } }
 const newline = bytes.indexOf(10);
 return bytes.length > 0 && bytes.length <= 1024 && e.offset + bytes.length <= total && (newline < 0 ? !e.end_line : newline === bytes.length - 1 && e.end_line);
}
