import type { Session } from '../auth/session';
import { validOutput_get_target_discovery, validOutput_get_query_result } from '../generated/validate-projection';
import { operations, type Operations, type Output, type Input } from './http';

export type DiscoveryPage = Extract<Output<'get_target_discovery'>, { status: 'ok' }>['data'];
export type DiscoveryState = { phase: 'idle' | 'loading' | 'pending' | 'result' | 'expired' | 'unavailable' | 'uncertain'; page?: DiscoveryPage; nextCursor?: string; warnings?: string[]; canCheck?: boolean };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// Reads an existing immutable capture. Attaching, paging and checking never
// acquire or refresh a process inventory; an unknown Begin is not replayed.
export class TargetDiscovery {
  private state: DiscoveryState = { phase: 'idle' };
  private listeners = new Set<() => void>();
  private session?: Session; private scope?: AbortSignal; private captureID?: string;
  private active?: AbortController; private detach?: () => void; private generation = 0;
  private input?: Input<'get_target_discovery'>; private handle?: string; private expiry?: string;
  private artifact?: string; private version?: string;
  private cutoff = Infinity; private retryAt = Infinity;
  private timer?: ReturnType<typeof setTimeout>; private pollTimer?: ReturnType<typeof setTimeout>;
  constructor(private client: Operations = operations, private now = () => performance.now()) {}
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(state: DiscoveryState) { this.state = state; for (const listener of this.listeners) listener(); }
  close = () => {
    ++this.generation; this.active?.abort(); this.active = undefined;
    clearTimeout(this.timer); clearTimeout(this.pollTimer); this.timer = undefined; this.pollTimer = undefined;
    this.input = undefined; this.handle = undefined; this.expiry = undefined; this.artifact = undefined; this.version = undefined;
    this.cutoff = Infinity; this.retryAt = Infinity; this.publish({ phase: 'idle' });
  };
  isAttachedTo(session: Session, scope: AbortSignal, captureID: string) { return this.session === session && this.scope === scope && !scope.aborted && this.captureID === captureID; }
  attach(session: Session, scope: AbortSignal, captureID: string) {
    this.detach?.(); this.close(); this.session = session; this.scope = scope; this.captureID = uuid.test(captureID) ? captureID : undefined;
    const abort = () => { this.session = undefined; this.captureID = undefined; this.close(); };
    const detach = () => { if (this.detach !== detach) return; scope.removeEventListener('abort', abort); this.detach = undefined; abort(); };
    this.detach = detach; scope.addEventListener('abort', abort, { once: true }); if (scope.aborted) abort(); return detach;
  }
  inspect = async () => { if (this.state.phase !== 'loading' && this.state.phase !== 'pending') await this.begin(); };
  nextPage = async () => {
    if (this.state.phase !== 'result' || !this.state.nextCursor) return;
    await this.begin(this.state.nextCursor);
  };
  private async begin(cursor?: string) {
    if (!this.session || !this.scope || !this.captureID || this.scope.aborted) return;
    const artifact = cursor ? this.artifact : undefined, version = cursor ? this.version : undefined;
    this.close(); this.artifact = artifact; this.version = version;
    this.input = { capture_id: this.captureID, section: 'processes', limit: 20, ...(cursor ? { cursor } : {}) };
    this.cutoff = this.now() + 60_000; this.arm(); await this.read(false);
  }
  check = async () => { if (this.state.phase === 'pending' && this.handle && this.now() >= this.retryAt) await this.read(true); };
  private arm() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => { this.close(); this.publish({ phase: 'expired' }); }, Math.max(0, this.cutoff - this.now()));
  }
  private async read(poll: boolean) {
    if (!this.input || !this.session || !this.scope || this.scope.aborted || this.now() >= this.cutoff) return;
    const scope = this.scope, generation = ++this.generation, request = new AbortController(), started = this.now();
    this.active = request; const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    clearTimeout(this.pollTimer); this.publish({ phase: 'loading' });
    let received = false;
    try {
      const outer = poll ? await this.client.call('get_query_result', { query_handle: this.handle! }, this.session.csrf_token, request.signal) : await this.client.call('get_target_discovery', this.input, this.session.csrf_token, request.signal);
      received = true;
      if (generation !== this.generation || scope.aborted || request.signal.aborted) return;
      if (!(poll ? validOutput_get_query_result(outer) : validOutput_get_target_discovery(outer))) throw new Error('Discovery unavailable');
      if (outer.status === 'error') { this.close(); this.publish({ phase: 'unavailable' }); return; }
      if (poll && (!('query_handle' in outer.data) || outer.data.query_handle !== this.handle || outer.next_cursor !== null || outer.provenance.length !== 0 || outer.truncated)) throw new Error('Query changed');
      const expiry = outer.data.query_expires_at, observed = outer.data.query_observed_at;
      const duration = Date.parse(expiry) - Date.parse(observed);
      if (!Number.isFinite(duration) || duration <= 1 || duration > 60_000 || this.expiry !== undefined && this.expiry !== expiry) throw new Error('Query interval changed');
      this.expiry = expiry; this.cutoff = Math.min(this.cutoff, started + duration - 1); this.arm();
      if (this.now() >= this.cutoff) { this.close(); this.publish({ phase: 'expired' }); return; }
      if (outer.status === 'pending') {
        if (outer.data_class !== 'metadata' || outer.next_cursor !== null || outer.provenance.length !== 0 || outer.truncated || this.handle && this.handle !== outer.data.query_handle) throw new Error('Pending changed');
        this.handle = outer.data.query_handle; this.retryAt = this.now() + outer.data.retry_after_seconds * 1000;
        this.publish({ phase: 'pending', canCheck: false });
        this.pollTimer = setTimeout(() => { if (generation === this.generation && !scope.aborted && this.now() < this.cutoff) this.publish({ phase: 'pending', canCheck: true }); }, Math.max(0, this.retryAt - this.now())); return;
      }
      if (poll && (!('tool_name' in outer.data) || outer.data.tool_name !== 'get_target_discovery')) throw new Error('Wrong tool');
      const page: unknown = poll && 'result' in outer.data ? outer.data.result : outer;
      if (!validOutput_get_target_discovery(page) || page.status !== 'ok' || page.truncated !== (page.next_cursor !== null) || page.request_id !== outer.request_id || page.data_class !== 'extract' || outer.data_class !== 'extract' || page.provenance.length !== 1 || page.data.capture_id !== this.captureID || page.data.section !== 'processes' || page.data.source_artifact_ids.length !== 1 || page.provenance[0].artifactID !== page.data.source_artifact_ids[0] || page.data.query_observed_at !== observed || page.data.query_expires_at !== expiry || Date.parse(page.data.expires_at) > Date.parse(expiry)) throw new Error('Wrong discovery source');
      const artifact = page.data.source_artifact_ids[0], version = page.provenance[0].digest;
      if (this.artifact !== undefined && this.artifact !== artifact || this.version !== undefined && this.version !== version) throw new Error('Source version changed');
      this.artifact = artifact; this.version = version;
      this.publish({ phase: 'result', page: structuredClone(page.data), nextCursor: page.next_cursor ?? undefined, warnings: [...page.warnings] });
    } catch {
      if (generation === this.generation && !scope.aborted && !request.signal.aborted) {
        this.close(); this.publish({ phase: received ? 'unavailable' : 'uncertain' });
      }
    } finally { scope.removeEventListener('abort', abort); if (generation === this.generation) this.active = undefined; }
  }
}
