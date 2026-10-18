import type { Session } from '../auth/session';
import { validOutput_get_file_excerpt, validOutput_get_query_result } from '../generated/validate-projection';
import { operations, type Operations, type Excerpt } from './http';

export type State = { phase: 'idle' | 'loading' | 'pending' | 'result' | 'expired' | 'unavailable'; excerpt?: Excerpt; retryAt?: number; canCheck?: boolean };
type Timing = { query_observed_at: string; query_expires_at: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// One transient view, with no storage, global result cache or implicit repeat.
// The request-start clock deliberately includes network/audit delay in its TTL.
export class ContextProjection {
  private state: State = { phase: 'idle' };
  private listeners = new Set<() => void>();
  private session?: Session;
  private scope?: AbortSignal;
  private target?: { case_id: string; artifact_id: string };
  private detach?: () => void;
  private active?: AbortController;
  private generation = 0;
  private cutoff = Infinity;
  private handle?: string;
  private timer?: ReturnType<typeof setTimeout>;
  private pollTimer?: ReturnType<typeof setTimeout>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private now: () => number = () => performance.now()) {}
  private publish(state: State) { this.state = state; for (const listener of this.listeners) listener(); }
  private clear(phase: State['phase']) {
    ++this.generation; this.active?.abort(); this.active = undefined;
    clearTimeout(this.timer); clearTimeout(this.pollTimer); this.timer = undefined; this.pollTimer = undefined; this.handle = undefined; this.cutoff = Infinity;
    this.publish({ phase });
  }
  close = () => this.clear('idle');
  attach(session: Session, scope: AbortSignal, caseID: string, artifactID: string) {
    this.detach?.(); this.close();
    this.session = session; this.scope = scope;
    this.target = uuid.test(caseID) && uuid.test(artifactID) ? { case_id: caseID, artifact_id: artifactID } : undefined;
    const abort = () => { this.session = undefined; this.target = undefined; this.close(); };
    const detach = () => {
      if (this.detach !== detach) return;
      scope.removeEventListener('abort', abort); this.detach = undefined; abort();
    };
    this.detach = detach;
    scope.addEventListener('abort', abort, { once: true });
    if (scope.aborted) abort();
    return detach;
  }
  private acceptTiming(timing: Timing, started: number) {
    // Date.parse truncates fractions to milliseconds. Subtract one millisecond
    // so different fractional endpoints can never extend the original interval.
    const duration = Date.parse(timing.query_expires_at) - Date.parse(timing.query_observed_at);
    if (!Number.isFinite(duration) || duration <= 1 || duration > 60_000) throw new Error('Invalid query interval');
    this.cutoff = Math.min(this.cutoff, started + duration - 1);
    if (this.now() >= this.cutoff) { this.clear('expired'); return false; }
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.clear('expired'), Math.max(0, this.cutoff - this.now()));
    return true;
  }
  inspect = async () => {
    if (this.state.phase === 'loading' || !this.target || !this.session || this.scope?.aborted) return;
    this.close();
    await this.read(false);
  };
  check = async () => {
    if (this.state.phase !== 'pending' || !this.handle || this.now() < (this.state.retryAt ?? Infinity)) return;
    if (this.now() >= this.cutoff) { this.clear('expired'); return; }
    await this.read(true);
  };
  private async read(poll: boolean) {
    if (!this.session || !this.target || !this.scope || this.scope.aborted) return;
    const generation = ++this.generation;
    const request = new AbortController(); this.active = request;
    const scope = this.scope;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    const started = this.now();
    clearTimeout(this.pollTimer);
    this.publish({ phase: 'loading' });
    try {
      const response = poll
        ? await this.client.call('get_query_result', { query_handle: this.handle! }, this.session.csrf_token, request.signal)
        : await this.client.call('get_file_excerpt', { ...this.target, line_start: 1, max_lines: 14 }, this.session.csrf_token, request.signal);
      if (generation !== this.generation || scope.aborted || request.signal.aborted) return;
      const valid = poll ? validOutput_get_query_result(response) : validOutput_get_file_excerpt(response);
      if (!valid || response.data_class !== 'metadata' || response.truncated || response.next_cursor !== null || response.status === 'error') throw new Error('Query unavailable');
      if (poll && response.data.query_handle !== this.handle) throw new Error('Query replaced');
      if (!this.acceptTiming(response.data as Timing, started)) return;
      if (response.status === 'pending') {
        if (this.handle && response.data.query_handle !== this.handle) throw new Error('Query replaced');
        this.handle = response.data.query_handle;
        const retryAt = this.now() + response.data.retry_after_seconds * 1000;
        this.publish({ phase: 'pending', retryAt, canCheck: false });
        if (retryAt < this.cutoff) this.pollTimer = setTimeout(() => {
          if (generation === this.generation && this.state.phase === 'pending' && !scope.aborted && this.now() < this.cutoff) this.publish({ phase: 'pending', retryAt, canCheck: true });
        }, Math.max(0, retryAt - this.now()));
        return;
      }
      let excerpt: unknown = response;
      if (poll) {
        if (!('result' in response.data) || response.data.tool_name !== 'get_file_excerpt') throw new Error('Unexpected query');
        excerpt = response.data.result;
        if (!validOutput_get_file_excerpt(excerpt) || excerpt.request_id !== response.request_id || excerpt.status !== 'ok' ||
          excerpt.data.query_observed_at !== response.data.query_observed_at || excerpt.data.query_expires_at !== response.data.query_expires_at) throw new Error('Query association changed');
      }
      if (!validOutput_get_file_excerpt(excerpt) || excerpt.status !== 'ok' || excerpt.data_class !== 'metadata' || excerpt.truncated || excerpt.next_cursor !== null ||
        excerpt.data.logical_path !== 'pod-status.txt' || excerpt.data.line_start !== 1 || excerpt.data.lines.length !== 14) throw new Error('Unexpected projection');
      this.publish({ phase: 'result', excerpt: { ...excerpt.data, lines: [...excerpt.data.lines] } });
    } catch {
      if (generation === this.generation && !scope.aborted) this.clear('unavailable');
    } finally {
      scope.removeEventListener('abort', abort);
      if (this.active === request) this.active = undefined;
    }
  }
}
