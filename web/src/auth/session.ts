import type { components } from '../generated/auth';
import { validCSRF, validSession } from '../generated/validate-auth';
import { authRequest, SessionFailure } from './http';

export type Session = components['schemas']['Session'];
export type SessionState =
  | { phase: 'checking' | 'signedOut' | 'unavailable' | 'signingOut'; reason?: 'expired' | 'logoutFailed' | 'hidden' }
  | { phase: 'active'; session: Session; scope: AbortSignal };

async function authAfterBusy(path: '/auth/csrf' | '/auth/refresh' | '/auth/logout', signal: AbortSignal, attemptUntil: number, onBusy: () => void, csrf?: string): Promise<unknown> {
  for (;;) {
    try { return await authRequest(path, signal, csrf); }
    catch (error) {
      if (!(error instanceof SessionFailure) || !error.busy) throw error;
      onBusy();
      // CSRF and its subsequent POST share one original attempt budget. A collision
      // never renews the page's data scope or absolute session expiry.
      if (Date.now() + 1_000 >= attemptUntil || signal.aborted) throw error;
      await new Promise<void>(resolve => {
        const done = () => { clearTimeout(timer); signal.removeEventListener('abort', done); resolve(); };
        const timer = setTimeout(done, 1_000);
        signal.addEventListener('abort', done, { once: true });
        if (signal.aborted) done();
      });
      if (signal.aborted) throw error;
    }
  }
}

// In-memory UI coordination only. Every application request still requires the
// server's current identity, scope and disclosure checks.
export class BrowserSession {
  private state: SessionState = { phase: 'checking' };
  private listeners = new Set<() => void>();
  private request?: AbortController;
  private scope?: AbortController;
  private generation = 0;
  private csrf?: string;
  private expiry?: ReturnType<typeof setTimeout>;
  private refresh?: ReturnType<typeof setTimeout>;
  private disposed = false;
  private logoutPending = false;
  private pending?: Promise<void>;
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };

  private publish(state: SessionState) { this.state = state; for (const listener of this.listeners) listener(); }
  private clearTimers() { clearTimeout(this.expiry); clearTimeout(this.refresh); }
  private invalidate() { this.scope?.abort(); this.scope = undefined; this.clearTimers(); }
  private current(generation: number) { return !this.disposed && generation === this.generation; }

  resume = (): Promise<void> => {
    if (this.disposed || this.logoutPending) return Promise.resolve();
    if (this.pending) return this.pending;
    const previous = this.state.phase === 'active' ? this.state.session : undefined;
    const generation = ++this.generation;
    const request = new AbortController();
    this.request = request;
    clearTimeout(this.refresh);
    const attemptUntil = Math.min(Date.now() + 10_000, previous ? Date.parse(previous.expires_at) : Infinity);
    const attemptTimer = setTimeout(() => request.abort(), Math.max(0, attemptUntil - Date.now()));
    if (!previous) this.publish({ phase: 'checking' });
    const work = async () => {
      let observedBusy = false;
      try {
        const token = await authAfterBusy('/auth/csrf', request.signal, attemptUntil, () => { observedBusy = true; });
        if (!this.current(generation)) return;
        if (!validCSRF(token)) throw new SessionFailure(502);
        this.csrf = token.csrf_token;
        const value = await authAfterBusy('/auth/refresh', request.signal, attemptUntil, () => { observedBusy = true; }, this.csrf);
        if (!this.current(generation)) return;
        if (!validSession(value) || value.principal.kind !== 'user') throw new SessionFailure(502);
        const sameIdentity = previous && previous.principal.issuer === value.principal.issuer && previous.principal.subject_id === value.principal.subject_id;
        const until = Math.min(Date.parse(value.expires_at), sameIdentity ? Date.parse(previous.expires_at) : Infinity);
        if (until <= Date.now()) throw new SessionFailure(401);
        this.invalidate();
        this.scope = new AbortController();
        this.csrf = value.csrf_token;
        this.publish({ phase: 'active', session: { ...value, expires_at: new Date(until).toISOString() }, scope: this.scope.signal });
        this.expiry = setTimeout(() => this.expire(), until - Date.now());
        this.scheduleRefresh(until);
      } catch (error) {
        if (!this.current(generation)) return;
        const denied = error instanceof SessionFailure && [401, 403].includes(error.status);
        if (!denied && (error instanceof SessionFailure && error.busy || observedBusy && request.signal.aborted)) {
          if (!previous) this.publish({ phase: 'unavailable' });
          else this.scheduleRefresh(Date.parse(previous.expires_at));
          return;
        }
        this.invalidate();
        this.publish({ phase: denied ? 'signedOut' : 'unavailable' });
        if (denied) this.csrf = undefined;
      }
    };
    const pending = work().finally(() => { clearTimeout(attemptTimer); if (this.pending === pending) this.pending = undefined; });
    this.pending = pending;
    return pending;
  };

  private scheduleRefresh(until: number) {
    clearTimeout(this.refresh);
    if (!this.disposed && Date.now() < until) this.refresh = setTimeout(() => { void this.resume(); }, Math.min(60_000, until - Date.now()));
  }

  private expire() {
    ++this.generation;
    this.request?.abort(); this.pending = undefined;
    this.invalidate(); this.csrf = undefined;
    this.publish({ phase: 'signedOut', reason: 'expired' });
  }

  // A bfcache/background page must not redisplay old protected content before a
  // current session check. Browser visibility does not renew server authority.
  suspend = () => {
    if (this.disposed) return;
    ++this.generation;
    this.request?.abort(); this.pending = undefined;
    this.invalidate();
    this.publish(this.logoutPending ? { phase: 'unavailable', reason: 'logoutFailed' } : { phase: 'checking', reason: 'hidden' });
  };

  logout = async () => {
    if (this.disposed || this.state.phase === 'signingOut') return;
    const logoutUntil = Math.min(Date.now() + 10_000, this.state.phase === 'active' ? Date.parse(this.state.session.expires_at) : Infinity);
    const generation = ++this.generation;
    this.logoutPending = true;
    this.request?.abort(); this.pending = undefined;
    this.invalidate();
    this.publish({ phase: 'signingOut' });
    const request = new AbortController();
    this.request = request;
    const logoutTimer = setTimeout(() => request.abort(), Math.max(0, logoutUntil - Date.now()));
    try {
      // This still works during protected-settings outages; it returns no user.
      const token = await authAfterBusy('/auth/csrf', request.signal, logoutUntil, () => {});
      if (!this.current(generation)) return;
      if (!validCSRF(token)) throw new SessionFailure(502);
      // Only canonical pre-revocation Busy is retryable. Network failures and
      // uncertain revocation responses still require an explicit user retry.
      await authAfterBusy('/auth/logout', request.signal, logoutUntil, () => {}, token.csrf_token);
      if (this.current(generation)) { this.csrf = undefined; this.logoutPending = false; this.publish({ phase: 'signedOut' }); }
    } catch (error) {
      if (!this.current(generation)) return;
      if (error instanceof SessionFailure && error.status === 401) {
        this.csrf = undefined; this.logoutPending = false; this.publish({ phase: 'signedOut' });
      } else this.publish({ phase: 'unavailable', reason: 'logoutFailed' });
    } finally { clearTimeout(logoutTimer); }
  };

  close = () => {
    this.disposed = true; ++this.generation;
    this.request?.abort(); this.pending = undefined;
    this.invalidate(); this.csrf = undefined;
    this.state = { phase: 'signedOut' }; this.listeners.clear();
  };
}
