import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BrowserSession, type Session } from './session';
import { authRequest } from './http';

const csrf = 'C'.repeat(43);
const session = (changes: Partial<Session> = {}): Session => ({
  principal: { issuer: 'https://identity.invalid', subject_id: 'developer', kind: 'user' },
  roles: [], csrf_token: csrf, expires_at: new Date(Date.now() + 120_000).toISOString(), step_up: 'unavailable', ...changes,
});
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const token = () => json({ csrf_token: csrf });
const busy = () => new Response(JSON.stringify({ type: 'about:blank', title: 'Conflict', status: 409 }), { status: 409, headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '1' } });
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
let controller: BrowserSession;
let fetcher: ReturnType<typeof vi.fn<typeof fetch>>;
beforeEach(() => { vi.useFakeTimers(); controller = new BrowserSession(); fetcher = vi.fn<typeof fetch>(); vi.stubGlobal('fetch', fetcher); });
afterEach(() => { controller.close(); vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('browser session lifecycle', () => {
  it('keeps the workspace hidden until CSRF and current refresh complete; coalesces callers', async () => {
    const refresh = deferred<Response>();
    fetcher.mockResolvedValueOnce(token()).mockReturnValueOnce(refresh.promise);
    const first = controller.resume();
    expect(controller.resume()).toBe(first);
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(controller.snapshot().phase).toBe('checking');
    expect(fetcher.mock.calls[0]).toMatchObject(['/auth/csrf', { method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' }]);
    expect(fetcher.mock.calls[1]).toMatchObject(['/auth/refresh', { method: 'POST', headers: { 'X-CSRF-Token': csrf } }]);
    expect(fetcher.mock.calls[1][1]).not.toHaveProperty('body');
    refresh.resolve(json(session())); await first;
    expect(controller.snapshot().phase).toBe('active');
  });

  it('shows sign-in for a missing cookie and does not call refresh', async () => {
    fetcher.mockResolvedValueOnce(new Response(null, { status: 401 }));
    await controller.resume();
    expect(controller.snapshot().phase).toBe('signedOut');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('clears current scope after an unavailable refresh without automatic retry', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    const state = controller.snapshot();
    if (state.phase !== 'active') throw new Error('not active');
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(new Response(null, { status: 503 }));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(controller.snapshot().phase).toBe('unavailable');
    expect(state.scope.aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(120_000);
    expect(fetcher).toHaveBeenCalledTimes(4);
  });

  it('retains the current workspace while a competing owned refresh joins, then rechecks', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    const current = controller.snapshot();
    if (current.phase !== 'active') throw new Error('not active');
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(busy()).mockResolvedValueOnce(json(session()));
    const pending = controller.resume();
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(4));
    expect(controller.snapshot()).toBe(current);
    expect(current.scope.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1_000);
    await pending;
    expect(fetcher).toHaveBeenCalledTimes(5);
    expect(controller.snapshot().phase).toBe('active');
  });

  it('bounds busy retries without clearing the current page or extending its deadline', async () => {
    const until = Date.now() + 120_000;
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session({ expires_at: new Date(until).toISOString() })));
    await controller.resume();
    const current = controller.snapshot();
    if (current.phase !== 'active') throw new Error('not active');
    fetcher.mockResolvedValueOnce(token()).mockImplementation(async () => busy());
    const pending = controller.resume();
    await vi.advanceTimersByTimeAsync(10_001); await pending;
    expect(controller.snapshot()).toBe(current);
    expect(current.scope.aborted).toBe(false);
    const calls = fetcher.mock.calls.length;
    expect(calls).toBeLessThanOrEqual(13);
    await vi.advanceTimersByTimeAsync(50_000);
    expect(fetcher).toHaveBeenCalledTimes(calls);
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetcher).toHaveBeenCalledTimes(calls + 2);
    expect(controller.snapshot().phase).toBe('active');
    await vi.advanceTimersByTimeAsync(until - Date.now());
    expect(controller.snapshot()).toEqual({ phase: 'signedOut', reason: 'expired' });
    expect(current.scope.aborted).toBe(true);
  });

  it('shares one bounded retry budget between CSRF and POST collisions', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    const original = controller.snapshot();
    let csrfCalls = 0;
    fetcher.mockImplementation(async path => path === '/auth/csrf' && ++csrfCalls > 5 ? token() : busy());
    const pending = controller.resume();
    await vi.advanceTimersByTimeAsync(10_001); await pending;
    expect(controller.snapshot()).toBe(original);
    const calls = fetcher.mock.calls.length;
    expect(calls).toBeLessThanOrEqual(13);
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/refresh')).toHaveLength(6);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetcher).toHaveBeenCalledTimes(calls);
  });

  it('stops busy retry at original session expiry and cannot resurrect it', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session({ expires_at: new Date(Date.now() + 1_500).toISOString() })));
    await controller.resume();
    fetcher.mockResolvedValueOnce(token()).mockImplementation(async () => busy());
    const pending = controller.resume();
    await vi.advanceTimersByTimeAsync(1_500); await pending;
    expect(controller.snapshot()).toEqual({ phase: 'signedOut', reason: 'expired' });
    const calls = fetcher.mock.calls.length;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetcher).toHaveBeenCalledTimes(calls);
  });

  it('cannot extend a fixed deadline for the same user', async () => {
    const deadline = Date.now() + 2_000;
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session({ expires_at: new Date(deadline).toISOString() })));
    await controller.resume();
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    const state = controller.snapshot();
    expect(state.phase === 'active' && Date.parse(state.session.expires_at)).toBe(deadline);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(controller.snapshot()).toEqual({ phase: 'signedOut', reason: 'expired' });
    expect(state.phase === 'active' && state.scope.aborted).toBe(true);
  });

  it('ignores an old response after sign-out even when transport ignores cancellation', async () => {
    const stale = deferred<Response>();
    fetcher.mockResolvedValueOnce(token()).mockReturnValueOnce(stale.promise);
    const pending = controller.resume();
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await controller.logout();
    stale.resolve(json(session())); await pending;
    expect(controller.snapshot().phase).toBe('signedOut');
  });

  it('one click logs out after a concurrent CSRF rotation without replaying the logout POST', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    fetcher.mockResolvedValueOnce(busy()).mockResolvedValueOnce(token()).mockResolvedValueOnce(new Response(null, { status: 204 }));
    const pending = controller.logout();
    await vi.advanceTimersByTimeAsync(1_000); await pending;
    expect(controller.snapshot().phase).toBe('signedOut');
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1);
  });

  it('does not claim sign-out after an ambiguous response and can retry during settings outage', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    fetcher.mockResolvedValueOnce(token()).mockRejectedValueOnce(new TypeError('synthetic network failure'));
    await controller.logout();
    expect(controller.snapshot()).toEqual({ phase: 'unavailable', reason: 'logoutFailed' });
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(new Response(null, { status: 204 }));
    await controller.logout();
    expect(controller.snapshot().phase).toBe('signedOut');
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/refresh')).toHaveLength(1);
  });

  it('one click retries logout rejected before revocation by a concurrent CSRF rotation', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(busy()).mockResolvedValueOnce(new Response(null, { status: 204 }));
    const pending = controller.logout();
    await vi.advanceTimersByTimeAsync(1_000); await pending;
    expect(controller.snapshot().phase).toBe('signedOut');
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(2);
  });

  it('shares the original logout budget between CSRF lookup and pre-revocation retry', async () => {
    let csrfCalls = 0;
    fetcher.mockImplementation(async path => path === '/auth/csrf' && ++csrfCalls > 5 ? token() : busy());
    const pending = controller.logout();
    await vi.advanceTimersByTimeAsync(10_000); await pending;
    expect(controller.snapshot()).toEqual({ phase: 'unavailable', reason: 'logoutFailed' });
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(5);
    const calls = fetcher.mock.calls.length;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(fetcher).toHaveBeenCalledTimes(calls);
  });

  it.each(['network', 'unavailable', 'untyped conflict'])('does not automatically replay logout after %s', async failure => {
    fetcher.mockResolvedValueOnce(token());
    if (failure === 'network') fetcher.mockRejectedValueOnce(new TypeError('synthetic lost reply'));
    else fetcher.mockResolvedValueOnce(new Response(null, { status: failure === 'unavailable' ? 503 : 409 }));
    await controller.logout();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(controller.snapshot()).toEqual({ phase: 'unavailable', reason: 'logoutFailed' });
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1);
  });

  it('does not reopen a workspace when a tab returns after failed sign-out', async () => {
    fetcher.mockResolvedValueOnce(token()).mockRejectedValueOnce(new TypeError('synthetic lost logout reply'));
    await controller.logout();
    controller.suspend();
    await controller.resume();
    expect(controller.snapshot()).toEqual({ phase: 'unavailable', reason: 'logoutFailed' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('aborts the previous data scope on identity replacement and suspension', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session()));
    await controller.resume();
    const old = controller.snapshot();
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session({ principal: { issuer: 'https://identity.invalid', subject_id: 'other', kind: 'user' } })));
    await controller.resume();
    expect(old.phase === 'active' && old.scope.aborted).toBe(true);
    const current = controller.snapshot();
    expect(current.phase === 'active' && current.session.principal.subject_id).toBe('other');
    controller.suspend();
    expect(current.phase === 'active' && current.scope.aborted).toBe(true);
    expect(controller.snapshot().phase).toBe('checking');
  });

  it('never revives an expired session from an in-flight successful refresh', async () => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(session({ expires_at: new Date(Date.now() + 1_000).toISOString() })));
    await controller.resume();
    const late = deferred<Response>();
    fetcher.mockResolvedValueOnce(token()).mockReturnValueOnce(late.promise);
    const pending = controller.resume();
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(4));
    await vi.advanceTimersByTimeAsync(1_000);
    late.resolve(json(session())); await pending;
    expect(controller.snapshot()).toEqual({ phase: 'signedOut', reason: 'expired' });
  });

  it.each([
    { csrf_token: 10 },
    session({ expires_at: 'tomorrow' }),
    { ...session(), unexpected: 'secret' },
    session({ principal: { issuer: 'https://identity.invalid', subject_id: 'group', kind: 'group' } }),
  ])('rejects noncanonical session metadata', async value => {
    fetcher.mockResolvedValueOnce(token()).mockResolvedValueOnce(json(value));
    await controller.resume();
    expect(controller.snapshot().phase).toBe('unavailable');
  });
});

describe('bounded authentication transport', () => {
  it('recognizes only the bounded exact busy problem, never a bare status or redirect', async () => {
    fetcher.mockResolvedValueOnce(busy());
    await expect(authRequest('/auth/refresh', new AbortController().signal, csrf)).rejects.toMatchObject({ status: 409, busy: true });
    for (const response of [new Response(null, { status: 409 }), new Response(JSON.stringify({ type: 'about:blank', title: 'Conflict', status: 409, secret: 'x' }), { status: 409, headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '1' } })]) {
      fetcher.mockResolvedValueOnce(response);
      await expect(authRequest('/auth/refresh', new AbortController().signal, csrf)).rejects.not.toMatchObject({ busy: true });
    }
  });
  it('rejects oversized decoded bodies even without Content-Length', async () => {
    fetcher.mockResolvedValueOnce(json({ csrf_token: 'a'.repeat(33_000) }));
    await expect(authRequest('/auth/csrf', new AbortController().signal)).rejects.toThrow();
  });
  it('rejects HTML responses rather than treating an SPA fallback as sign-in', async () => {
    fetcher.mockResolvedValueOnce(new Response('<html>not json</html>', { headers: { 'Content-Type': 'text/html' } }));
    await expect(authRequest('/auth/csrf', new AbortController().signal)).rejects.toThrow();
  });
  it('rejects invalid UTF-8 and bodies which arrive after cancellation', async () => {
    fetcher.mockResolvedValueOnce(new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } }));
    await expect(authRequest('/auth/csrf', new AbortController().signal)).rejects.toThrow();
    const stop = new AbortController(); stop.abort();
    fetcher.mockResolvedValueOnce(token());
    await expect(authRequest('/auth/csrf', stop.signal)).rejects.toThrow();
  });
});
