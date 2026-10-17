export class SessionFailure extends Error {
  constructor(readonly status: number, readonly busy = false) { super('Session request failed'); }
}

// Authentication responses only. Evidence/native downloads have separate bounds.
export async function authRequest(path: '/auth/csrf' | '/auth/refresh' | '/auth/logout', signal: AbortSignal, csrf?: string): Promise<unknown> {
  const timeout = new AbortController();
  const abort = () => timeout.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) timeout.abort();
  const timer = setTimeout(abort, 10_000);
  try {
    const response = await fetch(path, {
      method: path === '/auth/csrf' ? 'GET' : 'POST',
      credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: { Accept: 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      signal: timeout.signal,
    });
    if (!response.ok) {
      // Only this closed authentication problem identifies a competing refresh.
      // A bare 409, generic outage or arbitrary Retry-After cannot trigger retry.
      // On logout this response guarantees rejection before local revocation.
      if (response.status === 409 && response.headers.get('Retry-After') === '1' && response.headers.get('Content-Type')?.split(';')[0].trim() === 'application/problem+json' && response.body) {
        const reader = response.body.getReader();
        const chunks: Uint8Array[] = []; let total = 0;
        try {
          for (;;) {
            const { done, value } = await reader.read(); if (done) break;
            total += value.length;
            if (total > 1024 || timeout.signal.aborted) throw new SessionFailure(response.status);
            chunks.push(value);
          }
        } finally { await reader.cancel(); reader.releaseLock(); }
        if (timeout.signal.aborted) throw new SessionFailure(response.status);
        const bytes = new Uint8Array(total); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        let problem: unknown;
        try { problem = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new SessionFailure(response.status); }
        if (typeof problem === 'object' && problem !== null && !Array.isArray(problem) && Object.keys(problem).length === 3 && 'type' in problem && problem.type === 'about:blank' && 'title' in problem && problem.title === 'Conflict' && 'status' in problem && problem.status === 409) throw new SessionFailure(409, true);
      } else await response.body?.cancel();
      throw new SessionFailure(response.status);
    }
    if (path === '/auth/logout') {
      await response.body?.cancel();
      if (response.status !== 204) throw new SessionFailure(502);
      return undefined;
    }
    if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
      await response.body?.cancel(); throw new SessionFailure(502);
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > 32_768 || timeout.signal.aborted) throw new SessionFailure(502);
        chunks.push(value);
      }
    } finally { await reader.cancel(); reader.releaseLock(); }
    if (timeout.signal.aborted) throw new SessionFailure(503);
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', abort);
  }
}
