import { afterEach, expect, it, vi } from 'vitest';
import { SyscallQuery } from './syscall-query';
import { SyntheticProjection, session, id, queryHandle } from './test-fixtures';
import { packetPage } from './packet-query.test-fixtures';
const source = { caseID: id(2), artifactID: id(3), version: '7'.repeat(64), grantID: id(4) };
function page(cursor: string | null = null) {
  const p = packetPage(true); p.next_cursor = cursor; p.truncated = cursor !== null; p.narrowing_hint = cursor ? 'Continue with the next recorded events.' : null;
  p.data = { kind: 'syscallQuery', events: [{ identity: { process_ref: 'p', thread_ref: 't', pod_uid: 'pod' }, syscall: 'write', abi: 'x86_64', timestamp: '2026-11-05T09:00:00Z', duration_ns: 0, outcome: 'success', arguments: [{ name: 'fd', value: 'decimal:0', truncated: false }, { name: 'buffer', value: 'base64:', truncated: false }] }], coverage: { dropped_events: null, unmatched_events: 0, unfinished_events: 0, unknown_events: 0, record_count: 2, truncated: null, gaps: ['Acquisition coverage is unknown.'] }, query_observed_at: '2026-11-05T09:00:00Z', query_expires_at: '2026-11-05T09:01:00Z' };
  return p;
}
function pending() { const p = page(); p.status = 'pending'; p.data_class = 'metadata'; p.provenance = []; p.data = { query_handle: queryHandle, retry_after_seconds: 1, query_observed_at: p.data.query_observed_at, query_expires_at: p.data.query_expires_at }; return p; }
function poll(p = page()) { return { ...p, truncated: false, next_cursor: null, narrowing_hint: null, provenance: [], data: { query_handle: queryHandle, tool_name: 'syscall_query', result: p, query_observed_at: p.data.query_observed_at, query_expires_at: p.data.query_expires_at } }; }
afterEach(() => vi.useRealTimers());
it('requires an explicit approved grant before any query and never auto acquires', async () => {
  const client = new SyntheticProjection(), c = new SyscallQuery(client), scope = new AbortController(); c.attach(session, scope.signal, { ...source, grantID: undefined }); await c.run({}); expect(c.snapshot().phase).toBe('approval-required'); expect(client.calls).toHaveLength(0); scope.abort();
});
it('freezes grant/filter/key after an unknown Begin and retries that exact receipt only', async () => {
  const client = new SyntheticProjection(); let count = 0; client.responder = () => { if (count++ === 0) throw Error('lost'); return pending(); };
  const ids = vi.fn().mockReturnValueOnce('original').mockReturnValue('successor'), c = new SyscallQuery(client, () => 0, ids), scope = new AbortController(); c.attach(session, scope.signal, source);
  const selection = { syscall_names: ['write'], limit: 5 }; await c.run(selection); selection.syscall_names[0] = 'openat'; expect(c.snapshot().phase).toBe('uncertain'); await c.run({}); expect(client.calls).toHaveLength(1); await c.retryBegin(); expect(client.calls[1].input).toEqual(client.calls[0].input); expect(ids).toHaveBeenCalledTimes(1); expect(c.snapshot().phase).toBe('pending'); scope.abort();
});
it('uses current response observations but one original expiry/handle for a nested paid poll', async () => {
  vi.useFakeTimers(); let now = 0; const client = new SyntheticProjection(), p = page(); p.data.query_observed_at = '2026-11-05T09:00:01Z'; client.responder = name => name === 'syscall_query' ? pending() : poll(p);
  const c = new SyscallQuery(client, () => now), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({}); await c.check(); expect(client.calls).toHaveLength(1); now = 1000; await vi.advanceTimersByTimeAsync(1000); await c.check(); expect(client.calls[1].input).toEqual({ query_handle: queryHandle }); expect(c.snapshot().phase).toBe('result'); expect(c.snapshot().result?.events[0].arguments[0].value).toBe('decimal:0'); p.data.events[0].arguments[0].value = 'decimal:9'; expect(c.snapshot().result?.events[0].arguments[0].value).toBe('decimal:0'); scope.abort();
});
it('starts the next whole-event page only explicitly with a fresh key and unchanged grant/filter', async () => {
  const client = new SyntheticProjection(), cursor = '1:' + 'a'.repeat(32); let count = 0; client.responder = () => count++ ? page() : page(cursor);
  const ids = vi.fn().mockReturnValueOnce('first').mockReturnValueOnce('second'), c = new SyscallQuery(client, () => 0, ids), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({ syscall_names: ['write'], limit: 1 }); expect(client.calls).toHaveLength(1); expect(c.snapshot().nextCursor).toBe(cursor); await c.nextPage(); expect(client.calls[1].input).toMatchObject({ idempotency_key: 'second', cursor, grant_id: source.grantID, syscall_names: ['write'], limit: 1 }); expect(c.snapshot().phase).toBe('result'); scope.abort();
});
it.each(['source', 'version', 'grant-class', 'handle', 'tool', 'expiry', 'inner-times', 'filter', 'cursor'])('refuses changed %s binding without a successor', async mode => {
  vi.useFakeTimers(); let now = 0; const client = new SyntheticProjection(), p = page(), outer = poll(p);
  if (mode === 'source') p.provenance[0].artifactID = id(99); if (mode === 'version') p.provenance[0].digest = '8'.repeat(64); if (mode === 'grant-class') { p.data_class = 'extract'; outer.data_class = 'extract'; } if (mode === 'handle') outer.data.query_handle = 'other'; if (mode === 'tool') outer.data.tool_name = 'get_syscall_events'; if (mode === 'expiry') { outer.data.query_expires_at = '2026-11-05T09:01:01Z'; p.data.query_expires_at = outer.data.query_expires_at; } if (mode === 'inner-times') p.data.query_observed_at = '2026-11-05T09:00:02Z'; if (mode === 'filter') p.data.events[0].syscall = 'read'; if (mode === 'cursor') { p.next_cursor = '0:bad'; p.truncated = false; }
  client.responder = name => name === 'syscall_query' ? pending() : outer; const c = new SyscallQuery(client, () => now), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({ syscall_names: ['write'] }); now = 1000; await vi.advanceTimersByTimeAsync(1000); await c.check(); expect(c.snapshot().phase).toBe('unavailable'); expect(c.snapshot().result).toBeUndefined(); expect(client.calls).toHaveLength(2); scope.abort();
});
it('clears on immutable source/grant change, aborts the original request and ignores late bytes', async () => {
  const client = new SyntheticProjection(); let finish!: (p: unknown) => void; client.responder = () => new Promise(resolve => { finish = resolve; }); const c = new SyscallQuery(client), scope = new AbortController(); c.attach(session, scope.signal, source); const work = c.run({}); c.attach(session, scope.signal, { ...source, grantID: id(9) }); expect(client.calls[0].signal.aborted).toBe(true); finish(page()); await work; expect(c.snapshot().phase).toBe('idle'); expect(client.calls).toHaveLength(1); scope.abort();
});
it('expires and clears raw values at the original interval without an implicit repeat', async () => {
  vi.useFakeTimers(); let now = 0; const client = new SyntheticProjection(); client.responder = () => page(); const c = new SyscallQuery(client, () => now), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({}); expect(c.snapshot().phase).toBe('result'); now = 60_000; await vi.advanceTimersByTimeAsync(60_000); expect(c.snapshot().phase).toBe('expired'); expect(c.snapshot().result).toBeUndefined(); expect(client.calls).toHaveLength(1); scope.abort();
});
it('treats missing or revoked approval as a bounded remedy without replay or acquisition', async () => {
  const client = new SyntheticProjection(); client.responder = () => ({ ...page(), status: 'error', data_class: 'metadata', provenance: [], data: { code: 'RawApprovalRequired', message: 'Current raw syscall approval is required.', retryable: false } });
  const c = new SyscallQuery(client), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({}); expect(c.snapshot().phase).toBe('approval-required'); expect(c.snapshot().result).toBeUndefined(); expect(client.calls).toHaveLength(1); await c.retryBegin(); expect(client.calls).toHaveLength(1); scope.abort();
});
it('normalizes the finite name set and refuses invalid limits before an HTTP request', async () => {
  const client = new SyntheticProjection(); client.responder = () => page(); const c = new SyscallQuery(client), scope = new AbortController(); c.attach(session, scope.signal, source); await c.run({ limit: 101 }); expect(client.calls).toHaveLength(0); await c.run({ syscall_names: ['write', 'read', 'write'] }); expect(client.calls[0].input).toMatchObject({ syscall_names: ['read', 'write'] }); expect(c.snapshot().phase).toBe('result'); scope.abort();
});
