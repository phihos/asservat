import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { excerpt, id, syscallSummary, syscallEvents } from './test-fixtures';
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('uses fixed same-origin CSRF routes without an idempotency key or replay', async () => {
  const fetcher = vi.fn().mockResolvedValue(json(excerpt())); vi.stubGlobal('fetch', fetcher);
  const input = { case_id: id(2), artifact_id: id(3), line_start: 1, max_lines: 14 };
  await operations.call('get_file_excerpt', input, 'csrf', new AbortController().signal);
  expect(fetcher).toHaveBeenCalledOnce(); expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_file_excerpt');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'X-CSRF-Token': 'csrf' }, body: JSON.stringify(input) });
  expect(fetcher.mock.calls[0][1].headers).not.toHaveProperty('Idempotency-Key');
});
it.each([
  () => new Response('private provider details', { status: 503 }),
  () => new Response(new Uint8Array(65_537), { headers: { 'Content-Type': 'application/json' } }),
  () => json({ ...excerpt(), data: { native_bytes: 'private' } }),
  () => new Response('<html/>', { headers: { 'Content-Type': 'text/html' } }),
])('rejects unavailable, unbounded or unexpected payloads', async response => {
  const fetcher = vi.fn().mockImplementation(async () => response()); vi.stubGlobal('fetch', fetcher);
  await expect(operations.call('get_file_excerpt', { case_id: id(2), artifact_id: id(3) }, 'csrf', new AbortController().signal)).rejects.toThrow('Query unavailable');
  expect(fetcher).toHaveBeenCalledOnce();
});

it.each(['get_syscall_summary', 'get_syscall_events'] as const)('uses the same bounded CSRF transport for %s', async tool => {
  const fetcher = vi.fn().mockResolvedValue(json(tool === 'get_syscall_summary' ? syscallSummary() : syscallEvents())); vi.stubGlobal('fetch', fetcher);
  const input = { case_id: id(2), artifact_id: id(3), limit: 100 };
  await operations.call(tool, input, 'csrf', new AbortController().signal);
  expect(fetcher).toHaveBeenCalledOnce(); expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/' + tool);
  expect(fetcher.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'X-CSRF-Token': 'csrf' }, body: JSON.stringify(input) });
});

it('refuses raw arguments and excessive syscall display filters before issuing HTTP', async () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  for (const extra of [{ include_arguments: true }, { syscall_names: ['write', 'write'] }, { limit: 101 }]) {
    await expect(operations.call('get_syscall_events', { case_id: id(2), artifact_id: id(3), ...extra }, 'csrf', new AbortController().signal)).rejects.toThrow('Query unavailable');
  }
  expect(fetcher).not.toHaveBeenCalled();
});
