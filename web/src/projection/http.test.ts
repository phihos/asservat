import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { excerpt, id } from './test-fixtures';
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
