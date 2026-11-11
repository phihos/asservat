import { afterEach, expect, it, vi } from 'vitest';
import { processingReportClient, type ProcessingReportResponse } from './report-http';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const selection = '2026-11-01T00:00:00Z', digest = 'a'.repeat(64);
const query = { section: 'artifacts' as const, limit: 3, created_before: selection, policy_digest: digest };
function reply(): ProcessingReportResponse {
  const now = Date.now();
  return { schema_version: 'mcp-result/v1', request_id: id(1), status: 'ok', data_class: 'metadata',
    truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [], data: {
      schema_version: 'processing-report/v1', root_id: id(2), installation_id: id(3), section: 'artifacts',
      selection_created_before: selection, policy_revision: { uid: id(4), generation: 1, digest }, records: [],
      observed_at: new Date(now-10).toISOString(), valid_until: new Date(now+4990).toISOString(),
      next: { ...query, section: 'shares' }, processor_declarations: 'unsupplied', coverage: ['retained metadata observations', 'unknown client receipt', 'legal exceptions disabled', 'recorded lineage'],
    } };
}
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => vi.unstubAllGlobals());

it('posts only on demand with session CSRF, exact selection/cursor and caller cancellation', async () => {
  const value = reply(); value.data.next = { ...query, section: 'shares' };
  const cursorQuery = { ...query, after: { id: id(5), cluster_id: id(6), attempt_id: id(7) } };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(value)); vi.stubGlobal('fetch', fetcher);
  expect(fetcher).not.toHaveBeenCalled();
  await expect(processingReportClient.read(cursorQuery, 'C'.repeat(43), new AbortController().signal)).resolves.toEqual(value);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_processing_report');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'X-CSRF-Token': 'C'.repeat(43) } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual(cursorQuery);
});

it.each(['extra', 'wrong-section', 'mixed-record', 'expired', 'future', 'renewed', 'wrong-selection', 'wrong-policy', 'next-selection', 'next-policy', 'skip-section', 'missing-next', 'empty-cursor', 'truncated', 'outer-cursor'])('rejects malformed or mismatched report pages: %s', async mode => {
  const value = reply();
  if (mode === 'extra') Object.assign(value.data, { token: 'untrusted' });
  if (mode === 'wrong-section') value.data.section = 'shares';
  if (mode === 'mixed-record') Object.assign(value.data, { records: [{ visible_until: selection, artifact: {}, share: {} }] });
  if (mode === 'expired') value.data.valid_until = new Date(Date.now()-1).toISOString();
  if (mode === 'future') value.data.observed_at = new Date(Date.now()+1000).toISOString();
  if (mode === 'renewed') value.data.valid_until = new Date(Date.now()+6000).toISOString();
  if (mode === 'wrong-selection') value.data.selection_created_before = '2026-11-02T00:00:00Z';
  if (mode === 'wrong-policy') value.data.policy_revision.digest = 'b'.repeat(64);
  if (mode.startsWith('next-') || mode === 'skip-section') value.data.next = { ...query, section: 'shares' };
  if (mode === 'next-selection') value.data.next!.created_before = '2026-11-02T00:00:00Z';
  if (mode === 'next-policy') value.data.next!.policy_digest = 'b'.repeat(64);
  if (mode === 'skip-section') value.data.next!.section = 'operations';
  if (mode === 'missing-next') delete value.data.next;
  if (mode === 'empty-cursor') value.data.next = { ...query, after: { id: id(5), cluster_id: id(6), attempt_id: id(7) } };
  if (mode === 'truncated') value.truncated = true;
  if (mode === 'outer-cursor') Object.assign(value, { next_cursor: 'untrusted-cursor' });
  const fetcher = vi.fn().mockResolvedValue(json(value)); vi.stubGlobal('fetch', fetcher);
  await expect(processingReportClient.read(query, 'csrf', new AbortController().signal)).rejects.toMatchObject({ status: 502 });
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('rejects an invalid continuation before issuing a request', async () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  await expect(processingReportClient.read({ section: 'artifacts', limit: 3, after: { id: id(5), cluster_id: id(6), attempt_id: id(7) } }, 'csrf', new AbortController().signal)).rejects.toMatchObject({ status: 400 });
  expect(fetcher).not.toHaveBeenCalled();
});

it('cancels a partially consumed response body and never replays it', async () => {
  let downstream!: AbortSignal;
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => {
    downstream = init!.signal!;
    return new Response(new ReadableStream({ start(controller) {
      controller.enqueue(new TextEncoder().encode('{"schema_version":'));
      downstream.addEventListener('abort', () => controller.error(new DOMException('Aborted', 'AbortError')), { once: true });
    } }), { headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetcher); const scope = new AbortController();
  const result = processingReportClient.read({ section: 'artifacts', limit: 3 }, 'csrf', scope.signal);
  // Allow the real stream reader to await the remainder of this response.
  await Promise.resolve(); await Promise.resolve(); scope.abort();
  await expect(result).rejects.toMatchObject({ name: 'AbortError' });
  expect(downstream.aborted).toBe(true); expect(fetcher).toHaveBeenCalledTimes(1);
});

it('refuses oversized pages and HTTP failures without replay', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(json({ ...reply(), padding: 'x'.repeat(32_768) }))
    .mockResolvedValueOnce(new Response('private provider failure', { status: 503 })); vi.stubGlobal('fetch', fetcher);
  await expect(processingReportClient.read({ section: 'artifacts', limit: 3 }, 'csrf', new AbortController().signal)).rejects.toMatchObject({ status: 502 });
  await expect(processingReportClient.read({ section: 'artifacts', limit: 3 }, 'csrf', new AbortController().signal)).rejects.toMatchObject({ status: 503 });
  expect(fetcher).toHaveBeenCalledTimes(2);
});
