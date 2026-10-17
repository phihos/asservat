import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { caseResult, downloadResult, id } from './test-fixtures';
import { validOutput_get_case, validOutput_get_artifact_download, validInput_prepare_artifact_download } from '../generated/validate-evidence';
afterEach(() => vi.unstubAllGlobals());
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('uses the existing canonical native metadata group and exact request shape', () => {
  expect(validOutput_get_case(caseResult())).toBe(true);
  expect(validInput_prepare_artifact_download({ artifact_id: id(3), idempotency_key: 'original' })).toBe(true);
  for (const extra of [{ destination: '/tmp/file' }, { url: 'https://outside.invalid' }, { native_path: '/proc/1/mem' }]) expect(validInput_prepare_artifact_download({ artifact_id: id(3), idempotency_key: 'original', ...extra })).toBe(false);
  for (const state of ['Preparing', 'Ready', 'Completed', 'Cancelled', 'Interrupted'] as const) expect(validOutput_get_artifact_download(downloadResult(state))).toBe(true);
  const ready = downloadResult(); if (ready.status !== 'ok') throw new Error();
  delete ready.data.sha256; expect(validOutput_get_artifact_download(ready)).toBe(false);
});
it('sends only explicit preparation metadata with original key, CSRF and no automatic replay', async () => {
  const fetcher = vi.fn().mockResolvedValue(json(downloadResult('Preparing'))); vi.stubGlobal('fetch', fetcher);
  const body = { artifact_id: id(3), idempotency_key: 'same-original-key' };
  await operations.call('prepare_artifact_download', body, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/prepare_artifact_download');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'Idempotency-Key': body.idempotency_key, 'X-CSRF-Token': 'C'.repeat(43) }, body: JSON.stringify(body) });
});
it.each([
  () => new Response('private upstream diagnostics', { status: 503 }),
  () => json({ ...caseResult(), data_class: 'raw' }),
  () => json({ ...caseResult(), truncated: true, narrowing_hint: 'more' }),
  () => new Response(new Uint8Array(32769), { headers: { 'Content-Type': 'application/json' } }),
  () => new Response('<html>Sign in</html>', { headers: { 'Content-Type': 'text/html' } }),
])('rejects unavailable, nonmetadata, truncated or oversized details', async response => {
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => response()));
  await expect(operations.call('get_case', { case_id: id(2) }, 'csrf', new AbortController().signal)).rejects.toThrow();
});

it.each(['prepare_artifact_download', 'get_artifact_download', 'cancel_artifact_download'] as const)('accepts terminal-only Completed for %s without weakening native metadata validation', async name => {
  const completed = downloadResult('Completed'); if (completed.status !== 'ok') throw new Error();
  completed.data.expires_at = new Date(Date.now() - 1000).toISOString();
  for (const field of ['filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice'] as const) delete completed.data[field];
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(completed)));
  const input = name === 'prepare_artifact_download' ? { artifact_id: id(3), idempotency_key: 'same-original' } : name === 'cancel_artifact_download' ? { download_id: id(4), idempotency_key: 'same-cancel' } : { download_id: id(4) };
  const out = await operations.call(name, input, 'csrf', new AbortController().signal);
  expect(out).toEqual(completed);
  const partial = structuredClone(completed); partial.data.sha256 = 'a'.repeat(64);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(partial)));
  await expect(operations.call(name, input, 'csrf', new AbortController().signal)).rejects.toThrow();
});
