import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { caseResult, downloadResult, failure, id } from './test-fixtures';
import { validOutput_get_case, validOutput_download_artifact, validInput_download_artifact } from '../generated/validate-evidence';
afterEach(() => vi.unstubAllGlobals());
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('uses the canonical download status and exact request shapes', () => {
  expect(validOutput_get_case(caseResult())).toBe(true);
  expect(validInput_download_artifact({ action: 'prepare', artifact_id: id(3), idempotency_key: 'original' })).toBe(true);
  expect(validInput_download_artifact({ action: 'status', download_id: id(4), after_revision: 2 })).toBe(true);
  expect(validInput_download_artifact({ action: 'status', artifact_id: id(3), idempotency_key: 'original' })).toBe(false);
  for (const extra of [{ destination: '/tmp/file' }, { url: 'https://outside.invalid' }, { native_path: '/proc/1/mem' }]) expect(validInput_download_artifact({ action: 'prepare', artifact_id: id(3), idempotency_key: 'original', ...extra })).toBe(false);
  expect(validOutput_download_artifact(downloadResult())).toBe(true);
  expect(validOutput_download_artifact(failure('CapabilityUnavailable'))).toBe(true);
  const ready = downloadResult(); if (ready.status !== 'ok') throw new Error();
  delete (ready.data as { sha256?: string }).sha256; expect(validOutput_download_artifact(ready)).toBe(false);
});
it('sends prepare with its key as Idempotency-Key and status without one', async () => {
  const fetcher = vi.fn().mockImplementation(async () => json(downloadResult())); vi.stubGlobal('fetch', fetcher);
  const body = { action: 'prepare' as const, artifact_id: id(3), idempotency_key: 'same-original-key' };
  await operations.call('download_artifact', body, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/download_artifact');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: { 'Idempotency-Key': body.idempotency_key, 'X-CSRF-Token': 'C'.repeat(43) }, body: JSON.stringify(body) });
  await operations.call('download_artifact', { action: 'status', download_id: id(4) }, 'csrf', new AbortController().signal);
  expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBeUndefined();
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

it('lets a status read with after_revision outlast the server wait while other reads stop at 10 s', async () => {
  vi.useFakeTimers();
  try {
    const signals: AbortSignal[] = [];
    vi.stubGlobal('fetch', vi.fn((_url: RequestInfo | URL, init?: RequestInit) => { signals.push(init!.signal!); return new Promise(() => {}); }));
    void operations.call('download_artifact', { action: 'status', download_id: id(4), after_revision: 2 }, 'csrf', new AbortController().signal).catch(() => undefined);
    void operations.call('download_artifact', { action: 'status', download_id: id(4) }, 'csrf', new AbortController().signal).catch(() => undefined);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(signals[0].aborted).toBe(false); expect(signals[1].aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(31_000);
    expect(signals[0].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(4_000);
    expect(signals[0].aborted).toBe(true);
  } finally { vi.useRealTimers(); }
});
