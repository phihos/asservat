import { afterEach, expect, it, vi } from 'vitest';
import { processingClient, ProcessingFailure } from './http';
import { validProcessingChange } from '../generated/validate-processing';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const page = () => { const now = Date.now(); return { rootID: id(1), initialized: true, epoch: id(2), sequence: 1, rules: [], observedAt: new Date(now-10).toISOString(), validUntil: new Date(now+4990).toISOString() }; };
const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => vi.unstubAllGlobals());
it('uses same-origin bounded reads and closed lowerCamel change contracts', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(json(page())); vi.stubGlobal('fetch', fetcher); await processingClient.read(new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/processing/rules?limit=50'); expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
  expect(validProcessingChange({ action: 'restrict_processing', ruleID: id(3), expectedRevision: 0, artifactID: id(5) })).toBe(true);
  expect(validProcessingChange({ action: 'release_processing', ruleID: id(3), expectedRevision: 1, scope: { Kind: 'artifact', Location: {} } })).toBe(false);
  expect(validProcessingChange({ action: 'restrict_processing', ruleID: id(3), expectedRevision: 0, artifactID: id(5), scope: { kind: 'artifact', location: { clusterID: id(4), artifactID: id(5), attemptID: id(6) } } })).toBe(false);
});
it.each(['expired', 'renewed', 'extra', 'unordered', 'wrong-state', 'bad-cursor'])('rejects malformed or stale inventory: %s', async mode => {
  const out = page() as ReturnType<typeof page> & Record<string, unknown>;
  if (mode === 'expired') out.validUntil = new Date(Date.now()-1).toISOString(); if (mode === 'renewed') out.validUntil = new Date(Date.now()+6000).toISOString(); if (mode === 'extra') out.secret = 'untrusted';
  const rule = { id: id(3), revision: 1, state: 'restricted', scope: { kind: 'artifact', location: { clusterID: id(4), artifactID: id(5), attemptID: id(6) } }, administrationUntil: '2020-01-01T00:00:00Z', retireBy: '2030-01-01T00:00:00Z' };
  if (mode === 'unordered') Object.assign(out, { rules: [rule, rule] }); if (mode === 'wrong-state') Object.assign(out, { rules: [{ ...rule, revision: 2 }] }); if (mode === 'bad-cursor') out.nextCursor = id(9);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(out))); await expect(processingClient.read(new AbortController().signal)).rejects.toBeInstanceOf(ProcessingFailure);
});
it('sends exact caller key and CSRF and rejects another change receipt', async () => {
  const now = page(), input = { action: 'restrict_processing' as const, ruleID: id(3), expectedRevision: 0 as const, artifactID: id(5) };
  const receipt = { rootID: now.rootID, epoch: now.epoch, sequence: 2, requestID: id(8), ruleID: id(3), operationID: id(9), state: 'restricted', revision: 1, observedAt: now.observedAt, validUntil: now.validUntil };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(receipt)).mockResolvedValueOnce(json({ ...receipt, requestID: id(10) })); vi.stubGlobal('fetch', fetcher);
  await processingClient.change(input, id(8), 'C'.repeat(43), new AbortController().signal); expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', headers: { 'Idempotency-Key': id(8), 'X-CSRF-Token': 'C'.repeat(43) } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual(input); await expect(processingClient.change(input, id(8), 'C'.repeat(43), new AbortController().signal)).rejects.toBeInstanceOf(ProcessingFailure);
});
it('cancels the actual metadata request on scope loss without replay', async () => {
  let downstream!: AbortSignal;
  const fetcher = vi.fn<typeof fetch>().mockImplementation((_url, init) => new Promise((_resolve, reject) => {
    downstream = init!.signal!; downstream.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  }));
  vi.stubGlobal('fetch', fetcher); const scope = new AbortController(); const result = processingClient.read(scope.signal); scope.abort();
  await expect(result).rejects.toMatchObject({ name: 'AbortError' }); expect(downstream.aborted).toBe(true); expect(fetcher).toHaveBeenCalledTimes(1);
});

it('requires the exact artifact and request ID for an erasure acknowledgement without rule fields', async () => {
  const now = page(), input = { action: 'request_early_erasure' as const, artifactID: id(5) };
  const accepted = { rootID: now.rootID, epoch: now.epoch, sequence: 2, requestID: id(8), operationID: id(9),
    state: 'erasureRequested', observedAt: now.observedAt, validUntil: now.validUntil };
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(accepted));
  vi.stubGlobal('fetch', fetcher);
  const scope = new AbortController();
  expect(validProcessingChange({ ...input, ruleID: id(3) })).toBe(false);
  expect(validProcessingChange({ ...input, expectedRevision: 0 })).toBe(false);
  expect(validProcessingChange({ ...input, reason: 'free text' })).toBe(false);
  await expect(processingClient.change(input, id(8), 'C'.repeat(43), scope.signal)).resolves.toEqual(accepted);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/processing/changes');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', headers: { 'Idempotency-Key': id(8), 'X-CSRF-Token': 'C'.repeat(43) } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual(input);
  for (const mismatch of [{ requestID: id(10) }, { revision: 0 }, { ruleID: id(3) }, { state: 'initialized', revision: 0 }]) {
    fetcher.mockResolvedValueOnce(json({ ...accepted, ...mismatch }));
    await expect(processingClient.change(input, id(8), 'C'.repeat(43), scope.signal)).rejects.toMatchObject({ status: 502 });
  }
});
