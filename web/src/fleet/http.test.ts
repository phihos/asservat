import { afterEach, expect, it, vi } from 'vitest';
import { fleetClient, validBootstrapInput, type BootstrapReceipt } from './http';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const input = { displayName: 'Workload cluster', region: 'eu-test', deliveryProfile: 'regional-installer' };
const receipt = (): BootstrapReceipt => ({ bootstrapID: id(1), clusterID: id(2), peerID: id(3), issuerEpoch: id(4), deliveryProfile: input.deliveryProfile, credentialVersion: 1, notBefore: '2026-11-01T12:00:00Z', notAfter: '2026-11-01T12:05:00Z' });
const json = (value: unknown, status = 201) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
afterEach(() => vi.unstubAllGlobals());
it('sends one exact same-origin CSRF request and preserves original historical deadlines', async () => {
  const fetcher = vi.fn().mockResolvedValue(json(receipt())); vi.stubGlobal('fetch', fetcher);
  expect(await fleetClient.issue(input, id(8), 'C'.repeat(43), new AbortController().signal)).toEqual(receipt());
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]).toMatchObject(['/api/v1/fleet/cluster-bootstraps', { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(8) }, body: JSON.stringify(input) }]);
});
it('rejects expanded, mismatched and invalid receipts without replay', async () => {
  for (const value of [{ ...receipt(), secret: 'must-not-reach-ui' }, { ...receipt(), deliveryProfile: 'another' }, { ...receipt(), credentialVersion: 2 }, { ...receipt(), clusterID: 'invalid' }, { ...receipt(), notAfter: '2026-11-01T12:05:01Z' }, { ...receipt(), notAfter: receipt().notBefore }, { ...receipt(), notBefore: '2026-02-31T12:00:00Z' }]) {
    const fetcher = vi.fn().mockResolvedValue(json(value)); vi.stubGlobal('fetch', fetcher);
    await expect(fleetClient.issue(input, id(8), 'C'.repeat(43), new AbortController().signal)).rejects.toMatchObject({ status: 502 });
    expect(fetcher).toHaveBeenCalledTimes(1);
  }
});
it('preserves refusals and never automatically retries a failure', async () => {
  for (const status of [400, 401, 403, 429, 503]) {
    const fetcher = vi.fn().mockResolvedValue(json({}, status)); vi.stubGlobal('fetch', fetcher);
    await expect(fleetClient.issue(input, id(8), 'C'.repeat(43), new AbortController().signal)).rejects.toMatchObject({ status });
    expect(fetcher).toHaveBeenCalledTimes(1);
  }
});
it('cancels an oversized body and aborts an in-flight request', async () => {
  const cancel = vi.fn(), stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(4097)); }, cancel });
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(stream, { status: 201, headers: { 'Content-Type': 'application/json' } })));
  await expect(fleetClient.issue(input, id(8), 'C'.repeat(43), new AbortController().signal)).rejects.toMatchObject({ status: 502 });
  expect(cancel).toHaveBeenCalledTimes(1);
  let requestSignal!: AbortSignal;
  vi.stubGlobal('fetch', vi.fn((_url, options) => { requestSignal = options.signal; return new Promise<Response>((_resolve, reject) => requestSignal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })); }));
  const scope = new AbortController(), pending = fleetClient.issue(input, id(8), 'C'.repeat(43), scope.signal);
  scope.abort(); await expect(pending).rejects.toThrow(); expect(requestSignal.aborted).toBe(true);
});
it('checks finite Unicode bounds and does not send invalid or already-cancelled inputs', async () => {
  expect(validBootstrapInput({ ...input, displayName: '😀'.repeat(128) })).toBe(true);
  expect(validBootstrapInput({ ...input, displayName: '😀'.repeat(129) })).toBe(false);
  expect(validBootstrapInput({ ...input, region: '\u0080' })).toBe(false);
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  await expect(fleetClient.issue({ ...input, region: '' }, id(8), 'C'.repeat(43), new AbortController().signal)).rejects.toMatchObject({ status: 400 });
  const scope = new AbortController(); scope.abort();
  await expect(fleetClient.issue(input, id(8), 'C'.repeat(43), scope.signal)).rejects.toMatchObject({ status: 503 });
  expect(fetcher).not.toHaveBeenCalled();
});
