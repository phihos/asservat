export type BootstrapInput = { displayName: string; region: string; deliveryProfile: string };
export type BootstrapReceipt = {
  bootstrapID: string; clusterID: string; peerID: string; issuerEpoch: string;
  deliveryProfile: string; credentialVersion: number; notBefore: string; notAfter: string;
};
export interface FleetClient { issue(input: BootstrapInput, key: string, csrf: string, signal: AbortSignal): Promise<BootstrapReceipt> }
export class FleetFailure extends Error { constructor(readonly status: number) { super('Cluster bootstrap issuance unavailable'); } }
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const text = (value: string, characters: number, bytes: number) => value.length > 0 && [...value].length <= characters && new TextEncoder().encode(value).length <= bytes && !/\p{Cc}/u.test(value) && new TextDecoder().decode(new TextEncoder().encode(value)) === value;
export const validBootstrapInput = (input: BootstrapInput) => text(input.displayName, 128, 512) && text(input.region, 64, 256) && text(input.deliveryProfile, 64, 64);
function instant(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)$/.test(value)) return false;
  const year = +value.slice(0, 4), month = +value.slice(5, 7), day = +value.slice(8, 10);
  return year >= 2020 && year <= 9999 && month >= 1 && month <= 12 && day >= 1 && day <= new Date(Date.UTC(year, month, 0)).getUTCDate() && +value.slice(11, 13) < 24 && +value.slice(14, 16) < 60 && +value.slice(17, 19) < 60 && Number.isFinite(Date.parse(value));
}
function receipt(value: unknown, profile: string): value is BootstrapReceipt {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const out = value as Record<string, unknown>;
  const keys = ['bootstrapID', 'clusterID', 'peerID', 'issuerEpoch', 'deliveryProfile', 'credentialVersion', 'notBefore', 'notAfter'];
  return Object.keys(out).length === keys.length && keys.every(key => Object.hasOwn(out, key)) &&
    ['bootstrapID', 'clusterID', 'peerID', 'issuerEpoch'].every(key => typeof out[key] === 'string' && uuid.test(out[key] as string)) &&
    out.deliveryProfile === profile && out.credentialVersion === 1 && instant(out.notBefore) && instant(out.notAfter) &&
    Date.parse(out.notAfter) > Date.parse(out.notBefore) && Date.parse(out.notAfter) - Date.parse(out.notBefore) <= 300_000;
}
export const fleetClient: FleetClient = {
  async issue(input, key, csrf, signal) {
    if (!validBootstrapInput(input) || !uuid.test(key) || !/^[A-Za-z0-9_-]{43}$/.test(csrf)) throw new FleetFailure(400);
    const controller = new AbortController(), abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const timer = setTimeout(abort, 30_000);
    try {
      if (controller.signal.aborted) throw new FleetFailure(503);
      const response = await fetch('/api/v1/fleet/cluster-bootstraps', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'Idempotency-Key': key }, body: JSON.stringify(input),
      });
      if (response.status !== 201 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
        await response.body?.cancel(); throw new FleetFailure(response.status === 201 ? 502 : response.status);
      }
      const reader = response.body.getReader(), chunks: Uint8Array[] = [];
      let size = 0, complete = false;
      try {
        for (;;) {
          const { done, value } = await reader.read(); if (done) { complete = true; break; }
          size += value.length;
          if (size > 4096 || controller.signal.aborted) throw new FleetFailure(502);
          chunks.push(value);
        }
      } finally { if (!complete) await reader.cancel(); reader.releaseLock(); }
      if (controller.signal.aborted) throw new FleetFailure(503);
      const body = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
      let value: unknown;
      try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch { throw new FleetFailure(502); }
      if (!receipt(value, input.deliveryProfile)) throw new FleetFailure(502);
      return value;
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
  },
};
