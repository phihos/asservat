import type { components } from '../generated/processing';
import { validProcessingChange, validProcessingInventory, validProcessingReceipt } from '../generated/validate-processing';

export type Inventory = components['schemas']['ProcessingInventory'];
export type Rule = Inventory['rules'][number];
export type Change = components['schemas']['ProcessingChange'];
export type Receipt = components['schemas']['ProcessingReceipt'];
export class ProcessingFailure extends Error {
  constructor(readonly status: number) { super('Processing request unavailable'); }
}
export interface ProcessingClient {
  read(signal: AbortSignal, after?: string): Promise<Inventory>;
  change(input: Change, key: string, csrf: string, signal: AbortSignal): Promise<Receipt>;
}
export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const current = (value: { observedAt: string; validUntil: string }) => {
  const now = Date.now(), observed = Date.parse(value.observedAt), until = Date.parse(value.validUntil);
  return observed <= now && now < until && until - observed <= 5000;
};
function validInventory(value: unknown, after?: string): value is Inventory {
  if (!validProcessingInventory(value) || !current(value)) return false;
  let last = after ?? '';
  for (const rule of value.rules) {
    if (rule.id <= last || Date.parse(rule.retireBy) <= Date.parse(rule.administrationUntil) ||
      (rule.state === 'reserved' ? rule.revision !== 0 : rule.revision < 1 || rule.revision % 2 !== (rule.state === 'restricted' ? 1 : 0)) ||
      (rule.scope.kind === 'workloadInterval' && Date.parse(rule.scope.acquiredUntil) <= Date.parse(rule.scope.acquiredFrom))) return false;
    last = rule.id;
  }
  return !value.nextCursor || value.rules.length === 50 && value.nextCursor === last;
}
// Fixed same-origin metadata routes, finite reads, no redirects or automatic replay.
async function request(path: string, signal: AbortSignal, input?: Change, key?: string, csrf?: string): Promise<unknown> {
  const controller = new AbortController(), abort = () => controller.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  const timer = setTimeout(abort, 10_000);
  try {
    const response = await fetch(path, {
      method: input ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal,
      headers: input ? { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf!, 'Idempotency-Key': key! } : { Accept: 'application/json' },
      ...(input ? { body: JSON.stringify(input) } : {}),
    });
    if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
      await response.body?.cancel(); throw new ProcessingFailure(response.status === 200 ? 502 : response.status);
    }
    const reader = response.body.getReader(), parts: Uint8Array[] = [];
    let size = 0, complete = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) { complete = true; break; }
        size += value.length;
        if (size > (input ? 4096 : 128 * 1024) || controller.signal.aborted) throw new ProcessingFailure(502);
        parts.push(value);
      }
    } finally { if (!complete) await reader.cancel(); reader.releaseLock(); }
    if (controller.signal.aborted) throw new ProcessingFailure(503);
    const body = new Uint8Array(size); let offset = 0;
    for (const part of parts) { body.set(part, offset); offset += part.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
}
export const processingClient: ProcessingClient = {
  async read(signal, after) {
    if (after && !uuid.test(after)) throw new ProcessingFailure(400);
    const out = await request('/api/v1/processing/rules?limit=50' + (after ? '&after=' + encodeURIComponent(after) : ''), signal);
    if (!validInventory(out, after)) throw new ProcessingFailure(502);
    return out;
  },
  async change(input, key, csrf, signal) {
    if (!uuid.test(key) || !validProcessingChange(input)) throw new ProcessingFailure(400);
    const out = await request('/api/v1/processing/changes', signal, input, key, csrf);
    const state = input.action === 'initialize_processing' ? 'initialized' : input.action === 'restrict_processing' ? 'restricted' : 'released';
    if (!validProcessingReceipt(out) || !current(out) || out.requestID !== key || out.state !== state ||
      (input.action === 'initialize_processing' ? !!out.ruleID || out.revision !== 0 : out.ruleID !== input.ruleID || out.revision !== input.expectedRevision + 1)) throw new ProcessingFailure(502);
    return out;
  },
};
