import type { components } from '../generated/live';
import * as validators from '../generated/validate-live';

export type Operation = 'list_live_sources' | 'open_live_watch' | 'read_live_watch' | 'update_live_watch' | 'close_live_watch';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Source = Extract<Output<'list_live_sources'>, {status:'ok'}>['data']['sources'][number];
export type Watch = Extract<Output<'open_live_watch'>, {status:'ok'}>['data'];
export type Batch = Extract<Output<'read_live_watch'>, {status:'ok'}>['data'];
export type Row = Batch['rows'][number];
export type Filter = NonNullable<Input<'open_live_watch'>['display_filter']>;
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// Generated contracts do not confer availability. Registration requires the
// protected live source/control/delivery composition; there is no synthetic fallback.
export const operations: Operations = {
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    if (!validators[`validInput_${name}`](input) || signal.aborted) throw new Error('Live view unavailable');
    const request = new AbortController();
    const abort = () => request.abort();
    signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 20_000);
    const chunks: Uint8Array[] = [];
    try {
      const response = await fetch('/api/v1/operations/' + name, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify(input), signal: request.signal,
      });
      if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
        await response.body?.cancel(); throw new Error('Live view unavailable');
      }
      const reader = response.body.getReader();
    let complete = false; // cancel only an unfinished read: cancelling a finished stream can abort the request
      let size = 0;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) { complete = true; break; }
          size += value.length;
          if (size > 24_576 || request.signal.aborted) { value.fill(0); throw new Error('Live view unavailable'); }
          chunks.push(value);
        }
      } finally { if (!complete) await reader.cancel(); reader.releaseLock(); }
      if (request.signal.aborted) throw new Error('Live view unavailable');
      const body = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
      let result: unknown;
      try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); }
      finally { body.fill(0); for (const chunk of chunks) chunk.fill(0); }
      if (!validators[`validOutput_${name}`](result)) throw new Error('Live view unavailable');
      return result as Output<N>;
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); for (const chunk of chunks) chunk.fill(0); }
  },
};
