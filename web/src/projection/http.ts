import type { components } from '../generated/projection';
import * as validators from '../generated/validate-projection';

export type Operation = 'get_file_excerpt' | 'get_query_result';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Excerpt = Extract<Output<'get_file_excerpt'>, { status: 'ok' }>['data'];
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// Generated routes do not advertise runtime availability. A protected runtime
// composition must supply the optional view before these operations are offered.
export const operations: Operations = {
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    if (!validators[`validInput_${name}`](input) || signal.aborted) throw new Error('Query unavailable');
    const request = new AbortController();
    const abort = () => request.abort();
    signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 5_000);
    const chunks: Uint8Array[] = [];
    try {
      const response = await fetch('/api/v1/operations/' + name, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify(input), signal: request.signal,
      });
      if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' || !response.body) {
        await response.body?.cancel(); throw new Error('Query unavailable');
      }
      const reader = response.body.getReader();
      let size = 0;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 65_536 || request.signal.aborted) { value.fill(0); throw new Error('Query unavailable'); }
          chunks.push(value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      if (request.signal.aborted) throw new Error('Query unavailable');
      const body = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
      let result: unknown;
      try { result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); }
      finally { body.fill(0); for (const chunk of chunks) chunk.fill(0); }
      if (!validators[`validOutput_${name}`](result)) throw new Error('Query unavailable');
      return result as Output<N>;
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); for (const chunk of chunks) chunk.fill(0); }
  },
};
