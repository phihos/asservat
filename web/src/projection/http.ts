import type { components } from '../generated/projection';
import * as validators from '../generated/validate-projection';

export type Operation = 'get_target_discovery' | 'get_logs' | 'syscall_query' | 'pcap_query' | 'get_file_excerpt' | 'get_pcap_summary' | 'get_profile_summary' | 'compare_profiles' | 'get_syscall_summary' | 'get_syscall_events' | 'get_query_result';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
export type Excerpt = Extract<Output<'get_file_excerpt'>, { status: 'ok' }>['data'];
export type Comparison = Extract<Output<'compare_profiles'>, { status: 'ok' }>['data'];
export type SyscallQueryData = Extract<Output<'syscall_query'>, { status: 'ok' }>['data'];
export type PacketQueryData = Extract<Output<'pcap_query'>, { status: 'ok' }>['data'];
export type PacketSummary = Extract<Output<'get_pcap_summary'>, { status: 'ok' }>['data'];
export type Summary = Extract<Output<'get_profile_summary'>, { status: 'ok' }>['data'];
export type SyscallSummary = Extract<Output<'get_syscall_summary'>, { status: 'ok' }>['data'];
export type SyscallEvents = Extract<Output<'get_syscall_events'>, { status: 'ok' }>['data'];
export interface Operations {
  call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>>;
}

// Generated routes do not confer runtime availability. The server registers
// these operations only when its protected approved-read service is composed.
export const operations: Operations = {
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    if (!validators[`validInput_${name}`](input) || signal.aborted) throw new Error('Query unavailable');
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
        await response.body?.cancel(); throw new Error('Query unavailable');
      }
      const reader = response.body.getReader();
    let complete = false; // cancel only an unfinished read: cancelling a finished stream can abort the request
      let size = 0;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) { complete = true; break; }
          size += value.length;
          if (size > 24_576 || request.signal.aborted) { value.fill(0); throw new Error('Query unavailable'); }
          chunks.push(value);
        }
      } finally { if (!complete) await reader.cancel(); reader.releaseLock(); }
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
