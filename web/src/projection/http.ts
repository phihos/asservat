import type { components } from '../generated/projection';
import * as validators from '../generated/validate-projection';

export type Operation = 'get_extract' | 'query_artifact' | 'compare_profiles' | 'get_query_result';
export type Input<N extends Operation> = components['schemas'][`McpInput_${N}`];
export type Output<N extends Operation> = components['schemas'][`McpOutput_${N}`];
type Ok<N extends Operation> = Extract<Output<N>, { status: 'ok' }>;
type Page<N extends Operation, D> = Exclude<Output<N>, Ok<N>> | (Omit<Ok<N>, 'status' | 'data'> & { status: 'ok'; data: D });
type ExtractData = Ok<'get_extract'>['data'];
type QueryData = Ok<'query_artifact'>['data'];
export type Excerpt = Extract<ExtractData, { logical_path: string }>;
export type Summary = Extract<ExtractData, { top: unknown }>;
export type PacketSummary = Extract<ExtractData, { conversations: unknown }>;
export type SyscallSummary = Extract<ExtractData, { kind: 'syscallSummary' }>;
export type SyscallEvents = Extract<ExtractData, { kind: 'syscallEvents' }>;
export type LogQueryData = Extract<ExtractData, { kind: 'logs' }>;
export type SyscallQueryData = Extract<QueryData, { kind: 'syscallQuery' }>;
export type PacketQueryData = Extract<QueryData, { scanned_bytes: number }>;
export type Comparison = Ok<'compare_profiles'>['data'];
type Views = { fileExcerpt: Excerpt; profileSummary: Summary; pcapSummary: PacketSummary; syscallSummary: SyscallSummary; syscallEvents: SyscallEvents; logs: LogQueryData };
type Queries = { packets: PacketQueryData; syscalls: SyscallQueryData };
const viewTests: { [V in keyof Views]: (data: Record<string, unknown>) => boolean } = {
  fileExcerpt: d => 'logical_path' in d, profileSummary: d => 'top' in d, pcapSummary: d => 'conversations' in d,
  syscallSummary: d => d.kind === 'syscallSummary', syscallEvents: d => d.kind === 'syscallEvents', logs: d => d.kind === 'logs',
};
// The canonical get_extract and query_artifact outputs are unions over every
// view; these guards also require the data shape of the requested view.
export function validExtract<V extends keyof Views>(view: V, value: unknown): value is Page<'get_extract', Views[V]> {
  return validators.validOutput_get_extract(value) && (value.status !== 'ok' || viewTests[view](value.data as Record<string, unknown>));
}
export function validQuery<Q extends keyof Queries>(operation: Q, value: unknown): value is Page<'query_artifact', Queries[Q]> {
  return validators.validOutput_query_artifact(value) && (value.status !== 'ok' || (operation === 'packets') === ('scanned_bytes' in value.data));
}
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
