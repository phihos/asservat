// Synthetic UI fixtures; never imported by the product bundle.
import type { Input, Output, Operation, Operations } from './http';
import { id } from '../evidence/test-fixtures';
export { session, id } from '../evidence/test-fixtures';
export const queryHandle = 'synthetic-original-query';
const envelope = { schema_version: 'mcp-result/v1', request_id: '00000000-0000-4000-8000-000000000080', data_class: 'metadata', truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [] };
export const timing = { query_observed_at: '2026-10-18T12:00:00Z', query_expires_at: '2026-10-18T12:00:10Z' };
export function excerpt() { return { ...envelope, status: 'ok', data: { logical_path: 'pod-status.txt', line_start: 1, lines: Array.from({ length: 14 }, (_, i) => `synthetic-field-${i}: "value"`), ...timing } }; }
export function pending() { return { ...envelope, status: 'pending', data: { query_handle: queryHandle, retry_after_seconds: 1, ...timing } }; }
export function result() { return { ...envelope, status: 'ok', data: { query_handle: queryHandle, tool_name: 'get_file_excerpt', result: excerpt(), ...timing } }; }
export class SyntheticProjection implements Operations {
  calls: { name: Operation; input: unknown; signal: AbortSignal }[] = [];
  responder: (name: Operation) => unknown | Promise<unknown> = () => excerpt();
  async call<N extends Operation>(name: N, input: Input<N>, _csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), signal });
    return await this.responder(name) as Output<N>;
  }
}

export const profileVersion = '7'.repeat(64);
export function profileSummary() { return { ...envelope, status: 'ok', data_class: 'extract', data: { sample_type: 'cpu', unit: 'nanoseconds', duration_seconds: 10, total: 100, top: [{ function: 'example.work', flat: 25, cumulative: 50, fraction: 0.25 as number | null }], symbol_status: 'partial', ...timing }, provenance: [{ artifactID: '00000000-0000-4000-8000-000000000003', digest: profileVersion }] }; }
export function profileResult() { return { ...envelope, status: 'ok', data_class: 'extract', data: { query_handle: queryHandle, tool_name: 'get_profile_summary', result: profileSummary(), ...timing } }; }

const syscallCoverage = () => ({ record_count: 4, unmatched_events: 1, unfinished_events: 1, unknown_events: 0, dropped_events: null as number | null, truncated: null as boolean | null, gaps: ['Acquisition coverage is unknown.'] });
export function syscallSummary(cursor: string | null = null) { return { ...envelope, status: 'ok', data_class: 'extract', next_cursor: cursor, data: { kind: 'syscallSummary', rows: [{ syscall: 'read', count: 2, errors: 0, paired_count: 0, total_duration_ns: 0 }, { syscall: 'write', count: 2, errors: 1, paired_count: 2, total_duration_ns: 5 }], coverage: syscallCoverage(), ...timing }, provenance: [{ artifactID: id(3), digest: profileVersion }] }; }
export function syscallEvents(cursor: string | null = null) { return { ...envelope, status: 'ok', data_class: 'extract', next_cursor: cursor, data: { kind: 'syscallEvents', events: [{ identity: { process_ref: 'p:10:11@boot@epoch', thread_ref: 't:12:13@boot@epoch', pod_uid: id(4) }, syscall: 'write', abi: 'x86_64', timestamp: '2026-10-18T11:59:00Z', outcome: 'error', errno: 'ENOENT', duration_ns: 5 }], coverage: syscallCoverage(), ...timing }, provenance: [{ artifactID: id(3), digest: profileVersion }] }; }
export function syscallResult(view: 'summary' | 'events') { return { ...envelope, status: 'ok', data_class: 'extract', data: { query_handle: queryHandle, tool_name: view === 'summary' ? 'get_syscall_summary' : 'get_syscall_events', result: view === 'summary' ? syscallSummary() : syscallEvents(), ...timing } }; }
