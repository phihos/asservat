// Synthetic metadata only; these helpers are never imported by product code.
import { existsSync, readFileSync } from 'node:fs';
import type { Input, Output, Operations, Operation } from './http';
export { session } from '../capture/test-fixtures';
export const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const example = (name: string) => JSON.parse(readFileSync(existsSync(new URL('../../../examples/implemented/' + name, import.meta.url)) ? new URL('../../../examples/implemented/' + name, import.meta.url) : new URL('../../../examples/' + name, import.meta.url), 'utf8'));
export function caseResult(): Output<'get_case'> {
  const value = example('mcp-shared-case-notice-result.json');
  value.data.case.access = 'ordinary';
  const a = value.data.artifacts[0];
  a.kind = 'context'; a.data_class = 'metadata';
  a.expires_at = a.handling_notice.expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  a.handling_notice.deleteBy = new Date(Date.now() + 3_900_000).toISOString();
  a.handling_notice.asOf = new Date().toISOString();
  return value;
}
export function downloadResult(): Output<'download_artifact'> {
  const value = example('download-ready.json');
  value.warnings = [];
  const d = value.data;
  d.artifact_id = id(3); d.download_id = id(4); d.representation = 'file';
  d.filename = 'artifact-3.json'; d.native_format = 'pod-status/v1'; d.size_bytes = 512;
  d.coverage_notice = 'Selected pod-status metadata only; no logs or workload configuration.';
  d.access_until = new Date(Date.now() + 1_800_000).toISOString();
  d.content_path = `/api/v1/downloads/${id(4)}/content`; d.browser_url = `/downloads/${id(4)}`;
  return value;
}
export const failure = (code: string, message = 'Synthetic failure.', retryable = false) => ({ schema_version: 'mcp-result/v1', request_id: id(9), data_class: 'metadata', status: 'error', data: { code, message, retryable }, truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [] }) as Output<'download_artifact'>;
export function preparing(): Output<'download_artifact'> {
  const value = downloadResult(); const d = value.data as Record<string, unknown>;
  for (const key of ['filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice', 'content_path', 'browser_url']) delete d[key];
  d.state = 'Preparing'; d.revision = 1;
  return value;
}
export function completed(): Output<'download_artifact'> {
  const value = downloadResult(); const d = value.data as Record<string, unknown>;
  for (const key of ['filename', 'native_format', 'etag', 'coverage_notice', 'content_path', 'browser_url']) delete d[key];
  d.state = 'Completed'; d.revision = 15;
  return value;
}
export const cancelled = () => ({ ...downloadResult(), data: { download_id: id(4), state: 'Cancelled' } }) as Output<'download_artifact'>;
export class SyntheticEvidence implements Operations {
  calls: { name: Operation; input: unknown; signal: AbortSignal }[] = [];
  responder: (name: Operation, input: unknown) => unknown | Promise<unknown> = (name, input) => name === 'get_case' ? caseResult() : (input as { action: string }).action === 'cancel' ? cancelled() : downloadResult();
  async call<N extends Operation>(name: N, input: Input<N>, _csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), signal }); return await this.responder(name, input) as Output<N>;
  }
}
