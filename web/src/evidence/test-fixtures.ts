// Synthetic metadata only; these helpers are never imported by product code.
import { readFileSync } from 'node:fs';
import type { Input, Output, Operations, Operation, Download } from './http';
export { session } from '../capture/test-fixtures';
export const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const example = (name: string) => JSON.parse(readFileSync(new URL('../../../examples/' + name, import.meta.url), 'utf8'));
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
export function downloadResult(state: Download['state'] = 'Ready'): Output<'get_artifact_download'> {
  const value = example('download-ready.json');
  value.warnings = [];
  const d = value.data;
  d.artifact_id = id(3); d.download_id = id(4); d.state = state;
  d.filename = 'artifact-3.json'; d.native_format = 'pod-status/v1'; d.size_bytes = 512;
  d.coverage_notice = 'Selected pod-status metadata only; no logs or workload configuration.';
  d.expires_at = new Date(Date.now() + 1_800_000).toISOString();
  d.managed_read_until = new Date(Date.now() + 3_600_000).toISOString();
  d.content_path = `/api/v1/downloads/${id(4)}/content`;
  d.resume_available = ['Ready', 'Streaming', 'Interrupted'].includes(state);
  if (!['Ready', 'Streaming', 'Interrupted'].includes(state)) delete d.content_path;
  if (!['Ready', 'Streaming', 'Interrupted', 'Completed'].includes(state)) for (const key of ['filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice']) delete d[key];
  return value;
}
export class SyntheticEvidence implements Operations {
  calls: { name: Operation; input: unknown; signal: AbortSignal }[] = [];
  responder: (name: Operation) => unknown | Promise<unknown> = name => name === 'get_case' ? caseResult() : downloadResult(name === 'prepare_artifact_download' ? 'Preparing' : name === 'cancel_artifact_download' ? 'Cancelled' : 'Ready');
  async call<N extends Operation>(name: N, input: Input<N>, _csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), signal }); return await this.responder(name) as Output<N>;
  }
}
