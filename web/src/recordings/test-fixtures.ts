// Synthetic canonical fixtures for console tests only, never imported by UI.
import { readFileSync, existsSync } from 'node:fs';
import type { Data, Input, Output, Operation, Operations, Recording } from './http';
import { id } from '../capture/test-fixtures';
export const recording = (n = 1): Recording => ({
  recording_handle: `source-${n}`, owner_kind: 'policy', policy_name: 'recorder', policy_uid: 'policy-1', pod_uid: id(70 + n), pod_name: `api-${n}`,
  action_id: 'traffic', kind: 'packetCapture', state: 'Ready', history: 'Unknown', maximum_before: '30s', save_eligible: true, save_via: 'recordingSave', live_projections: [], blockers: [], incident_pod_cap: 1,
});
export const envelope = <N extends Operation>(data: Data<N>, cursor: string | null = null): Output<N> => ({
  schema_version: 'mcp-result/v1', request_id: id(500), data_class: 'metadata', status: 'ok', data,
  truncated: false, next_cursor: cursor, narrowing_hint: null, warnings: [], provenance: [],
}) as unknown as Output<N>;
export function inventoryResult(rows = [recording()], cursor: string | null = null): Output<'list_recordings'> {
  return envelope<'list_recordings'>({ kind: 'recordingPage', recordings: rows, expires_at: new Date(Date.now() + 60_000).toISOString(), capture_enabled: true }, cursor);
}
export function savePreviewResult(rows = [recording()]): Output<'preview_recording_save'> {
  const name = 'mcp-recording-save-preview-result.json';
  const fixture = JSON.parse(readFileSync(existsSync(new URL('../../../examples/implemented/' + name, import.meta.url)) ? new URL('../../../examples/implemented/' + name, import.meta.url) : new URL('../../../examples/' + name, import.meta.url), 'utf8'));
  const data = fixture.data;
  // preview_recording_save still returns the earlier row shape.
  data.selected_recordings = rows.map(({ recording_handle, policy_uid, pod_uid, pod_name, action_id, kind, history, maximum_before, save_eligible, blockers, incident_pod_cap }) => ({ recording_handle, policy_uid, pod_uid, pod_name, action_id, kind, state: 'Ready', history, maximum_before, save_eligible, blockers, incident_pod_cap }));
  data.windows = rows.map(row => ({ recording_handle: row.recording_handle, before: '30s', after: '0s' }));
  data.capture_enabled = true; data.incident_pod_cap = 1;
  data.capture_assessment.generatedAt = new Date().toISOString(); data.capture_assessment.validUntil = new Date(Date.now() + 5_000).toISOString();
  data.capture_assessment.actions = [data.capture_assessment.actions[0]];
  return fixture;
}
export class SyntheticRecordings implements Operations {
  calls: { name: Operation; input: unknown; csrf: string; signal: AbortSignal }[] = [];
  responder: (name: Operation) => unknown | Promise<unknown> = name => name === 'list_recordings' ? inventoryResult() : savePreviewResult();
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), csrf, signal });
    return await this.responder(name) as Output<N>;
  }
}
