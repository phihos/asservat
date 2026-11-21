// Synthetic canonical fixtures for console tests only, never imported by UI.
import { readFileSync } from 'node:fs';
import type { Data, Input, Output, Operation, Operations, Recording, SavePreview } from './http';
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
// The generic preview_capture answer to recording_handles (one policy action).
export function savePreviewResult(rows = [recording()]): Extract<Output<'preview_capture'>, { status: 'ok' }> & { data: SavePreview } {
  const read = (name: string) => JSON.parse(readFileSync(new URL('../../../examples/' + name, import.meta.url), 'utf8'));
  const fixture = read('mcp-composition-preview-result.json');
  const typed = read('mcp-recording-save-preview-result.json').data;
  const data = fixture.data;
  delete data.profile_composition;
  fixture.data_class = 'metadata';
  data.pod_count = new Set(rows.map(row => row.pod_uid)).size;
  data.capture_enabled = true; data.approval_required = false; data.blockers = [];
  data.warnings = rows.map(row => `Saves the last 30s of recording ${row.action_id} on pod ${row.pod_name}. It starts no recorder and runs none of the policy's other actions.`);
  data.lifecycle_plan = { schemaVersion: 'action-lifecycle/v1', requestKind: 'DebugPolicy', actions: [...new Set(rows.map(row => row.action_id))].map(actionID => ({ actionID, kind: 'packetCapture', executionMode: 'ongoing', activation: 'policyArming', requestedBefore: '30s', after: '0s' })), ongoingPodScope: 'none' };
  data.capture_assessment = typed.capture_assessment;
  data.execution_digest = data.capture_assessment.planDigest;
  data.capture_assessment.generatedAt = new Date().toISOString();
  data.capture_assessment.actions = rows.map(row => ({ ...structuredClone(data.capture_assessment.actions[0]), actionID: row.action_id, recording_handle: row.recording_handle }));
  for (const action of data.capture_assessment.actions) action.retention.anchorRule = 'submissionPreparation';
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
