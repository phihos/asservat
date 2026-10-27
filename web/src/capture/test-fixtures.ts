// Synthetic canonical fixtures for unit tests only; never imported by the UI.
import { readFileSync } from 'node:fs';
import type { Session } from '../auth/session';
import type { Input, Output, Operation, Operations } from './http';

export const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const session: Session = { principal: { issuer: 'https://identity.invalid', subject_id: 'synthetic-developer', kind: 'user' }, roles: [], csrf_token: 'C'.repeat(43), expires_at: new Date(Date.now() + 120_000).toISOString(), step_up: 'unavailable' };
export const target = { cluster_id: id(1), namespace: 'payments', kind: 'Deployment' as const, name: 'api' };
const example = (name: string) => JSON.parse(readFileSync(new URL('../../../examples/' + name, import.meta.url), 'utf8'));
export function previewResult(): Output<'preview_capture'> {
  const value = example('mcp-pod-status-preview-result.json');
  value.data.capture_enabled = true; value.data.blockers = []; value.data.warnings = [];
  value.data.expires_at = new Date(Date.now() + 300_000).toISOString();
  value.data.capture_assessment.generatedAt = new Date().toISOString();
  value.data.capture_assessment.validUntil = new Date(Date.now() + 5_000).toISOString();
  return value;
}
export function catalogResult(): Output<'list_diagnostics'> {
  const value = example('mcp-pod-status-diagnostics-result.json');
  value.data.diagnostics[0].available = true; value.data.diagnostics[0].blockers = [];
  return value;
}
export function result<N extends Operation>(data: unknown): Output<N> {
  return { schema_version: 'mcp-result/v1', request_id: id(500), data_class: 'metadata', status: 'ok', data, truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [] } as unknown as Output<N>;
}
export function progressResult(phase: 'Pending' | 'Finalizing' | 'Succeeded' = 'Pending', revision = 1): Output<'get_capture'> {
  return result<'get_capture'>({ capture_id: id(8), revision, phase, actions: [{ action_id: 'pod-status', phase }], navigation_uri: 'https://asservat.example.invalid/captures/' + id(8), can_cancel: false, blockers: [], retry_after_seconds: 5 });
}
export function acceptedResult(): Output<'request_capture'> {
  return result<'request_capture'>({ capture_id: id(8), phase: 'Accepted', navigation_uri: 'https://asservat.example.invalid/captures/' + id(8), operation: 'collect' });
}
export function resolvedClosedResult(): Output<'resolve_capture_request'> {
  return result<'resolve_capture_request'>({ state: 'closed' });
}
export function resolvedAcceptedResult(): Output<'resolve_capture_request'> {
  return result<'resolve_capture_request'>({ state: 'accepted', capture_id: id(8), phase: 'Accepted', navigation_uri: 'https://asservat.example.invalid/captures/' + id(8), operation: 'collect' });
}
export function historyResult(ids: string[] = []): Output<'list_capture_history'> {
  const accepted = new Date(Date.now() - 3_600_000);
  const expires = new Date(accepted.getTime() + 7 * 86_400_000).toISOString();
  return result<'list_capture_history'>({ kind: 'captureHistoryPage', ordering: 'acceptedAtDescCaptureIDDesc', history: ids.map(capture => ({
    capture_id: capture, origin: 'manual', accepted_at: accepted.toISOString(), summary_expires_at: expires, phase: 'Succeeded', action_kinds: ['kubernetesSnapshot'],
    evidence_state: 'available', repeat_state: 'available', settings_expires_at: expires, navigation_uri: 'https://asservat.example.invalid/captures/' + capture, operation: 'collect' })) });
}
export function repeatedPreviewResult(from: string): Output<'preview_capture'> {
  const value = previewResult();
  (value.data as { repeated_from_capture_id?: string }).repeated_from_capture_id = from;
  return value;
}
export class SyntheticOperations implements Operations {
  calls: { name: Operation; input: unknown; signal: AbortSignal; csrf: string }[] = [];
  responder: (name: Operation) => unknown | Promise<unknown> = name => ({ list_diagnostics: catalogResult, preview_capture: previewResult, request_capture: acceptedResult, resolve_capture_request: resolvedClosedResult, get_capture: progressResult, list_capture_history: () => historyResult(), get_capture_settings: () => settingsResult() })[name]();
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), signal, csrf });
    return await this.responder(name) as Output<N>;
  }
}

export function recordingPreviewResult(from?: string): Output<'preview_capture'> {
  const value = example('mcp-composition-preview-result.json');
  const pod = previewResult(); if (pod.status !== 'ok') throw new Error('synthetic pod preview');
  value.data.preview_id = id(173);
  value.data.target_ref = pod.data.target_ref;
  value.data.selected_pods = pod.data.selected_pods;
  value.data.expires_at = new Date(Date.now() + 120_000).toISOString();
  value.data.capture_assessment.generatedAt = new Date().toISOString();
  value.data.capture_assessment.validUntil = new Date(Date.now() + 5_000).toISOString();
  value.data.capture_enabled = false; value.data.approval_required = true;
  value.data.blockers = [{ code: 'ApprovalRequired', message: 'Independent review is required.', responsible_role: 'approver', retryable: false }];
  if (from) value.data.repeated_from_capture_id = from;
  return value;
}
export function approvalPendingResult(): Output<'request_capture'> {
  return { ...result<'request_capture'>({}), status: 'error', data: { code: 'ApprovalRequired', message: 'Independent approval is pending.', retryable: false,
    responsible_role: 'approver', navigation_uri: 'https://asservat.example.invalid/approvals/' + id(41) } } as Output<'request_capture'>;
}

export function settingsResult(capture = id(41)): Output<'get_capture_settings'> {
  return result<'get_capture_settings'>({ kind: 'captureSettings', capture_id: capture, cluster_id: target.cluster_id, namespace_uid: 'namespace-uid', accepted_at: new Date(Date.now() - 60000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(), settings_digest: 'a'.repeat(64), original_execution_digest: 'b'.repeat(64), navigation_uri: 'https://asservat.example.invalid/captures/' + capture, settings: {
    target: { namespace: target.namespace, workloadRef: { apiVersion: 'apps/v1', kind: target.kind, name: target.name, uid: 'workload-uid' }, maxPods: 1, selection: 'allWithinLimit', adoption: 'pinUID' },
    recipe_spec: { actions: [{ id: 'pod-status', kind: 'kubernetesSnapshot', parameters: { include: ['pod'] }, dependsOn: [], required: true, impact: 'observe', limits: { maxBytes: 4096, timeout: '5s' }, executionMode: 'onTrigger' }], maxTotalBytes: 4096, maxDuration: '5s' }, dependency_pins: [{ role: 'recipe', digest: 'c'.repeat(64) }], requested_retention: '120s',
  } });
}
