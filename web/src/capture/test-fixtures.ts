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
  return { schema_version: 'mcp-result/v1', request_id: id(500), data_class: 'metadata', status: 'ok', data, truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [] } as Output<N>;
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
export class SyntheticOperations implements Operations {
  calls: { name: Operation; input: unknown; signal: AbortSignal; csrf: string }[] = [];
  responder: (name: Operation) => unknown | Promise<unknown> = name => ({ list_diagnostics: catalogResult, preview_capture: previewResult, request_capture: acceptedResult, resolve_capture_request: resolvedClosedResult, get_capture: progressResult })[name]();
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string, signal: AbortSignal): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), signal, csrf });
    return await this.responder(name) as Output<N>;
  }
}
