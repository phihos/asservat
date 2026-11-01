// Run in native ESM, independently of Vitest's module transformation. A helper
// that works only in the test runner must fail qualification before packaging.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validCSRF, validSession } from '../src/generated/validate-auth.js';
import * as capture from '../src/generated/validate-capture.js';
import * as projection from '../src/generated/validate-projection.js';
import * as policy from '../src/generated/validate-policy.js';
import * as sharing from '../src/generated/validate-sharing.js';

assert.equal(validCSRF({ csrf_token: 'C'.repeat(43) }), true);
assert.equal(validCSRF({ csrf_token: '😀'.repeat(257) }), false);
const session = {
  principal: { issuer: 'https://identity.invalid', subject_id: 'synthetic-developer', kind: 'user' },
  roles: [], csrf_token: 'C'.repeat(43), expires_at: '2026-10-11T12:00:00Z', step_up: 'unavailable',
};
assert.equal(validSession(session), true);
assert.equal(validSession({ ...session, expires_at: 'not-a-date' }), false);
assert.equal(validSession({ ...session, extra: 'unexpected' }), false);
for (const [file, validator] of [
  ['mcp-pod-status-diagnostics-input', 'validInput_list_diagnostics'],
  ['mcp-pod-status-diagnostics-result', 'validOutput_list_diagnostics'],
  ['mcp-pod-status-preview-input', 'validInput_preview_capture'],
  ['mcp-pod-status-preview-result', 'validOutput_preview_capture'],
  ['mcp-resolve-capture-input', 'validInput_resolve_capture_request'],
  ['mcp-resolve-capture-accepted', 'validOutput_resolve_capture_request'],
  ['mcp-resolve-capture-closed', 'validOutput_resolve_capture_request'],
]) {
  const value = JSON.parse(await readFile(new URL('../../examples/' + file + '.json', import.meta.url), 'utf8'));
  assert.equal(capture[validator](value), true, file);
  assert.equal(capture[validator]({ ...value, extra: 'unexpected' }), false, file + ' rejects extra field');
}
const id = '00000000-0000-4000-8000-000000000008';
const podStatus = JSON.parse(await readFile(new URL('../../examples/mcp-pod-status-preview-result.json', import.meta.url), 'utf8'));
for (const anchorRule of ['firstAcquisitionOrEarlierSource', 'uploadCompletion', 'previewCreation']) {
  const wrong = structuredClone(podStatus);
  wrong.data.capture_assessment.actions[0].retention.anchorRule = anchorRule;
  assert.equal(capture.validOutput_preview_capture(wrong), false, 'pod-status rejects ' + anchorRule);
}
const otherMechanism = JSON.parse(await readFile(new URL('../../examples/mcp-preview-result.json', import.meta.url), 'utf8'));
assert.equal(capture.validOutput_preview_capture(otherMechanism), true, 'manual previews retain their submission-preparation anchor');
const wrongRecorder = structuredClone(otherMechanism);
wrongRecorder.data.capture_assessment.actions[0].retention.anchorRule = 'firstAcquisitionOrEarlierSource';
assert.equal(capture.validOutput_preview_capture(wrongRecorder), false, 'manual recorder preview refuses source-snapshot timing');
assert.equal(capture.validInput_request_capture({ preview_id: id, idempotency_key: id }), true);
assert.equal(capture.validInput_request_capture({ preview_id: 'invalid', idempotency_key: id }), false);
assert.equal(capture.validInput_get_capture({ capture_id: id }), true);
const result = data => ({ schema_version: 'mcp-result/v1', request_id: id, data_class: 'metadata', status: 'ok', data, truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [] });
assert.equal(capture.validOutput_request_capture(result({ capture_id: id, phase: 'Accepted', navigation_uri: 'https://asservat.example.invalid/captures/' + id, operation: 'collect' })), true);
assert.equal(capture.validOutput_get_capture(result({ capture_id: id, revision: 1, phase: 'Finalizing', actions: [{ action_id: 'pod-status', phase: 'Finalizing' }], navigation_uri: 'https://asservat.example.invalid/captures/' + id, can_cancel: false, blockers: [], retry_after_seconds: 5 })), true);
for (const data of [{ state: 'closed', capture_id: id }, { state: 'accepted' }, { state: 'pending' }, { state: 'closed', target_ref: {} }]) assert.equal(capture.validOutput_resolve_capture_request(result(data)), false, 'reject mixed/unknown/incomplete disposition');
assert.equal(capture.validOutput_resolve_capture_request({ ...result({state:'closed'}), warnings:['private target'] }), false, 'closed carries no warning metadata');
console.log('Native ESM auth and all five capture operation validators passed positive and negative checks.');

const evidence = await import('../src/generated/validate-evidence.js');
for (const [file, validator] of [
  ['mcp-shared-case-notice-result', 'validOutput_get_case'],
  ['download-prepare', 'validInput_prepare_artifact_download'],
  ['download-get', 'validInput_get_artifact_download'],
  ['download-cancel', 'validInput_cancel_artifact_download'],
  ['download-ready', 'validOutput_prepare_artifact_download'],
  ['download-ready', 'validOutput_get_artifact_download'],
  ['download-cancelled', 'validOutput_cancel_artifact_download'],
]) {
  const value = JSON.parse(await readFile(new URL('../../examples/' + file + '.json', import.meta.url), 'utf8'));
  assert.equal(evidence[validator](value), true, file);
  assert.equal(evidence[validator]({ ...value, extra: 'unexpected' }), false, file + ' rejects extra field');
}
const ready = JSON.parse(await readFile(new URL('../../examples/download-ready.json', import.meta.url), 'utf8'));
delete ready.data.sha256;
assert.equal(evidence.validOutput_get_artifact_download(ready), false, 'native metadata is an indivisible group');
console.log('Native ESM case and download validators passed positive and negative checks.');

const nativeFields = ['filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice'];
const completed = JSON.parse(await readFile(new URL('../../examples/download-ready.json', import.meta.url), 'utf8'));
completed.data.state = 'Completed'; completed.data.resume_available = false;
completed.data.expires_at = '2000-01-01T00:00:00Z';
delete completed.data.content_path;
for (const field of nativeFields) delete completed.data[field];
const full = JSON.parse(await readFile(new URL('../../examples/download-ready.json', import.meta.url), 'utf8'));
for (const name of ['prepare_artifact_download', 'get_artifact_download', 'cancel_artifact_download']) {
  const validate = evidence['validOutput_' + name];
  assert.equal(validate(completed), true, name + ' accepts terminal-only Completed after transfer expiry');
  for (const field of nativeFields) {
    const partial = structuredClone(completed); partial.data[field] = full.data[field];
    assert.equal(validate(partial), false, name + ' rejects isolated native field ' + field);
  }
  const verified = structuredClone(completed);
  for (const field of nativeFields) verified.data[field] = full.data[field];
  assert.equal(validate(verified), true, name + ' retains complete verified metadata');
  for (const field of nativeFields) {
    const partial = structuredClone(verified); delete partial.data[field];
    assert.equal(validate(partial), false, name + ' rejects missing native field ' + field);
  }
  for (const [field, value] of [['sha256', 'not-verified'], ['content_path', full.data.content_path], ['resume_available', true]]) {
    const invalid = structuredClone(verified); invalid.data[field] = value;
    assert.equal(validate(invalid), false, name + ' rejects terminal ' + field);
  }
  for (const state of ['Ready', 'Streaming', 'Interrupted']) {
    const absent = structuredClone(completed); absent.data.state = state; absent.data.content_path = full.data.content_path;
    assert.equal(validate(absent), false, name + ' still requires verified metadata for ' + state);
  }
}
console.log('Native ESM download terminal-only status and complete native metadata guards passed for all three operations.');
for (const [file, validator] of [
  ['mcp-context-excerpt-pending', 'validOutput_get_file_excerpt'],
  ['mcp-context-excerpt-result', 'validOutput_get_file_excerpt'],
  ['mcp-context-query-pending', 'validOutput_get_query_result'],
  ['mcp-context-query-result', 'validOutput_get_query_result'],
]) {
  const example = JSON.parse(await readFile(new URL('../../examples/' + file + '.json', import.meta.url), 'utf8'));
  assert.equal(projection[validator](example), true, file);
  example.data.query_expires_at = 'not-a-date';
  assert.equal(projection[validator](example), false, file + ' invalid query expiry');
}
assert.equal(projection.validInput_get_query_result({ query_handle: 'original', idempotency_key: 'extra' }), false);
console.log('Native ESM approved projection and pending query validators passed canonical examples and invalid timing checks.');
const policyReply = { schema_version: 'mcp-result/v1', request_id: '00000000-0000-4000-8000-000000000001', data_class: 'metadata', status: 'ok', truncated: false, next_cursor: null, narrowing_hint: null, warnings: [], provenance: [],
  data: { policy_uid: 'policy-uid', acceptance_id: '00000000-0000-4000-8000-000000000002', state: 'deactivated', replay: false } };
assert.equal(policy.validOutput_deactivate_policy(policyReply), true);
assert.equal(policy.validOutput_deactivate_policy({ ...policyReply, data: { ...policyReply.data, state: 'active' } }), false);
assert.equal(policy.validInput_deactivate_policy({ policy_name: 'regional-restarts', idempotency_key: 'k' }), true);
assert.equal(policy.validInput_deactivate_policy({ policy_name: 'Bad_Name', idempotency_key: 'k' }), false);
console.log('Native ESM policy validators passed positive and negative checks.');
const shareReply = { ...policyReply, data: { share_id: '00000000-0000-4000-8000-000000000003', phase: 'Revoked', revision: 2 } };
assert.equal(sharing.validOutput_revoke_share(shareReply), true);
assert.equal(sharing.validOutput_revoke_share({ ...shareReply, data: { ...shareReply.data, phase: 'Active' } }), false);
const shareInput = { case_id: '00000000-0000-4000-8000-000000000002', artifacts: [{ artifactID: '00000000-0000-4000-8000-000000000004', digest: 'ab'.repeat(32) }],
  recipients: [{ kind: 'Group', issuer: 'https://identity.invalid', id: 'team' }], data_classes: ['metadata'], operations: ['get_case'],
  expires_at: '2026-10-27T12:00:00Z', reason: 'incident review', idempotency_key: 'k' };
assert.equal(sharing.validInput_create_share(shareInput), true);
assert.equal(sharing.validInput_create_share({ ...shareInput, recipients: [{ kind: 'Team', issuer: 'https://identity.invalid', id: 'team' }] }), false);
assert.equal(sharing.validInput_list_shares({ view: 'received', limit: 100 }), true);
console.log('Native ESM share validators passed positive and negative checks.');

// Recording inventory/save uses the same canonical schemas in native ESM.
const recordings = await import('../src/generated/validate-recordings.js');
assert.equal(recordings.validInput_list_recordings({ target_ref: { cluster_id: id, namespace: 'payments', kind: 'Deployment', name: 'api' }, limit: 20 }), true);
assert.equal(recordings.validInput_preview_recording_save({ recording_handles: ['opaque-source'], before: '10s' }), true);
for (const extra of [{ after: '5s' }, { t0: '2026-10-30T12:00:00Z' }, { executor: {} }, { recipe: 'core' }]) assert.equal(recordings.validInput_preview_recording_save({ recording_handles: ['opaque-source'], ...extra }), false);
const saveExample = JSON.parse(await readFile(new URL('../../examples/mcp-recording-save-preview-result.json', import.meta.url), 'utf8'));
assert.equal(recordings.validOutput_preview_recording_save(saveExample), true, 'typed recording-save preview');
const badSource = structuredClone(saveExample); badSource.data.selected_recordings[0].packet_contents = 'not metadata';
assert.equal(recordings.validOutput_preview_recording_save(badSource), false, 'recording metadata rejects evidence fields');
console.log('Native ESM recording inventory/save validators passed positive and negative checks.');
