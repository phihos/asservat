import { afterEach, expect, it, vi } from 'vitest';
import { Investigation } from './investigation';
import { FakeEventSource } from '../test-setup';
import { SyntheticOperations, SyntheticGrants, session, target, id, previewResult, acceptedResult, progressResult, catalogResult, recordingPreviewResult, approvalPendingResult, settingsResult, historyResult } from './test-fixtures';

const controllers: Investigation[] = [];
const submission = (retention: number, key = id(4)) => ({ preview: { target_ref: target, preset_ref: { name: 'pod-status', version: 'v1' }, requested_retention_seconds: retention }, expected_plan_digest: 'b'.repeat(64), idempotency_key: key });
it('opens settings from a direct capture URL and repeats only after an explicit review with a fresh target', async () => {
  const client = new SyntheticOperations(); const controller = new Investigation(client); controllers.push(controller);
  client.responder = name => name === 'get_capture' ? progressResult('Succeeded') : name === 'get_capture_settings' ? settingsResult(id(8)) : previewResult();
  controller.attach(session, new AbortController().signal, id(8));
  await vi.waitFor(() => expect(controller.snapshot().busy).toBe(false));
  await controller.repeat(id(8));
  expect(client.calls.some(c => c.name === 'preview_capture')).toBe(false);
  await controller.showSettings(id(8));
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8), settings: { capture_id: id(8) } });
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  await controller.previewComposition(recording.data.profile_composition!.authored, id(8), undefined, '0');
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8), settings: { capture_id: id(8) } });
  expect(client.calls.some(c => c.name === 'preview_capture')).toBe(false);
  client.responder = () => { const p = previewResult(); if (p.status !== 'ok') throw new Error(); p.data.repeated_from_capture_id = id(8); p.data.selected_pods![0].name = 'api-new'; p.data.selected_pods![0].uid = 'fresh-pod-uid'; return p; };
  await controller.repeat(id(8));
  expect(client.calls.at(-1)!.input).toEqual({ history_capture_id: id(8) });
  expect(controller.snapshot()).toMatchObject({ stage: 'review', captureID: undefined, repeatedFrom: id(8), draft: { target }, preview: { selected_pods: [{ name: 'api-new', uid: 'fresh-pod-uid' }] } });
  expect(client.calls.some(c => c.name === 'request_capture')).toBe(false);
});
it('reviews edited recorder parameters under the same source and version pins without restoring old authority', async () => {
  const { controller, client } = await ready('3600');
  client.responder = name => name === 'get_capture_settings' ? settingsResult() : recordingPreviewResult(id(41));
  await controller.showSettings(id(41));
  expect(controller.snapshot().settings?.capture_id).toBe(id(41));
  const saved = recordingPreviewResult(); if (saved.status !== 'ok') throw new Error();
  const edited = structuredClone(saved.data.profile_composition!.authored);
  edited.components[0].overrides![0].value = 'tcp port 8443'; edited.maxDuration = '15s';
  await controller.previewComposition(edited, id(41));
  const inputs = client.calls.filter(c => c.name === 'preview_capture').map(c => c.input);
  expect(inputs.at(-1)).toEqual({ target_ref: target, profile_composition: edited, repeated_from_capture_id: id(41) });
  expect(controller.snapshot()).toMatchObject({ stage: 'review', repeatedFrom: id(41) });
  await controller.preview();
  expect(client.calls.filter(c => c.name === 'preview_capture').at(-1)!.input).toEqual(inputs.at(-1));
  expect(client.calls.some(c => c.name === 'request_capture')).toBe(false);
  expect(edited.components.map(c => c.profileRef)).toEqual(saved.data.profile_composition!.authored.components.map(c => c.profileRef));
});
it('preserves typed argument settings and false when repeating and refreshing a capture review', async () => {
  const { controller, client } = await ready();
  client.responder = () => recordingPreviewResult(id(41));
  const saved = recordingPreviewResult(); if (saved.status !== 'ok') throw new Error();
  const edited = structuredClone(saved.data.profile_composition!.authored);
  edited.components[0].profileRef = { catalog: 'namespace', name: 'argument-capture', version: 'v2' };
  edited.components[0].overrides = [{ actionID: 'syscalls', field: 'syscallArguments', value: { maxBytesPerEvent: 128, captureBuffers: false } }];
  await controller.previewComposition(edited, id(41));
  await controller.preview();
  const calls = client.calls.filter(c => c.name === 'preview_capture').slice(-2);
  expect(calls).toHaveLength(2);
  for (const call of calls) expect(JSON.parse(JSON.stringify(call.input))).toMatchObject({ target_ref: target, profile_composition: edited, repeated_from_capture_id: id(41) });
  expect(client.calls.some(c => c.name === 'request_capture')).toBe(false);
});
it('preserves explicit current policy Pod selection and edited retention on refresh', async () => {
  const { controller, client } = await ready();
  client.responder = () => recordingPreviewResult(id(41));
  await controller.repeat(id(41), 'currentEligiblePod');
  expect(client.calls.at(-1)!.input).toEqual({ history_capture_id: id(41), history_selection: 'currentEligiblePod' });
  const saved = recordingPreviewResult(); if (saved.status !== 'ok') throw new Error();
  await controller.previewComposition(saved.data.profile_composition!.authored, id(41), 'currentEligiblePod', '90');
  await controller.preview();
  expect(client.calls.at(-1)!.input).toMatchObject({ repeated_from_capture_id: id(41), history_selection: 'currentEligiblePod', requested_retention_seconds: 90 });
  expect(client.calls.some(c => c.name === 'request_capture')).toBe(false);
});
it('filters history origins and refuses expired settings without preparing a capture', async () => {
  const { controller, client } = await ready();
  client.responder = () => historyResult(); await controller.historyOrigin('policy');
  expect(client.calls.at(-1)!.input).toMatchObject({ origin: 'policy' });
  const settings = settingsResult(); if (settings.status !== 'ok') throw new Error();
  settings.data.expires_at = new Date(Date.now() - 1).toISOString();
  client.responder = () => settings;
  await controller.showSettings(id(41));
  expect(controller.snapshot().settings).toBeUndefined();
  expect(controller.snapshot().error).toMatch(/could not be verified/);
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(1);
});
it('drops saved settings at their original source expiry and on session cancellation', async () => {
  vi.useFakeTimers();
  const { controller, client, scope } = await ready();
  client.responder = () => settingsResult();
  await controller.showSettings(id(41));
  expect(controller.snapshot().settings).toBeDefined();
  await vi.advanceTimersByTimeAsync(60_001);
  expect(controller.snapshot().settings).toBeUndefined();
  await controller.showSettings(id(41));
  expect(controller.snapshot().settings).toBeDefined();
  scope.abort();
  expect(controller.snapshot().settings).toBeUndefined();
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
});
it('pages with the opaque authorized cursor, removes duplicates and expires its cached history', async () => {
  vi.useFakeTimers();
  const { controller, client } = await ready();
  const page = historyResult([id(41)]); if (page.status !== 'ok') throw new Error();
  page.next_cursor = 'opaque-server-cursor';
  page.data.history[0].summary_expires_at = new Date(Date.now() + 30_000).toISOString();
  client.responder = () => page; await controller.historyOrigin('all');
  client.responder = () => historyResult([id(42), id(41)]);
  await controller.moreHistory();
  expect(client.calls.at(-1)!.input).toMatchObject({ cursor: 'opaque-server-cursor', origin: 'all' });
  expect(controller.snapshot().history?.map(row => row.capture_id)).toEqual([id(41), id(42)]);
  expect(controller.snapshot().historyCursor).toBeUndefined();
  await vi.advanceTimersByTimeAsync(30_001);
  expect(controller.snapshot().history).toBeUndefined();
  expect(controller.snapshot().historyMessage).toMatch(/Refresh history/);
});
afterEach(() => { for (const c of controllers) c.reset(); controllers.length = 0; vi.useRealTimers(); window.history.replaceState(null, '', '/'); });
async function ready(retention = '3600', newID = () => id(4)) {
  const client = new SyntheticOperations(); const grants = new SyntheticGrants();
  const controller = new Investigation(client, newID, grants); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal);
  controller.setDraft({ target, retention }); await controller.discover();
  await controller.preview(controller.snapshot().diagnostics![0]);
  expect(controller.snapshot().stage).toBe('review');
  return { controller, client, scope, grants };
}
it('submits only the reviewed preview input and digest and freezes its key before I/O', async () => {
  const { controller, client } = await ready(); await controller.submit();
  expect(client.calls.find(call => call.name === 'preview_capture')!.input).toMatchObject({ requested_retention_seconds: 3600 });
  const submitted = client.calls.filter(call => call.name === 'request_capture');
  expect(submitted).toHaveLength(1);
  expect(submitted[0].input).toEqual(submission(3600));
  expect(controller.snapshot().progress?.phase).toBe('Pending');
  expect(window.location.pathname).toBe('/captures/' + id(8));
  await controller.submit(); expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(1);
});
it('submits the same reviewed handle after two minutes; assessment age does not impose a five-second click timer', async () => {
  vi.useFakeTimers(); const { controller, client } = await ready('60');
  await vi.advanceTimersByTimeAsync(120_000);
  expect(controller.snapshot().stale).toBe(true);
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  await controller.submit();
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
  expect(client.calls.find(call => call.name === 'preview_capture')!.input).toMatchObject({ requested_retention_seconds: 60 });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual(submission(60));
});
it('retains only the reviewed request across same-user session scopes', async () => {
  vi.useFakeTimers(); const { controller, client, scope } = await ready('60');
  await vi.advanceTimersByTimeAsync(120_000); scope.abort();
  controller.attach(session, new AbortController().signal);
  expect(controller.snapshot()).toMatchObject({ stage: 'reviewed', preview: undefined, diagnostics: undefined });
  await controller.submit();
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual(submission(60));
});
it('clears the unsubmitted review on new identity or logout', async () => {
  const { controller, client } = await ready();
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other-user' } }, new AbortController().signal);
  expect(controller.snapshot().stage).toBe('target');
  controller.reset(); controller.attach(session, new AbortController().signal); await controller.submit();
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
});
it('retries an unknown committed reply using the same receipt across session refresh', async () => {
  const { controller, client, scope } = await ready();
  client.responder = () => { throw new Error('lost commit reply'); };
  await controller.submit(); expect(controller.snapshot().stage).toBe('uncertain');
  scope.abort(); controller.attach(session, new AbortController().signal);
  expect(controller.snapshot().preview).toBeUndefined();
  client.responder = name => name === 'request_capture' ? acceptedResult() : progressResult();
  await controller.retrySubmission();
  const submissions = client.calls.filter(call => call.name === 'request_capture');
  expect(submissions).toHaveLength(2); expect(submissions[0].input).toEqual(submissions[1].input);
  expect(controller.snapshot().captureID).toBe(id(8));
});
it('discards a late response after scope cancellation but retains only its retry receipt', async () => {
  const { controller, client, scope } = await ready();
  let resolve!: (v: unknown) => void;
  client.responder = () => new Promise(r => { resolve = r; });
  const pending = controller.submit(); scope.abort(); resolve(acceptedResult()); await pending;
  expect(controller.snapshot().captureID).toBeUndefined();
  controller.attach(session, new AbortController().signal);
  expect(controller.snapshot().stage).toBe('uncertain');
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'different' } }, new AbortController().signal);
  expect(controller.snapshot().stage).toBe('target');
  await controller.retrySubmission(); expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(1);
});
it('never treats an available preview as permission to bypass runtime disablement', async () => {
  const { controller, client } = await ready();
  const value = previewResult(); if (value.status !== 'ok') throw new Error(); value.data.capture_enabled = false;
  client.responder = () => value; await controller.preview(); await controller.submit();
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
});
it('accepts reordered object fields and rejects a substituted exact target', async () => {
  const { controller, client } = await ready();
  const value = previewResult(); if (value.status !== 'ok') throw new Error();
  value.data.target_ref = { name: target.name, kind: target.kind, namespace: target.namespace, cluster_id: target.cluster_id };
  client.responder = () => value; await controller.preview(); expect(controller.snapshot().preview).toBeTruthy();
  value.data.target_ref.name = 'another'; await controller.preview(); expect(controller.snapshot().preview).toBeUndefined();
});
it('hides progress after a denied read and rejects decreasing durable revisions', async () => {
  const { controller, client } = await ready(); await controller.submit();
  client.responder = () => progressResult('Finalizing', 3); await controller.refreshProgress();
  expect(controller.snapshot().progress?.phase).toBe('Finalizing');
  client.responder = () => progressResult('Pending', 2); await controller.refreshProgress();
  expect(controller.snapshot().progress).toBeUndefined();
  client.responder = () => { throw new Error('permission changed'); }; await controller.refreshProgress();
  expect(controller.snapshot().progress).toBeUndefined();
  client.responder = () => progressResult('Pending', 2); await controller.refreshProgress();
  expect(controller.snapshot().progress).toBeUndefined();
});
it('follows pushed status events instead of polling and stops at a terminal phase', async () => {
  vi.useFakeTimers(); const { controller, client } = await ready(); await controller.submit();
  client.responder = () => progressResult('Pending', 1); await controller.refreshProgress();
  const stream = FakeEventSource.instances.at(-1)!;
  expect(stream.url).toBe('/api/v1/events?capture_id=' + id(8));
  const reads = client.calls.filter(c => c.name === 'get_capture').length;
  await vi.advanceTimersByTimeAsync(60_000);
  expect(client.calls.filter(c => c.name === 'get_capture').length).toBe(reads);
  stream.emit('capture', { type: 'capture', id: id(8), revision: 2, result: progressResult('Finalizing', 2) });
  expect(controller.snapshot().progress?.phase).toBe('Finalizing');
  stream.emit('capture', { type: 'capture', id: id(8), revision: 3, result: progressResult('Succeeded', 3) });
  expect(controller.snapshot().progress?.phase).toBe('Succeeded');
  expect(stream.closed).toBe(true);
});
it('resynchronizes once after the stream closes and reports a failed resync', async () => {
  vi.useFakeTimers(); const { controller, client } = await ready(); await controller.submit();
  client.responder = () => progressResult('Pending', 1); await controller.refreshProgress();
  const first = FakeEventSource.instances.at(-1)!;
  client.responder = () => progressResult('Finalizing', 2);
  first.fail(); await vi.advanceTimersByTimeAsync(0);
  expect(controller.snapshot().progress?.phase).toBe('Finalizing');
  const second = FakeEventSource.instances.at(-1)!;
  expect(second).not.toBe(first);
  client.responder = () => { throw new Error('session ended'); };
  second.fail(); await vi.advanceTimersByTimeAsync(0);
  expect(controller.snapshot().error).toMatch(/updates stopped/);
  expect(FakeEventSource.instances.at(-1)).toBe(second);
});
it('rejects a selected pod outside the requested workload even in a schema-valid reply', async () => {
  const { controller, client } = await ready();
  const value = previewResult(); if (value.status !== 'ok') throw new Error();
  value.data.selected_pods![0].workload.name = 'foreign';
  client.responder = () => value; await controller.preview();
  expect(controller.snapshot().preview).toBeUndefined();
  expect(controller.snapshot().error).toContain('could not be verified');
});
it('does not display or submit a pod-status review with another mechanism\'s retention anchor', async () => {
  const { controller, client } = await ready();
  const value = previewResult(); if (value.status !== 'ok') throw new Error();
  value.data.capture_assessment.actions[0].retention.anchorRule = 'firstAcquisitionOrEarlierSource';
  client.responder = () => value; await controller.preview(); await controller.submit();
  expect(controller.snapshot().preview).toBeUndefined();
  expect(controller.snapshot().error).toContain('could not be verified');
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
});
it('keeps the administrator retention default absent and rejects malformed custom values', async () => {
  const { controller, client } = await ready(); controller.edit(); controller.setDraft({ target, retention: '' });
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : previewResult();
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
  expect(client.calls.at(-1)!.input).not.toHaveProperty('requested_retention_seconds');
  controller.edit(); controller.setDraft({ target, retention: '0' }); await controller.discover();
  const count = client.calls.length; await controller.preview(controller.snapshot().diagnostics![0]);
  expect(client.calls).toHaveLength(count); expect(controller.snapshot().error).toContain('whole number');
});
it('sends capture-time sharing with the issuer of the signed-in user and only an explicit end (ADR-235)', async () => {
  const { controller, client } = await ready(); controller.edit();
  controller.setDraft({ target, retention: '', sharing: [{ kind: 'Group', id: 'incident-team' }] });
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : previewResult();
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
  expect(client.calls.at(-1)!.input).toMatchObject({ sharing: { recipients: [{ kind: 'Group', issuer: session.principal.issuer, id: 'incident-team' }] } });
  expect((client.calls.at(-1)!.input as { sharing: object }).sharing).not.toHaveProperty('notAfter');
  const before = Date.now();
  controller.edit(); controller.setDraft({ target, retention: '', sharing: [{ kind: 'User', id: 'reviewer' }], shareHours: 2 });
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
  const end = Date.parse((client.calls.at(-1)!.input as { sharing: { notAfter: string } }).sharing.notAfter);
  expect(end).toBeGreaterThanOrEqual(before + 2 * 3_600_000); expect(end).toBeLessThan(before + 2 * 3_600_000 + 60_000);
  controller.edit(); controller.setDraft({ target, retention: '', sharing: [{ kind: 'User', id: 'reviewer' }], shareHours: 169 }); await controller.discover();
  const count = client.calls.length; await controller.preview(controller.snapshot().diagnostics![0]);
  expect(client.calls).toHaveLength(count); expect(controller.snapshot().error).toContain('168');
  controller.edit(); controller.setDraft({ target, retention: '', sharing: [] });
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
  expect(client.calls.at(-1)!.input).not.toHaveProperty('sharing');
});

async function uncertain() {
  const setup = await ready();
  setup.client.responder = () => { throw new Error('unknown admission'); };
  await setup.controller.submit();
  return setup;
}
it.each(['ReviewChanged', 'Conflict'])('releases the receipt after a final %s refusal; a fresh review gets a new key', async code => {
  const newID = vi.fn().mockReturnValueOnce(id(4)).mockReturnValueOnce(id(5));
  const { controller, client } = await ready('60', newID);
  client.responder = () => { throw new Error('unknown admission'); }; await controller.submit();
  client.responder = () => ({ ...acceptedResult(), status: 'error', data: { code, message: 'The reviewed plan changed. Review it again.', retryable: false } });
  await controller.retrySubmission();
  expect(controller.snapshot()).toMatchObject({ stage: 'target', error: 'The reviewed plan changed. Review it again.', draft: { target, retention: '60' } });
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : name === 'preview_capture' ? previewResult() : name === 'request_capture' ? acceptedResult() : progressResult();
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]); await controller.submit();
  expect(client.calls.filter(c => c.name === 'request_capture').map(c => c.input)).toEqual([submission(60), submission(60), submission(60, id(5))]);
});
it('keeps the receipt after a retryable error and clears it on identity change', async () => {
  const { controller, client } = await uncertain();
  client.responder = () => ({ ...acceptedResult(), status: 'error', data: { code: 'Unavailable', message: 'Try again.', retryable: true } });
  await controller.retrySubmission(); await controller.preview();
  expect(controller.snapshot().stage).toBe('uncertain');
  const submits = client.calls.filter(c => c.name === 'request_capture');
  expect(submits).toHaveLength(2); expect(submits[1].input).toEqual(submits[0].input);
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other' } }, new AbortController().signal);
  await controller.retrySubmission();
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(2); expect(controller.snapshot().stage).toBe('target');
});

it('requests independent approval for an exact recording review and resubmits the same request after approval', async () => {
  vi.useFakeTimers();
  const { controller, client, scope } = await ready();
  client.responder = name => name === 'preview_capture' ? recordingPreviewResult() : approvalPendingResult();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  await controller.previewComposition(recording.data.profile_composition!.authored);
  expect(controller.snapshot().preview?.approval_required).toBe(true);
  await controller.submit();
  expect(controller.snapshot()).toMatchObject({ stage: 'approval', approvalURI: '/approvals/' + id(41), captureID: undefined });
  expect(client.calls.some(c => c.name === 'get_capture')).toBe(false);
  const submitted = client.calls.filter(c => c.name === 'request_capture');
  expect(submitted).toHaveLength(1);
  const first = submitted[0].input;
  scope.abort(); controller.attach(session, new AbortController().signal);
  expect(controller.snapshot()).toMatchObject({ stage: 'approval', preview: undefined, approvalURI: '/approvals/' + id(41) });
  await vi.advanceTimersByTimeAsync(120_001);
  client.responder = name => name === 'request_capture' ? acceptedResult() : progressResult();
  await controller.retrySubmission();
  expect(client.calls.filter(c => c.name === 'request_capture').map(c => c.input)).toEqual([first, first]);
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(2);
  expect(controller.snapshot().captureID).toBe(id(8));
});
// ADR-335 D5: approval submits the request; the tab waits for its capture.
it('waits for the capture an approval starts and resubmits only after the sign-in ended', async () => {
  const { controller, client, grants } = await ready();
  client.responder = () => approvalPendingResult(); await controller.submit();
  await vi.waitFor(() => expect(grants.calls).toBe(1));
  const stream = FakeEventSource.instances.at(-1)!;
  expect(stream.url).toBe('/api/v1/events?capture_id=' + id(8));
  client.responder = () => progressResult();
  stream.emit('capture', {});
  await vi.waitFor(() => expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8) }));
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);

  const again = await ready();
  again.client.responder = () => approvalPendingResult(); again.grants.grant = { phase: 'Approved', can_resume: true };
  await again.controller.submit();
  await vi.waitFor(() => expect(again.controller.snapshot().resubmit).toBe(true));
  expect(again.client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);

  // A decision without a capture ends the wait and the grant is read again.
  const decided = await ready();
  decided.client.responder = () => approvalPendingResult(); await decided.controller.submit();
  await vi.waitFor(() => expect(decided.grants.calls).toBe(1));
  decided.grants.grant = { phase: 'Approved', can_resume: true };
  FakeEventSource.instances.at(-1)!.emit('accessLost', {});
  await vi.waitFor(() => expect(decided.controller.snapshot().resubmit).toBe(true));
  expect(decided.grants.calls).toBe(2);

  const approved = await ready();
  approved.client.responder = () => approvalPendingResult(); await approved.controller.submit();
  approved.grants.grant = { phase: 'Approved', can_resume: false };
  approved.client.responder = name => name === 'request_capture' ? acceptedResult() : progressResult();
  await approved.controller.checkApproval();
  const submits = approved.client.calls.filter(c => c.name === 'request_capture');
  expect(submits).toHaveLength(2); expect(submits[1].input).toEqual(submits[0].input);
  expect(approved.controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8) });
});
it('drops an approval-pending submission only on an explicit edit', async () => {
  const { controller, client } = await ready();
  client.responder = () => approvalPendingResult(); await controller.submit();
  expect(controller.snapshot().stage).toBe('approval');
  controller.discardApprovalRequest();
  expect(controller.snapshot()).toMatchObject({ stage: 'target', approvalURI: undefined });
  await controller.retrySubmission(); expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
});

it('retains selected result access unchanged through uncertain submission and approval', async () => {
  const { controller, client, scope } = await ready();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  client.responder = () => recording;
  await controller.previewComposition(recording.data.profile_composition!.authored);
  const access = { actionIds: [recording.data.capture_assessment.actions[0].actionID], operations: ['download_artifact' as const, 'pcap_query' as const, 'syscall_query' as const], maxArtifacts: 1, maxBytes: 8 * 1024 * 1024 + 49152, maxOperations: 10, notAfter: new Date(Date.now() + 3600000).toISOString() };
  client.responder = () => { throw new Error('lost response'); };
  await controller.submit(access);
  access.maxBytes = 1; access.actionIds[0] = 'changed'; access.operations.reverse(); access.maxOperations = 1; access.notAfter = new Date(0).toISOString();
  const first = client.calls.filter(c => c.name === 'request_capture')[0].input;
  expect(first).toMatchObject({ result_access: { maxBytes: 8 * 1024 * 1024 + 49152, operations: ['download_artifact', 'pcap_query', 'syscall_query'], maxOperations: 10, actionIds: [recording.data.capture_assessment.actions[0].actionID] } });
  scope.abort(); controller.attach(session, new AbortController().signal);
  client.responder = () => approvalPendingResult();
  await controller.retrySubmission();
  expect(client.calls.filter(c => c.name === 'request_capture').map(c => c.input)).toEqual([first, first]);
  controller.reset();
});
