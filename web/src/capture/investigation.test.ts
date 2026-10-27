import { afterEach, expect, it, vi } from 'vitest';
import { Investigation } from './investigation';
import { SyntheticOperations, session, target, id, previewResult, acceptedResult, progressResult, catalogResult, resolvedAcceptedResult, resolvedClosedResult, recordingPreviewResult, approvalPendingResult } from './test-fixtures';

const controllers: Investigation[] = [];
afterEach(() => { for (const c of controllers) c.reset(); controllers.length = 0; vi.useRealTimers(); window.history.replaceState(null, '', '/'); });
async function ready(retention = '3600', newID = () => id(4)) {
  const client = new SyntheticOperations();
  const controller = new Investigation(client, newID); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal);
  controller.setDraft({ target, retention }); await controller.discover();
  await controller.preview(controller.snapshot().diagnostics![0]);
  expect(controller.snapshot().stage).toBe('review');
  return { controller, client, scope };
}
it('submits only the reviewed handle and freezes its original key before I/O', async () => {
  const { controller, client } = await ready(); await controller.submit();
  expect(client.calls.find(call => call.name === 'preview_capture')!.input).toMatchObject({ requested_retention_seconds: 3600 });
  const submission = client.calls.filter(call => call.name === 'request_capture');
  expect(submission).toHaveLength(1);
  expect(submission[0].input).toEqual({ preview_id: id(173), idempotency_key: id(4) });
  expect(controller.snapshot().progress?.phase).toBe('Pending');
  expect(window.location.pathname).toBe('/captures/' + id(8));
  await controller.submit(); expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(1);
});
it('submits the same reviewed handle after two minutes; assessment age does not impose a five-second click timer', async () => {
  vi.useFakeTimers(); const { controller, client } = await ready('60');
  await vi.advanceTimersByTimeAsync(120_000);
  expect(controller.snapshot().stale).toBe(true);
  expect(controller.snapshot().expired).toBe(false);
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  await controller.submit();
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
  expect(client.calls.find(call => call.name === 'preview_capture')!.input).toMatchObject({ requested_retention_seconds: 60 });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual({ preview_id: id(173), idempotency_key: id(4) });
});
it('retains only the eligible reviewed handle across same-user session scopes without extending its original expiry', async () => {
  vi.useFakeTimers(); const { controller, client, scope } = await ready('60');
  await vi.advanceTimersByTimeAsync(120_000); scope.abort();
  controller.attach(session, new AbortController().signal);
  expect(controller.snapshot()).toMatchObject({ stage: 'reviewed', expired: false, preview: undefined, diagnostics: undefined });
  await controller.submit();
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual({ preview_id: id(173), idempotency_key: id(4) });
});
it('clears the unsubmitted handle on new identity/logout and preserves its original expiry on refresh', async () => {
  vi.useFakeTimers(); const { controller, client, scope } = await ready();
  await vi.advanceTimersByTimeAsync(240_000); scope.abort(); controller.attach(session, new AbortController().signal);
  await vi.advanceTimersByTimeAsync(60_001); await controller.submit();
  expect(controller.snapshot().expired).toBe(true); expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other-user' } }, new AbortController().signal);
  expect(controller.snapshot().stage).toBe('target');
  controller.reset(); controller.attach(session, new AbortController().signal); await controller.submit();
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
});
it('requires a new review after actual passive-preview expiry and never submits automatically', async () => {
  vi.useFakeTimers(); const { controller, client } = await ready();
  await vi.advanceTimersByTimeAsync(300_001); await controller.submit();
  expect(controller.snapshot().expired).toBe(true);
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  await controller.preview(); expect(controller.snapshot().expired).toBe(false);
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
it('opens an already accepted request from resolution without another admission or a new key', async () => {
  const { controller, client } = await uncertain();
  client.responder = name => name === 'resolve_capture_request' ? resolvedAcceptedResult() : progressResult();
  await controller.resolveBeforeEditing();
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
  expect(client.calls.find(c => c.name === 'resolve_capture_request')!.input).toEqual({ preview_id: id(173), idempotency_key: id(4) });
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8) });
  controller.editClosedRequest(); await controller.resolveBeforeEditing();
  expect(controller.snapshot().stage).toBe('progress');
  expect(client.calls.filter(c => c.name === 'resolve_capture_request')).toHaveLength(1);
});
it('requires acknowledged closure and an explicit edit before preparing a new review', async () => {
  const { controller, client } = await uncertain();
  controller.editClosedRequest(); expect(controller.snapshot().stage).toBe('uncertain');
  client.responder = () => resolvedClosedResult();
  await controller.resolveBeforeEditing();
  expect(controller.snapshot()).toMatchObject({ stage: 'closed', preview: undefined, progress: undefined, captureID: undefined });
  await controller.retrySubmission(); await controller.preview(); await controller.discover();
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(1);
  controller.editClosedRequest();
  expect(controller.snapshot()).toMatchObject({ stage: 'target', draft: { target, retention: '3600' } });
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(1);
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
});
it.each(['PreviewExpired', 'ReviewChanged', 'Conflict', 'CollectionDisabled', 'Unavailable'])('keeps the receipt when resolution reports %s instead of durable closure', async code => {
  const { controller, client } = await uncertain();
  client.responder = () => ({ ...resolvedClosedResult(), status: 'error', data: { code, message: 'Access or recovery is unavailable.', retryable: false } });
  await controller.resolveBeforeEditing(); controller.editClosedRequest();
  expect(controller.snapshot().stage).toBe('uncertain');
  client.responder = () => { throw new Error('another unknown reply'); };
  await controller.retrySubmission();
  const submits = client.calls.filter(c => c.name === 'request_capture');
  expect(submits).toHaveLength(2); expect(submits[1].input).toEqual(submits[0].input);
});
it('repeats a lost closure reply with the same pair after session refresh and retains acknowledged closure', async () => {
  const { controller, client, scope } = await uncertain();
  await controller.resolveBeforeEditing(); // Transport failure may follow durable closure.
  expect(controller.snapshot().stage).toBe('uncertain');
  scope.abort(); const nextScope = new AbortController(); controller.attach(session, nextScope.signal);
  client.responder = () => resolvedClosedResult(); await controller.resolveBeforeEditing();
  const resolutions = client.calls.filter(c => c.name === 'resolve_capture_request');
  expect(resolutions).toHaveLength(2); expect(resolutions[0].input).toEqual(resolutions[1].input);
  nextScope.abort(); controller.attach(session, new AbortController().signal);
  expect(controller.snapshot()).toMatchObject({ stage: 'closed', preview: undefined, progress: undefined });
  await controller.retrySubmission(); expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
});
it('discards late closure after scope loss and lets a current accepted outcome win', async () => {
  const { controller, client, scope } = await uncertain();
  let close!: (v: unknown) => void;
  client.responder = () => new Promise(r => { close = r; });
  const pending = controller.resolveBeforeEditing();
  scope.abort(); controller.attach(session, new AbortController().signal);
  client.responder = name => name === 'resolve_capture_request' ? resolvedAcceptedResult() : progressResult();
  await controller.resolveBeforeEditing(); close(resolvedClosedResult()); await pending;
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8) });
  controller.editClosedRequest(); expect(controller.snapshot().stage).toBe('progress');
});
it('clears unresolved and closed receipts on identity change or explicit reset', async () => {
  const { controller, client } = await uncertain();
  client.responder = () => resolvedClosedResult(); await controller.resolveBeforeEditing();
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other' } }, new AbortController().signal);
  const before = client.calls.length;
  await controller.resolveBeforeEditing(); controller.editClosedRequest();
  expect(client.calls).toHaveLength(before); expect(controller.snapshot().stage).toBe('target');
  controller.reset(); expect(controller.snapshot().draft.target.name).toBe('');
});

it('creates a new key only on a deliberate submission after closed request editing and a fresh review', async () => {
  const newID = vi.fn().mockReturnValueOnce(id(4)).mockReturnValueOnce(id(5));
  const { controller, client } = await ready('60', newID);
  expect(newID).not.toHaveBeenCalled();
  client.responder = () => { throw new Error('unknown admission'); }; await controller.submit();
  expect(newID).toHaveBeenCalledTimes(1);
  client.responder = () => resolvedClosedResult(); await controller.resolveBeforeEditing();
  controller.editClosedRequest(); await controller.submit();
  expect(newID).toHaveBeenCalledTimes(1);
  client.responder = name => {
    if (name === 'list_diagnostics') return catalogResult();
    if (name === 'preview_capture') { const preview = previewResult(); if (preview.status === 'ok') preview.data.preview_id = id(174); return preview; }
    return name === 'request_capture' ? acceptedResult() : progressResult();
  };
  await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
  expect(newID).toHaveBeenCalledTimes(1);
  await controller.submit();
  expect(newID).toHaveBeenCalledTimes(2);
  expect(client.calls.filter(c => c.name === 'request_capture').map(c => c.input)).toEqual([
    { preview_id: id(173), idempotency_key: id(4) }, { preview_id: id(174), idempotency_key: id(5) },
  ]);
});
it('continues accepted acquisition only on an explicit action using the same receipt', async () => {
  vi.useFakeTimers(); const { controller, client, scope } = await ready(); await controller.submit();
  await vi.advanceTimersByTimeAsync(12_000);
  scope.abort(); controller.attach(session, new AbortController().signal);
  await vi.advanceTimersByTimeAsync(1); // Settle attach's automatic passive status read.
  expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(1);
  expect(controller.snapshot().canContinue).toBe(true);
  await controller.continueAcquisition();
  const submissions = client.calls.filter(call => call.name === 'request_capture');
  expect(submissions.map(call => call.input)).toEqual([
    { preview_id: id(173), idempotency_key: id(4) },
    { preview_id: id(173), idempotency_key: id(4), continue_acquisition: true },
  ]);
  expect(controller.snapshot().captureID).toBe(id(8));
  expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
});
it('keeps an uncertain continuation attached to the same original capture and key', async () => {
  const { controller, client } = await ready(); await controller.submit();
  client.responder = () => { throw new Error('lost start reply'); };
  await controller.continueAcquisition();
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8) });
  expect(controller.snapshot().error).toContain('Collection may already have started');
  client.responder = name => name === 'request_capture' ? acceptedResult() : progressResult();
  await controller.continueAcquisition();
  const calls = client.calls.filter(call => call.name === 'request_capture');
  expect(calls[1].input).toEqual(calls[2].input);
  expect(calls[2].input).toEqual({ preview_id: id(173), idempotency_key: id(4), continue_acquisition: true });
});
it('never reconstructs continuation authority from a pasted progress URL', async () => {
  const client = new SyntheticOperations(); const controller = new Investigation(client); controllers.push(controller);
  controller.attach(session, new AbortController().signal, id(8)); await controller.refreshProgress();
  expect(controller.snapshot().canContinue).toBe(false);
  await controller.continueAcquisition();
  expect(client.calls.every(call => call.name === 'get_capture')).toBe(true);
});
it.each(['AcquisitionClosed', 'AcquisitionUncertain'])('stops continuation after %s without minting a replacement', async code => {
  const { controller, client } = await ready(); await controller.submit();
  client.responder = () => ({ ...acceptedResult(), status: 'error', data: { code, message: 'Check the original collection status before starting another investigation.', retryable: false } });
  await controller.continueAcquisition();
  expect(controller.snapshot().captureID).toBe(id(8)); expect(controller.snapshot().canContinue).toBe(false);
  client.responder = () => progressResult(); await controller.refreshProgress(); await controller.continueAcquisition();
  expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(2);
});

it('requests independent approval for an exact recording review and resumes its original intent after expiry', async () => {
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
