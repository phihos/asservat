import { afterEach, expect, it, vi } from 'vitest';
import { waitFor } from '@testing-library/react';
import { Recordings } from './recordings';
import { SyntheticRecordings, inventoryResult, recording, savePreviewResult } from './test-fixtures';
import { session, target } from '../capture/test-fixtures';

const controllers: Recordings[] = [];
afterEach(() => { controllers.forEach(controller => controller.reset()); controllers.length = 0; vi.useRealTimers(); });
async function loaded(rows = [recording()]) {
  const client = new SyntheticRecordings();
  client.responder = name => name === 'list_recordings' ? inventoryResult(rows, 'opaque-next-page') : savePreviewResult(rows);
  const controller = new Recordings(client); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, target);
  await waitFor(() => expect(controller.snapshot().rows).toHaveLength(rows.length));
  return { client, controller, scope };
}
it('lists only actual server metadata, paginates with the original opaque cursor and never submits', async () => {
  const { client, controller } = await loaded();
  expect(client.calls[0]).toMatchObject({ name: 'list_recordings', input: { target_ref: target, limit: 20 }, csrf: session.csrf_token });
  expect(controller.snapshot().rows![0]).toMatchObject({ state: 'Unknown', history: 'Unknown' });
  await controller.load(controller.snapshot().cursor);
  expect(client.calls.at(-1)).toMatchObject({ name: 'list_recordings', input: { target_ref: target, cursor: 'opaque-next-page', limit: 20 } });
  expect(client.calls.every(call => call.name === 'list_recordings')).toBe(true);
});
it('refuses excess incident pods and mixed policies without dropping the selected source', async () => {
  const rows = [recording(), recording(2), { ...recording(3), policy_uid: 'other-policy' }];
  const { controller } = await loaded(rows);
  controller.select(rows[0], true); controller.select(rows[1], true);
  expect(controller.snapshot().selected).toEqual([rows[0]]);
  expect(controller.snapshot().error).toMatch(/at most 1 pod/);
  controller.select(rows[2], true);
  expect(controller.snapshot().selected).toEqual([rows[0]]);
  expect(controller.snapshot().error).toMatch(/one policy/);
});
it('sends only exact opaque handles and a shorter positive window, with no recipe, future window or inherited sharing', async () => {
  const { client, controller } = await loaded();
  controller.select(recording(), true); controller.setBefore('31s'); await controller.review();
  expect(client.calls).toHaveLength(1);
  controller.setBefore('0s'); await controller.review(); expect(client.calls).toHaveLength(1);
  controller.setBefore('10s');
  client.responder = () => { const value = savePreviewResult(); if (value.status === 'ok') value.data.windows[0].before = '10s'; return value; };
  await controller.review();
  expect(client.calls.at(-1)).toMatchObject({ name: 'preview_recording_save', input: { recording_handles: ['source-1'], before: '10s' } });
  expect(controller.submittable).toBe(true);
});
it('blocks changed source/window/digest reviews and disabled capture rather than submitting an alternative', async () => {
  const { client, controller } = await loaded(); controller.select(recording(), true);
  for (const mutate of [
    (value: ReturnType<typeof savePreviewResult>) => { if (value.status === 'ok') value.data.selected_recordings[0].pod_uid = 'replacement'; },
    (value: ReturnType<typeof savePreviewResult>) => { if (value.status === 'ok') value.data.windows[0].recording_handle = 'replacement'; },
    (value: ReturnType<typeof savePreviewResult>) => { if (value.status === 'ok') value.data.capture_assessment.planDigest = 'd'.repeat(64); },
  ]) {
    client.responder = () => { const value = savePreviewResult(); mutate(value); return value; };
    await controller.review(); expect(controller.submittable).toBe(false); expect(controller.snapshot().error).toMatch(/selection or window changed/);
  }
  client.responder = () => { const value = savePreviewResult(); if (value.status === 'ok') value.data.capture_enabled = false; return value; };
  await controller.review(); expect(controller.submittable).toBe(false);
});
it('clears selection and protected metadata at original expiry even after a failed preview', async () => {
  vi.useFakeTimers();
  const client = new SyntheticRecordings(); const controller = new Recordings(client); controllers.push(controller);
  controller.attach(session, new AbortController().signal, target);
  await vi.advanceTimersByTimeAsync(0); controller.select(recording(), true);
  client.responder = () => { throw new Error('unavailable'); };
  await controller.review(); await vi.advanceTimersByTimeAsync(60_001);
  expect(controller.snapshot()).toMatchObject({ expired: true, rows: undefined, selected: [], preview: undefined });
});
it('clears on scope loss and discards a late unabortable inventory reply', async () => {
  const client = new SyntheticRecordings(); let deliver!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { deliver = resolve; });
  const controller = new Recordings(client); controllers.push(controller); const scope = new AbortController();
  controller.attach(session, scope.signal, target); scope.abort(); deliver(inventoryResult());
  await Promise.resolve(); await Promise.resolve();
  expect(client.calls[0].signal.aborted).toBe(true);
  expect(controller.snapshot().rows).toBeUndefined(); expect(controller.snapshot().preview).toBeUndefined(); expect(controller.snapshot().selected).toEqual([]);
});
it('repeats with fresh policy inventory and carries only protected lineage into a new preview', async () => {
  const client = new SyntheticRecordings(); const controller = new Recordings(client); controllers.push(controller);
  controller.attach(session, new AbortController().signal, target, { policyUID: 'policy-1', captureID: 'old-capture', before: '30s' });
  await waitFor(() => expect(controller.snapshot().rows).toHaveLength(1));
  expect(client.calls[0].input).toEqual({ target_ref: target, limit: 20, policy_uid: 'policy-1' });
  controller.select(recording(), true); await controller.review();
  expect(client.calls[1].input).toEqual({ recording_handles: ['source-1'], before: '30s', repeated_from_capture_id: 'old-capture' });
});
it('an immediate save uses a fresh preview identity without another review when disclosures match', async () => {
  const { id } = await import('../capture/test-fixtures');
  const { client, controller } = await loaded(); controller.select(recording(), true); let generation = 0;
  client.responder = () => { const value = savePreviewResult(); if (value.status === 'ok') { value.data.preview_id = id(200 + ++generation); value.data.capture_id = id(300 + generation); } return value; };
  await controller.review(); const previous = controller.snapshot().preview!;
  const submit = vi.fn().mockResolvedValue(undefined); await controller.save(submit);
  expect(submit).toHaveBeenCalledWith(id(202), id(302), expect.any(String));
  expect(controller.snapshot().preview?.preview_id).not.toBe(previous.preview_id);
  expect(client.calls.map(call => call.name)).toEqual(['list_recordings', 'preview_recording_save', 'preview_recording_save']);
});
it('a changed handling disclosure stops immediate admission and leaves the new review visible', async () => {
  const { client, controller } = await loaded(); controller.select(recording(), true); await controller.review();
  client.responder = () => { const value = savePreviewResult(); if (value.status === 'ok') value.data.capture_assessment.actions[0].retention.accessAgeSeconds--; return value; };
  const submit = vi.fn(); await controller.save(submit);
  expect(submit).not.toHaveBeenCalled(); expect(controller.snapshot().preview).toBeDefined();
  expect(controller.snapshot().error).toMatch(/assessment changed/);
  expect(client.calls).toHaveLength(3);
});

it('preserves reason scalars verbatim, omits empty input and clears it on fresh repeat', async () => {
 const {client,controller,scope}=await loaded();controller.select(recording(),true);
 const reason='  \n'+ '🙂'.repeat(509);controller.setReason(reason);await controller.review();
 expect(client.calls.at(-1)).toMatchObject({name:'preview_recording_save',input:{reason}});
 controller.setReason('🙂'.repeat(513));const calls=client.calls.length;await controller.review();expect(client.calls).toHaveLength(calls);
 controller.setReason('');await controller.review();expect(client.calls.at(-1)!.input).not.toHaveProperty('reason');
 controller.setReason('old reason');controller.attach(session,scope.signal,target,{captureID:'old',policyUID:'policy'});
 expect(controller.snapshot().reason).toBeUndefined();
});
