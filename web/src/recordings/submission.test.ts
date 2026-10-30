import { afterEach, expect, it, vi } from 'vitest';
import { Investigation } from '../capture/investigation';
import { SyntheticOperations, id, session, target, result, progressResult } from '../capture/test-fixtures';

const controllers: Investigation[] = [];
afterEach(() => { controllers.forEach(controller => controller.reset()); controllers.length = 0; window.history.replaceState(null, '', '/'); });
it('hands manual save to the same-key uncertain receipt and refuses another capture', async () => {
  const client = new SyntheticOperations(); let uncertain = true;
  client.responder = name => {
    if (name === 'request_capture') {
      if (uncertain) throw new Error('lost reply');
      return result<'request_capture'>({ capture_id: id(9), phase: 'Accepted', operation: 'recordingSave', navigation_uri: 'https://asservat.invalid/captures/' + id(9) });
    }
    return progressResult();
  };
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  controller.attach(session, new AbortController().signal); controller.setDraft({ target, retention: '' }); controller.showRecordings();
  await controller.submitRecordingSave(id(2), id(8), new Date(Date.now() + 60_000).toISOString());
  expect(controller.snapshot()).toMatchObject({ stage: 'uncertain' });
  uncertain = false; await controller.retrySubmission();
  const submitted = client.calls.filter(call => call.name === 'request_capture');
  expect(submitted).toHaveLength(2);
  expect(submitted[0].input).toEqual({ preview_id: id(2), idempotency_key: id(6) });
  expect(submitted[1].input).toEqual(submitted[0].input);
  expect(controller.snapshot()).toMatchObject({ stage: 'uncertain' });
  expect(controller.snapshot().error).toMatch(/outcome could not be verified/);
  expect(client.calls.some(call => call.name === 'preview_capture')).toBe(false);
});
it('opens only the exact saved capture and requires recordingSave progress', async () => {
  const client = new SyntheticOperations();
  client.responder = name => name === 'request_capture'
    ? result<'request_capture'>({ capture_id: id(8), phase: 'Accepted', operation: 'recordingSave', navigation_uri: 'https://asservat.invalid/captures/' + id(8) })
    : { ...progressResult('Finalizing'), data: { ...(progressResult('Finalizing').data), operation: 'recordingSave' } };
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  controller.attach(session, new AbortController().signal); controller.showRecordings();
  await controller.submitRecordingSave(id(2), id(8), new Date(Date.now() + 60_000).toISOString());
  expect(controller.snapshot()).toMatchObject({ stage: 'progress', captureID: id(8), progress: { operation: 'recordingSave', phase: 'Finalizing' } });
  expect(client.calls.map(call => call.name)).toEqual(['request_capture', 'get_capture']);
});
it('an expired save preview never creates a receipt or sends a capture request', async () => {
  const client = new SyntheticOperations(); const controller = new Investigation(client); controllers.push(controller);
  controller.attach(session, new AbortController().signal); controller.showRecordings();
  await controller.submitRecordingSave(id(2), id(8), new Date(Date.now() - 1).toISOString());
  expect(client.calls).toHaveLength(0); expect(controller.snapshot().stage).toBe('recordings');
});
it('history repeat restores only preferences and requires fresh source selection', async () => {
  const { readFileSync } = await import('node:fs');
  const name = 'mcp-recording-save-settings-result.json';
  const saved = JSON.parse(readFileSync(new URL('../../../examples/' + name, import.meta.url), 'utf8'));
  saved.data.expires_at = new Date(Date.now() + 60_000).toISOString();
  const client = new SyntheticOperations(); const base = client.responder;
  client.responder = name => name === 'get_capture_settings' ? saved : base(name);
  const controller = new Investigation(client); controllers.push(controller);
  controller.attach(session, new AbortController().signal); controller.setDraft({ target, retention: '' });
  await controller.showSettings(saved.data.capture_id); controller.selectRecordingsAgain(controller.snapshot().settings!);
  expect(controller.snapshot()).toMatchObject({ stage: 'recordings', recordingRepeat: { policyUID: saved.data.settings.policy.policyUID, captureID: saved.data.capture_id } });
  expect(client.calls.map(call => call.name)).toEqual(['get_capture_settings']);
  expect(JSON.stringify(controller.snapshot().recordingRepeat)).not.toMatch(/recording_handle|sharing|grant/);
});

it('cancels the grouped parent with one stable retry receipt and preserves stored children', async () => {
  const client = new SyntheticOperations(); let first = true; let requested = false; let joined = false;
  client.responder = name => {
    if (name === 'cancel_capture') { if (first) { first = false; throw new Error('lost reply'); } requested = true; return result<'cancel_capture'>({capture_id:id(8),revision:3,phase:'Running',cancellation_requested:true,navigation_uri:'https://asservat.invalid/captures/'+id(8)}); }
    return result<'get_capture'>({capture_id:id(8),revision:requested ? 3 : 2,operation:'recordingSave',phase:joined ? 'Partial' : 'Running',can_cancel:!requested,cancellation_requested:requested,blockers:[],case_id:id(50),navigation_uri:'https://asservat.invalid/captures/'+id(8),actions:[
      {action_id:'traffic',action_instance_id:id(101),pod_uid:'pod-a',pod_name:'api-a',phase:'Succeeded'},
      {action_id:'traffic',action_instance_id:id(102),pod_uid:'pod-b',pod_name:'api-b',phase:joined ? 'Cancelled' : 'Running'},
    ]});
  };
  const controller = new Investigation(client,()=>id(6)); controllers.push(controller); controller.attach(session,new AbortController().signal,id(8));
  await vi.waitFor(()=>expect(controller.snapshot().progress?.revision).toBe(2));
  await controller.cancelRecordingSave(); expect(controller.snapshot()).toMatchObject({cancellationStatus:'unconfirmed',progress:{phase:'Running'}});
  await controller.cancelRecordingSave(); expect(controller.snapshot()).toMatchObject({cancellationStatus:'requested',progress:{phase:'Running',case_id:id(50),actions:[{phase:'Succeeded'},{phase:'Running'}]}});
  const cancels=client.calls.filter(call=>call.name==='cancel_capture'); expect(cancels).toHaveLength(2);expect(cancels[0].input).toEqual({capture_id:id(8),expected_revision:2,idempotency_key:id(6)});expect(cancels[1].input).toEqual(cancels[0].input);
  expect(client.calls.every(call=>call.name==='cancel_capture'||call.name==='get_capture')).toBe(true);expect(client.calls.every(call=>!!call.input && typeof call.input === 'object' && 'capture_id' in call.input && call.input.capture_id===id(8))).toBe(true);
  joined=true;await controller.refreshProgress();expect(controller.snapshot()).toMatchObject({cancellationStatus:undefined,progress:{phase:'Partial',actions:[{phase:'Succeeded'},{phase:'Cancelled'}]}});
});
it('refuses duplicate child identities instead of collapsing grouped progress', async () => {
 const client=new SyntheticOperations();client.responder=()=>result<'get_capture'>({capture_id:id(8),revision:1,operation:'recordingSave',phase:'Running',can_cancel:false,blockers:[],navigation_uri:'https://asservat.invalid/captures/'+id(8),actions:[
 {action_id:'traffic',action_instance_id:id(101),pod_uid:'pod-a',pod_name:'api-a',phase:'Running'},
 {action_id:'traffic',action_instance_id:id(101),pod_uid:'pod-b',pod_name:'api-b',phase:'Running'},
 ]});const controller=new Investigation(client);controllers.push(controller);controller.attach(session,new AbortController().signal,id(8));await vi.waitFor(()=>expect(controller.snapshot().error).toMatch(/could not be verified/));expect(controller.snapshot().progress).toBeUndefined();
});
