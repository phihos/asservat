import { afterEach, expect, it } from 'vitest';
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
