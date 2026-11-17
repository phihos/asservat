import { afterEach, expect, it, vi } from 'vitest';
import { Evidence } from './evidence';
import { SyntheticEvidence, session, id, caseResult, downloadResult, failure, cancelled } from './test-fixtures';
const controllers: Evidence[] = [];
afterEach(() => { for (const c of controllers) c.reset(); controllers.length = 0; vi.useRealTimers(); });
async function ready() {
  const client = new SyntheticEvidence(); let sequence = 100; const newID = vi.fn(() => id(++sequence));
  const controller = new Evidence(client, newID); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, id(2));
  await vi.waitFor(() => expect(controller.snapshot().details).toBeTruthy());
  return { client, controller, scope, newID };
}
const actions = (client: SyntheticEvidence) => client.calls.filter(c => c.name === 'download_artifact').map(c => (c.input as { action: string }).action);
it('reads only the exact case and prepares only on request', async () => {
  const { controller, client, newID } = await ready();
  expect(client.calls.map(c => c.name)).toEqual(['get_case']); expect(newID).not.toHaveBeenCalled();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(client.calls.at(-1)!.input).toEqual({ action: 'prepare', artifact_id: id(3), idempotency_key: id(101) });
  expect(controller.snapshot().download?.state).toBe('Ready'); expect(controller.canStart()).toBe(true);
  controller.startDownload(); expect(controller.snapshot().started).toBe(true);
  expect(actions(client)).toEqual(['prepare']);
});
it('repeats prepare with the same key while the file is prepared', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const { controller, client } = await ready();
  let first = true;
  client.responder = (name, input) => name === 'get_case' ? caseResult() : first ? (first = false, failure('RetryLater', 'Preparing.', true)) : downloadResult();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.snapshot().download).toBeUndefined();
  await vi.advanceTimersByTimeAsync(1_000);
  await vi.waitFor(() => expect(controller.snapshot().download?.state).toBe('Ready'));
  const prepares = client.calls.filter(c => (c.input as { action: string }).action === 'prepare');
  expect(prepares).toHaveLength(2); expect(prepares[0].input).toEqual(prepares[1].input);
});
it('retains the same preparation key after unknown replies and same-user refresh', async () => {
  const { controller, client, scope, newID } = await ready();
  client.responder = () => { throw new Error('lost prepare commit'); }; await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.snapshot().uncertain).toBe(true);
  scope.abort(); client.responder = name => name === 'get_case' ? caseResult() : downloadResult();
  controller.attach(session, new AbortController().signal, id(2));
  await vi.waitFor(() => expect(controller.snapshot().details).toBeTruthy());
  await controller.retryPreparation();
  const calls = client.calls.filter(c => c.name === 'download_artifact');
  expect(calls).toHaveLength(2); expect(calls[0].input).toEqual(calls[1].input); expect(newID).toHaveBeenCalledOnce();
});
it('rejects a substituted case, download or foreign content path', async () => {
  const { controller, client } = await ready();
  const original = controller.snapshot().details!.artifacts[0];
  const badCase = caseResult(); if (badCase.status !== 'ok') throw new Error(); badCase.data.case.case_id = id(9);
  client.responder = () => badCase; await controller.refresh(); expect(controller.snapshot().details).toBeUndefined();
  client.responder = () => caseResult(); await controller.refresh();
  for (const mutation of [
    (d: ReturnType<typeof downloadResult>) => { if (d.status === 'ok' && 'artifact_id' in d.data) d.data.artifact_id = id(9); },
    (d: ReturnType<typeof downloadResult>) => { if (d.status === 'ok' && 'artifact_id' in d.data) d.data.content_path = `/api/v1/downloads/${id(9)}/content`; },
  ]) {
    const result = downloadResult(); mutation(result); client.responder = () => result;
    if (!controller.snapshot().preparingArtifact) await controller.prepare(original); else await controller.retryPreparation();
    expect(controller.snapshot().download).toBeUndefined(); expect(controller.canStart()).toBe(false);
  }
});
it('opens the prefilled review when raw approval is required', async () => {
  const { controller, client } = await ready();
  client.responder = () => failure('RawApprovalRequired', 'Whole-file download needs independent approval.');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.snapshot().rawApprovalArtifact).toBe(id(3));
});
it('keeps cancellation uncertain, blocks delivery, and retries the original cancellation key', async () => {
  const { controller, client } = await ready();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  client.responder = () => { throw new Error('lost cancel'); }; await controller.cancel();
  expect(controller.snapshot().cancelling).toBe(true); expect(controller.canStart()).toBe(false);
  client.responder = () => downloadResult(); await controller.checkDownload(); expect(controller.canStart()).toBe(false);
  client.responder = () => cancelled(); await controller.cancel();
  const calls = client.calls.filter(c => (c.input as { action: string }).action === 'cancel');
  expect(calls).toHaveLength(2); expect(calls[0].input).toEqual(calls[1].input);
  expect(controller.snapshot().cancellation?.state).toBe('Cancelled');
  controller.newDownload(); expect(controller.snapshot().preparingArtifact).toBeUndefined();
});
it('shows an ended session and starts a new download with a fresh key', async () => {
  const { controller, client } = await ready();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  client.responder = () => failure('CapabilityUnavailable', 'This download session ended: Completed.');
  await controller.checkDownload();
  expect(controller.snapshot().ended).toContain('Completed'); expect(controller.canStart()).toBe(false); expect(controller.canCancel()).toBe(false);
  client.responder = () => downloadResult();
  await controller.restartDownload();
  const prepares = client.calls.filter(c => (c.input as { action: string }).action === 'prepare');
  expect(prepares).toHaveLength(2); expect(prepares[0].input).not.toEqual(prepares[1].input);
  expect(actions(client)).not.toContain('cancel');
  expect(controller.snapshot().download?.state).toBe('Ready');
});
it('stops the previous session before a restart', async () => {
  const { controller, client } = await ready();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  controller.startDownload();
  client.responder = (name, input) => (input as { action: string }).action === 'cancel' ? cancelled() : downloadResult();
  await controller.restartDownload();
  expect(actions(client)).toEqual(['prepare', 'cancel', 'prepare']);
});
it('discards late preparation after scope loss and resets receipts for another identity', async () => {
  const { controller, client, scope } = await ready();
  let release!: (value: unknown) => void;
  client.responder = () => new Promise(resolve => { release = resolve; });
  const pending = controller.prepare(controller.snapshot().details!.artifacts[0]);
  scope.abort(); release(downloadResult()); await pending;
  expect(controller.snapshot().download).toBeUndefined();
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other' } }, new AbortController().signal, id(2));
  expect(controller.snapshot().preparingArtifact).toBeUndefined();
});
