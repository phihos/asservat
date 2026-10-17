import { afterEach, expect, it, vi } from 'vitest';
import { Evidence } from './evidence';
import { SyntheticEvidence, session, id, caseResult, downloadResult } from './test-fixtures';
const controllers: Evidence[] = [];
afterEach(() => { for (const c of controllers) c.reset(); controllers.length = 0; vi.useRealTimers(); });
async function ready() {
  const client = new SyntheticEvidence(); let sequence = 100; const newID = vi.fn(() => id(++sequence));
  const controller = new Evidence(client, newID); controllers.push(controller);
  const scope = new AbortController(); controller.attach(session, scope.signal, id(2));
  await vi.waitFor(() => expect(controller.snapshot().details).toBeTruthy());
  return { client, controller, scope, newID };
}
it('reads only the exact case and does not prepare or fetch bytes implicitly', async () => {
  const { controller, client, newID } = await ready();
  expect(client.calls.map(c => c.name)).toEqual(['get_case']); expect(newID).not.toHaveBeenCalled();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(client.calls.at(-1)!.input).toEqual({ artifact_id: id(3), idempotency_key: id(101) });
  expect(controller.snapshot().download?.state).toBe('Preparing'); expect(controller.canStart()).toBe(false);
  await controller.checkDownload(); expect(controller.canStart()).toBe(true);
  controller.startDownload(); expect(controller.snapshot().started).toBe(true);
  expect(client.calls.map(c => c.name)).toEqual(['get_case', 'prepare_artifact_download', 'get_artifact_download']);
});
it('retains the same preparation key after unknown replies and same-user refresh', async () => {
  const { controller, client, scope, newID } = await ready();
  client.responder = () => { throw new Error('lost prepare commit'); }; await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.snapshot().uncertain).toBe(true);
  scope.abort(); client.responder = name => name === 'get_case' ? caseResult() : downloadResult('Preparing');
  controller.attach(session, new AbortController().signal, id(2));
  await vi.waitFor(() => expect(controller.snapshot().details).toBeTruthy());
  await controller.retryPreparation();
  const calls = client.calls.filter(c => c.name === 'prepare_artifact_download');
  expect(calls).toHaveLength(2); expect(calls[0].input).toEqual(calls[1].input); expect(newID).toHaveBeenCalledOnce();
});
it('rejects a substituted case or download, foreign path and invented preparing metadata', async () => {
  const { controller, client } = await ready();
  const original = controller.snapshot().details!.artifacts[0];
  const badCase = caseResult(); if (badCase.status !== 'ok') throw new Error(); badCase.data.case.case_id = id(9);
  client.responder = () => badCase; await controller.refresh(); expect(controller.snapshot().details).toBeUndefined();
  client.responder = () => caseResult(); await controller.refresh();
  for (const mutation of [
    (d: ReturnType<typeof downloadResult>) => { if (d.status === 'ok') d.data.artifact_id = id(9); },
    (d: ReturnType<typeof downloadResult>) => { if (d.status === 'ok') d.data.content_path = `/api/v1/downloads/${id(9)}/content`; },
    (d: ReturnType<typeof downloadResult>) => { if (d.status === 'ok') d.data.state = 'Preparing'; },
  ]) {
    const result = downloadResult(); mutation(result); client.responder = () => result;
    if (!controller.snapshot().preparingArtifact) await controller.prepare(original); else await controller.retryPreparation();
    expect(controller.snapshot().download).toBeUndefined(); expect(controller.canStart()).toBe(false);
  }
});
it('keeps cancellation uncertain, blocks delivery, and retries the original cancellation key', async () => {
  const { controller, client } = await ready();
  client.responder = () => downloadResult(); await controller.prepare(controller.snapshot().details!.artifacts[0]);
  client.responder = () => { throw new Error('lost cancel'); }; await controller.cancel();
  expect(controller.snapshot().cancelling).toBe(true); expect(controller.canStart()).toBe(false);
  client.responder = () => downloadResult(); await controller.checkDownload(); expect(controller.canStart()).toBe(false);
  client.responder = () => downloadResult('Cancelled'); await controller.cancel();
  const calls = client.calls.filter(c => c.name === 'cancel_artifact_download');
  expect(calls).toHaveLength(2); expect(calls[0].input).toEqual(calls[1].input);
  expect(controller.snapshot().download?.state).toBe('Cancelled');
  controller.newDownload(); expect(controller.snapshot().preparingArtifact).toBeUndefined();
  expect(client.calls.filter(c => c.name === 'prepare_artifact_download')).toHaveLength(1);
});
it('does not revive a terminal session on a later status reply', async () => {
  const { controller, client } = await ready(); client.responder = () => downloadResult('Completed');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  client.responder = () => downloadResult(); await controller.checkDownload();
  expect(controller.canStart()).toBe(false); expect(controller.snapshot().download).toBeUndefined();
});
it('withholds content on local expiry and clears protected results after scope cancellation', async () => {
  const { controller, client, scope } = await ready();
  const result = downloadResult(); if (result.status !== 'ok') throw new Error(); result.data.expires_at = new Date(Date.now() - 1).toISOString();
  client.responder = () => result; await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.canStart()).toBe(false);
  scope.abort(); expect(controller.snapshot().details).toBeUndefined(); expect(controller.snapshot().download).toBeUndefined();
});
it('discards late preparation after scope loss and resets receipts for another identity', async () => {
  const { controller, client, scope } = await ready(); let reply!: (v: unknown) => void;
  client.responder = () => new Promise(r => { reply = r; });
  const pending = controller.prepare(controller.snapshot().details!.artifacts[0]);
  scope.abort(); reply(downloadResult()); await pending;
  expect(controller.snapshot().download).toBeUndefined(); expect(controller.snapshot().uncertain).toBe(true);
  client.responder = () => caseResult();
  controller.attach({ ...session, principal: { ...session.principal, subject_id: 'other' } }, new AbortController().signal, id(2));
  expect(controller.snapshot().preparingArtifact).toBeUndefined();
});

it('does not repeatedly poll a ready file while the developer is reading its metadata', async () => {
  const { controller, client } = await ready(); vi.useFakeTimers(); client.responder = () => downloadResult();
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  const before = client.calls.length; await vi.advanceTimersByTimeAsync(15_000);
  expect(client.calls).toHaveLength(before); expect(controller.canStart()).toBe(true);
  controller.startDownload(); await vi.advanceTimersByTimeAsync(2_001);
  expect(client.calls.filter(c => c.name === 'get_artifact_download')).toHaveLength(1);
});

it('bounds distant expiry timers and removes them on scope loss', async () => {
  vi.useFakeTimers();
  const client = new SyntheticEvidence(); const result = caseResult(); if (result.status !== 'ok') throw new Error();
  result.data.artifacts[0].expires_at = result.data.artifacts[0].handling_notice.expiresAt = new Date(Date.now() + 60 * 86400_000).toISOString();
  result.data.artifacts[0].handling_notice.deleteBy = new Date(Date.now() + 61 * 86400_000).toISOString();
  client.responder = () => result;
  const controller = new Evidence(client); controllers.push(controller); const scope = new AbortController();
  controller.attach(session, scope.signal, id(2)); await vi.advanceTimersByTimeAsync(0);
  expect(vi.getTimerCount()).toBe(1);
  await vi.advanceTimersByTimeAsync(2_147_483_647);
  expect(client.calls).toHaveLength(1); expect(vi.getTimerCount()).toBe(1);
  scope.abort(); expect(vi.getTimerCount()).toBe(0); expect(controller.snapshot().details).toBeUndefined();
});


it.each([true, false])('bounds terminal status by the existing managed read interval when native metadata is present=%s', async includeMetadata => {
  const { controller, client } = await ready(); vi.useFakeTimers();
  const result = downloadResult('Completed'); if (result.status !== 'ok') throw new Error();
  result.data.expires_at = new Date(Date.now() - 1000).toISOString();
  result.data.managed_read_until = new Date(Date.now() + 1000).toISOString();
  if (!includeMetadata) for (const field of ['filename', 'native_format', 'size_bytes', 'sha256', 'etag', 'coverage_notice'] as const) delete result.data[field];
  client.responder = name => { if (name === 'get_artifact_download') throw new Error('metadata access expired'); return result; };
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.snapshot().download?.state).toBe('Completed'); expect(controller.canStart()).toBe(false);
  expect(controller.snapshot().download?.sha256).toBe(includeMetadata ? 'a'.repeat(64) : undefined);
  await vi.advanceTimersByTimeAsync(1001);
  expect(controller.snapshot().download).toBeUndefined();
  expect(client.calls.map(c => c.name)).toEqual(['get_case', 'prepare_artifact_download', 'get_artifact_download']);
  await vi.advanceTimersByTimeAsync(60_000);
  expect(client.calls).toHaveLength(3);
});

it('continues only acknowledged Preparing on the original key and stops on unknown outcome', async () => {
 const { controller, client } = await ready(); vi.useFakeTimers();
 const preparing = downloadResult('Preparing'); if (preparing.status !== 'ok') throw new Error();
 Object.assign(preparing.data, { continue_preparation: true });
 client.responder = () => preparing; await controller.prepare(controller.snapshot().details!.artifacts[0]);
 await vi.advanceTimersByTimeAsync(2_001);
 let calls = client.calls.filter(c => c.name === 'prepare_artifact_download');
 expect(calls).toHaveLength(2); expect(calls[0].input).toEqual(calls[1].input);
 client.responder = () => { throw new Error('unknown continuation'); };
 await vi.advanceTimersByTimeAsync(2_001); const length = client.calls.length;
 await vi.advanceTimersByTimeAsync(20_000); expect(client.calls).toHaveLength(length);
 expect(controller.snapshot().uncertain).toBe(true); expect(controller.canCancel()).toBe(true);
});
it('passive status cannot authorize preparation and cancellation stops continuation', async () => {
 const { controller, client } = await ready(); vi.useFakeTimers();
 const preparing = downloadResult('Preparing'); if (preparing.status !== 'ok') throw new Error();
 client.responder = () => preparing; await controller.prepare(controller.snapshot().details!.artifacts[0]);
 Object.assign(preparing.data, { continue_preparation: true });
 await controller.checkDownload(); expect(controller.snapshot().download).toBeUndefined();
 await vi.advanceTimersByTimeAsync(20_000);
 expect(client.calls.filter(c => c.name === 'prepare_artifact_download')).toHaveLength(1);
 client.responder = () => preparing; await controller.retryPreparation();
 client.responder = () => { throw new Error('unknown stop'); }; await controller.cancel();
 const length = client.calls.length; await vi.advanceTimersByTimeAsync(20_000);
 expect(client.calls).toHaveLength(length); expect(controller.canStart()).toBe(false);
});
it('accepts a minimal stop receipt without revealing native or terminal artifact metadata', async () => {
 const { controller, client } = await ready(); vi.useFakeTimers();
 client.responder = () => downloadResult(); await controller.prepare(controller.snapshot().details!.artifacts[0]);
 client.responder = () => ({ schema_version: 'mcp-result/v1', request_id: id(20), data_class: 'metadata', status: 'ok', warnings: [], provenance: [], data: { download_id: id(4), state: 'AlreadyTerminal', audit_state: 'pending' } });
 await controller.cancel();
 expect(controller.snapshot().cancellation?.state).toBe('AlreadyTerminal');
 expect(controller.snapshot().download).toBeUndefined(); expect(controller.canCancel()).toBe(false); expect(controller.canStart()).toBe(false);
 const before = client.calls.length; await vi.advanceTimersByTimeAsync(60_001);
 expect(controller.snapshot().cancellation).toBeUndefined(); expect(client.calls).toHaveLength(before);
});

it('starts a new browser download only after acknowledged Stop and retains both keys through lost replies', async () => {
  const { controller, client, newID } = await ready();
  client.responder = () => downloadResult('Interrupted');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  expect(controller.canRestart()).toBe(true);
  client.responder = () => { throw new Error('lost Stop reply'); };
  await controller.restartDownload();
  const firstStop = client.calls.at(-1)!;
  expect(firstStop.name).toBe('cancel_artifact_download');
  expect(client.calls.filter(c => c.name === 'prepare_artifact_download')).toHaveLength(1);
  expect(controller.canStart()).toBe(false);
  client.responder = name => {
    if (name === 'cancel_artifact_download') return downloadResult('Cancelled');
    throw new Error('lost new prepare reply');
  };
  await controller.restartDownload();
  const stops = client.calls.filter(c => c.name === 'cancel_artifact_download');
  expect(stops).toHaveLength(2); expect(stops[1].input).toEqual(firstStop.input);
  const prepares = client.calls.filter(c => c.name === 'prepare_artifact_download');
  expect(prepares).toHaveLength(2); expect(prepares[1].input).not.toEqual(prepares[0].input);
  expect(controller.snapshot().uncertain).toBe(true); expect(controller.canRestart()).toBe(false);
  const next = downloadResult('Ready');
  if (next.status !== 'ok') throw new Error();
  next.data.download_id = id(5); next.data.content_path = `/api/v1/downloads/${id(5)}/content`;
  client.responder = () => next;
  await controller.retryPreparation();
  expect(client.calls.at(-1)!.input).toEqual(prepares[1].input);
  expect(newID).toHaveBeenCalledTimes(3);
  expect(controller.snapshot().download?.download_id).toBe(id(5)); expect(controller.canStart()).toBe(true);
});

it.each(['pending', 'foreign'] as const)('does not prepare a replacement after %s Stop result', async disposition => {
  const { controller, client } = await ready();
  client.responder = () => downloadResult('Interrupted');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  const stop = downloadResult(disposition === 'pending' ? 'Interrupted' : 'Cancelled');
  if (stop.status !== 'ok') throw new Error();
  if (disposition === 'foreign') stop.data.download_id = id(8);
  client.responder = () => stop;
  await controller.restartDownload();
  expect(client.calls.filter(c => c.name === 'prepare_artifact_download')).toHaveLength(1);
  expect(controller.canStart()).toBe(false); expect(controller.snapshot().error).toContain('not been confirmed stopped');
});

it('accepts a minimal restrictive Stop receipt without inventing artifact metadata', async () => {
  const { controller, client } = await ready();
  client.responder = () => downloadResult('Interrupted');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  client.responder = name => name === 'cancel_artifact_download'
    ? { schema_version: 'mcp-result/v1', request_id: id(30), data_class: 'metadata', status: 'ok', warnings: [], provenance: [], data: { download_id: id(4), state: 'AlreadyTerminal', audit_state: 'pending' } }
    : downloadResult('Preparing');
  await controller.restartDownload();
  expect(client.calls.map(c => c.name)).toEqual(['get_case', 'prepare_artifact_download', 'cancel_artifact_download', 'prepare_artifact_download']);
  expect(controller.snapshot().download?.state).toBe('Preparing');
  expect(controller.snapshot().download?.filename).toBeUndefined();
});

it('does not prepare after scope loss while waiting for Stop', async () => {
  const { controller, client, scope } = await ready();
  client.responder = () => downloadResult('Interrupted');
  await controller.prepare(controller.snapshot().details!.artifacts[0]);
  let finish!: (result: unknown) => void;
  client.responder = () => new Promise(resolve => { finish = resolve; });
  const stopped = controller.restartDownload();
  scope.abort(); finish(downloadResult('Cancelled')); await stopped;
  expect(client.calls.filter(c => c.name === 'prepare_artifact_download')).toHaveLength(1);
  expect(controller.snapshot().download).toBeUndefined();
});

it('keeps the chosen new request after an unknown Stop is confirmed by later terminal status', async () => {
 const {controller,client,newID}=await ready();
 client.responder=()=>downloadResult('Interrupted');await controller.prepare(controller.snapshot().details!.artifacts[0]);
 client.responder=()=>{throw new Error('lost Stop reply');};await controller.restartDownload();
 const oldStop=client.calls.at(-1)!.input;
 client.responder=()=>downloadResult('Cancelled');await controller.checkDownload();
 expect(controller.canRestart()).toBe(true);
 client.responder=name=>name==='cancel_artifact_download'?downloadResult('Cancelled'):downloadResult('Preparing');
 await controller.restartDownload();
 expect(client.calls.filter(c=>c.name==='cancel_artifact_download').at(-1)!.input).toEqual(oldStop);
 expect(newID).toHaveBeenCalledTimes(3);
 expect(client.calls.filter(c=>c.name==='prepare_artifact_download')).toHaveLength(2);
});
