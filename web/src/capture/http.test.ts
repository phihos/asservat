import { afterEach, expect, it, vi } from 'vitest';
import { operations, OperationFailure } from './http';
import { id, result, previewResult, recordingPreviewResult, settingsResult, acceptedResult, progressResult, target } from './test-fixtures';
import { validInput_preview_capture, validInput_request_capture, validOutput_preview_capture, validOutput_get_capture } from '../generated/validate-capture';

afterEach(() => vi.unstubAllGlobals());
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('accepts canonical recording extracts and a fixed bounded browser settings response', async () => {
  const settings = settingsResult();
  if (settings.status !== 'ok') throw new Error('fixture');
  if (!('recipe_spec' in settings.data.settings)) throw new Error('fixture settings');
  Object.assign(settings.data.settings, { recipe_spec: { description: '<é>&', actions: [{ id: 'command', kind: 'command', parameters: { argv: Array.from({ length: 30 }, () => 'a'.repeat(4096)), workingDirectory: '/', adapter: 'podsExec' }, required: true, impact: 'intrusive', limits: { maxBytes: 4096, timeout: '5s' }, executionMode: 'onTrigger' }], maxTotalBytes: 4096, maxDuration: '5s' } });
  expect(new TextEncoder().encode(JSON.stringify(settings)).length).toBeGreaterThan(120 * 1024);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(settings)));
  expect(await operations.call('get_capture', { capture_id: id(41), view: 'settings' }, 'csrf', new AbortController().signal)).toEqual(settings);
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(recordingPreviewResult())));
  await expect(operations.call('preview_capture', { target_ref: target, preset_ref: { name: 'pod-status', version: 'v1' } }, 'csrf', new AbortController().signal)).resolves.toBeDefined();
});
it('refuses larger settings and client-selected response budgets', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(' '.repeat(160 * 1024 + 1), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await expect(operations.call('get_capture', { capture_id: id(41), view: 'settings' }, 'csrf', new AbortController().signal)).rejects.toThrow();
  fetcher.mockClear();
  await expect(operations.call('get_capture', { capture_id: id(41), view: 'settings', response_budget: 999999 } as never, 'csrf', new AbortController().signal)).rejects.toThrow();
  expect(fetcher).not.toHaveBeenCalled();
});
it('uses canonical finite retention and exact whole-pod preview validation', () => {
  const input = { target_ref: { cluster: 'local', namespace: 'payments', kind: 'Pod', name: 'api' }, preset_ref: { name: 'pod-status', version: 'v1' } };
  expect(validInput_preview_capture(input)).toBe(true);
  for (const requested_retention_seconds of [1, 3600, 315360001]) expect(validInput_preview_capture({ ...input, requested_retention_seconds })).toBe(true);
  for (const requested_retention_seconds of [0, -1, 0.5, null, true, '3600']) expect(validInput_preview_capture({ ...input, requested_retention_seconds })).toBe(false);
  expect(validInput_preview_capture({ history_capture_id: id(1), requested_retention_seconds: 60 })).toBe(false);
  const reviewed = { preview: input, expected_plan_digest: 'b'.repeat(64), idempotency_key: id(3) };
  expect(validInput_request_capture(reviewed)).toBe(true);
  for (const extra of [{ requested_retention_seconds: 60 }, { preview_id: id(2) }, { continue_acquisition: true }]) expect(validInput_request_capture({ ...reviewed, ...extra })).toBe(false);
  expect(validInput_request_capture({ preview: input, idempotency_key: id(3) })).toBe(false);
  const preview = previewResult(); expect(validOutput_preview_capture(preview)).toBe(true);
  if (preview.status !== 'ok') throw new Error('fixture');
  const wrongAnchor = structuredClone(preview);
  wrongAnchor.data.capture_assessment.actions[0].retention.anchorRule = 'firstAcquisitionOrEarlierSource';
  expect(validOutput_preview_capture(wrongAnchor)).toBe(false);
  preview.data.selected_pods!.push(structuredClone(preview.data.selected_pods![0]));
  expect(validOutput_preview_capture(preview)).toBe(false);
  expect(validOutput_get_capture(progressResult('Finalizing'))).toBe(true);
});
it('sends same-origin CSRF and identical idempotency header without automatic replay', async () => {
  const fetcher = vi.fn().mockResolvedValue(json(acceptedResult())); vi.stubGlobal('fetch', fetcher);
  const body = { preview: { target_ref: target, preset_ref: { name: 'pod-status' as const, version: 'v1' as const } }, expected_plan_digest: 'b'.repeat(64), idempotency_key: id(3) };
  await operations.call('request_capture', body, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/request_capture');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', body: JSON.stringify(body), headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});
it.each([
  () => new Response('<html>private provider error</html>', { headers: { 'Content-Type': 'text/html' } }),
  () => json({ ...progressResult(), extra: 'unexpected' }),
  () => json({ ...progressResult(), data_class: 'raw' }),
  () => json({ ...progressResult(), truncated: true, narrowing_hint: 'more' }),
  () => new Response(' '.repeat(160 * 1024 + 1), { headers: { 'Content-Type': 'application/json' } }),
  () => new Response(new Uint8Array([0xc3, 0x28]), { headers: { 'Content-Type': 'application/json' } }),
])('rejects malformed, oversized or nonmetadata responses', async response => {
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => response()));
  await expect(operations.call('get_capture', { capture_id: id(8) }, 'csrf', new AbortController().signal)).rejects.toThrow();
});
it('does not expose an upstream error body and aborts on scope loss', async () => {
  const scope = new AbortController();
  vi.stubGlobal('fetch', vi.fn().mockImplementation(async (_path, options) => {
    scope.abort(); expect(options.signal.aborted).toBe(true); return new Response('secret', { status: 503 });
  }));
  await expect(operations.call('get_capture', { capture_id: id(8) }, 'csrf', scope.signal)).rejects.toEqual(new OperationFailure(503));
});

it('accepts a durable cancellation request without treating the capture as terminal', async () => {
  const progress = progressResult('Finalizing');
  if (progress.status !== 'ok') throw new Error('fixture');
  progress.data.cancellation_requested = true;
  expect(validOutput_get_capture(progress)).toBe(true);
  expect(validOutput_get_capture({ ...progress, data: { ...progress.data, cancellation_requested: 'true' } })).toBe(false);
  const fetcher = vi.fn().mockResolvedValue(json(progress)); vi.stubGlobal('fetch', fetcher);
  const response = await operations.call('get_capture', { capture_id: id(8) }, 'csrf', new AbortController().signal);
  expect(response).toEqual(progress);
  if (response.status === 'ok') expect(response.data.phase).toBe('Running');
});

it('sends cancellation only to the parent with matching CSRF and stable request identity', async () => {
 const response=result<'cancel_capture'>({capture_id:id(8),revision:3,phase:'Running',cancellation_requested:true,navigation_uri:'https://asservat.invalid/captures/'+id(8)});
 const fetcher=vi.fn().mockResolvedValue(json(response));vi.stubGlobal('fetch',fetcher);
 const input={capture_id:id(8),expected_revision:2,idempotency_key:id(9)};
 expect(await operations.call('cancel_capture',input,'C'.repeat(43),new AbortController().signal)).toEqual(response);
 expect(fetcher).toHaveBeenCalledOnce();expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/cancel_capture');
 expect(fetcher.mock.calls[0][1]).toMatchObject({body:JSON.stringify(input),credentials:'same-origin',headers:{'X-CSRF-Token':'C'.repeat(43),'Idempotency-Key':id(9)}});
});
it('requires all grouped action identity fields without rejecting repeated configured action IDs', () => {
 const response=progressResult('Finalizing');if(response.status!=='ok')throw new Error();response.data.operation='recordingSave';
 response.data.actions=[{action_id:'traffic',action_instance_id:id(101),pod_uid:'pod-a',pod_name:'api-a',phase:'Succeeded'},{action_id:'traffic',action_instance_id:id(102),pod_uid:'pod-b',pod_name:'api-b',phase:'Cancelled'}];
 expect(validOutput_get_capture(response)).toBe(true);
 const missing=structuredClone(response);delete (missing.data as {actions:{pod_uid?:string}[]}).actions[1].pod_uid;expect(validOutput_get_capture(missing)).toBe(false);
});
it('never cancels a fully read response body, only an unfinished one', async () => {
  // Cancelling a finished stream can abort the request in Chromium before its
  // load completes; only an over-limit read is cancelled.
  const cancelled = vi.spyOn(ReadableStreamDefaultReader.prototype, 'cancel');
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(recordingPreviewResult())));
  await operations.call('preview_capture', { target_ref: target, preset_ref: { name: 'pod-status', version: 'v1' } }, 'csrf', new AbortController().signal);
  expect(cancelled).not.toHaveBeenCalled();
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(' '.repeat(160 * 1024 + 1), { headers: { 'Content-Type': 'application/json' } })));
  await expect(operations.call('get_capture', { capture_id: id(41), view: 'settings' }, 'csrf', new AbortController().signal)).rejects.toThrow();
  expect(cancelled).toHaveBeenCalled();
  cancelled.mockRestore();
});

it('allows the accepted fifteen-second preview composition without replay', async () => {
  vi.useFakeTimers();
  try {
    let requestSignal: AbortSignal | undefined;
    const fetcher = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((resolve, reject) => {
      requestSignal = init.signal as AbortSignal;
      requestSignal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
      setTimeout(() => resolve(json(previewResult())), 12_000);
    }));
    vi.stubGlobal('fetch', fetcher);
    const pending = operations.call('preview_capture', { target_ref: target, preset_ref: { name: 'pod-status', version: 'v1' } }, 'csrf', new AbortController().signal);
    const outcome = pending.then(value => ({ value }), error => ({ error }));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(requestSignal?.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await outcome).toHaveProperty('value');
    expect(fetcher).toHaveBeenCalledOnce();
  } finally { vi.useRealTimers(); }
});

it('keeps ordinary capture reads at ten seconds and honors original caller cancellation', async () => {
  vi.useFakeTimers();
  try {
    for (const mode of ['ordinary', 'cancel-preview'] as const) {
      let requestSignal: AbortSignal | undefined;
      const fetcher = vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
        requestSignal = init.signal as AbortSignal;
        requestSignal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
      }));
      vi.stubGlobal('fetch', fetcher);
      const caller = new AbortController();
      const pending = mode === 'ordinary'
        ? operations.call('get_capture', { capture_id: id(1) }, 'csrf', caller.signal)
        : operations.call('preview_capture', { target_ref: target, preset_ref: { name: 'pod-status', version: 'v1' } }, 'csrf', caller.signal);
      const outcome = pending.then(() => 'delivered', () => 'aborted');
      if (mode === 'ordinary') await vi.advanceTimersByTimeAsync(10_000);
      else caller.abort();
      expect(await outcome).toBe('aborted');
      expect(requestSignal?.aborted).toBe(true);
      expect(fetcher).toHaveBeenCalledOnce();
    }
  } finally { vi.useRealTimers(); }
});
