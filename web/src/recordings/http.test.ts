import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { inventoryResult, savePreviewResult } from './test-fixtures';
import { target } from '../capture/test-fixtures';
import * as validators from '../generated/validate-recordings';
afterEach(() => vi.unstubAllGlobals());
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('uses the same-origin canonical passive operations with CSRF and bounded cursors', async () => {
  const fetcher = vi.fn().mockResolvedValue(json(inventoryResult(undefined, 'opaque-next'))); vi.stubGlobal('fetch', fetcher);
  const input = { target_ref: target, limit: 20 };
  const response = await operations.call('list_recordings', input, 'csrf', new AbortController().signal);
  expect(response.next_cursor).toBe('opaque-next');
  expect(fetcher.mock.calls[0]).toEqual(['/api/v1/operations/list_recordings', expect.objectContaining({ credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: expect.objectContaining({ 'X-CSRF-Token': 'csrf' }), body: JSON.stringify(input) })]);
  fetcher.mockResolvedValue(json(savePreviewResult()));
  await operations.call('preview_recording_save', { recording_handles: ['source-1'] }, 'csrf', new AbortController().signal);
  expect(fetcher.mock.calls[1][0]).toBe('/api/v1/operations/preview_recording_save');
});
it('rejects future windows, client-chosen sources and untyped coverage before I/O or display', async () => {
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  for (const extra of [{ after: '1s' }, { executor: 'forged' }, { recipe: 'dump' }, { t0: new Date().toISOString() }]) {
    await expect(operations.call('preview_recording_save', { recording_handles: ['source-1'], ...extra } as never, 'csrf', new AbortController().signal)).rejects.toThrow();
  }
  expect(fetcher).not.toHaveBeenCalled();
  expect(validators.validOutput_list_recordings(inventoryResult())).toBe(true);
  const changed = inventoryResult(); if (changed.status !== 'ok') throw new Error('fixture');
  Object.assign(changed.data.recordings[0], { observed_packets: ['payload'] });
  expect(validators.validOutput_list_recordings(changed)).toBe(false);
});
it('rejects oversized metadata and redirected or raw responses without exposing upstream text', async () => {
  for (const response of [new Response(' '.repeat(32769), { headers: { 'Content-Type': 'application/json' } }), json({ ...inventoryResult(), data_class: 'raw' }), new Response('private detail', { status: 503 })]) {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
    await expect(operations.call('list_recordings', { target_ref: target }, 'csrf', new AbortController().signal)).rejects.toThrow();
  }
});
