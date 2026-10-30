import { afterEach, expect, it, vi } from 'vitest';
import { operations } from './http';
import { inventoryResult, savePreviewResult, recording } from './test-fixtures';
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

it('reads all16 source disclosures within the dedicated preview bound and refuses one byte over', async () => {
 const rows=Array.from({length:16},(_,i)=>({...recording(i+1),recording_handle:'h'.repeat(125)+String(i).padStart(3,'0'),pod_uid:'u'.repeat(125)+String(i).padStart(3,'0'),pod_name:'n'.repeat(60)+String(i).padStart(3,'0'),action_id:'a'.repeat(63),policy_uid:'p'.repeat(64),incident_pod_cap:16}));
 const preview=savePreviewResult(rows);if(preview.status!=='ok')throw new Error();const base=preview.data.capture_assessment.actions[0];preview.data.incident_pod_cap=16;preview.data.capture_assessment.scope.incidentPods=16;
 preview.data.capture_assessment.actions=rows.map(row=>({...structuredClone(base),recording_handle:row.recording_handle,actionID:row.action_id,retention:{...base.retention,policyDigests:Array.from({length:64},(_,n)=>(n+1).toString(16).padStart(64,'0'))}}));
 const body=JSON.stringify(preview);expect(new TextEncoder().encode(body).length).toBeGreaterThan(64*1024);expect(validators.validOutput_preview_recording_save(preview)).toBe(true);
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json(preview)));const response=await operations.call('preview_recording_save',{recording_handles:rows.map(row=>row.recording_handle)},'csrf',new AbortController().signal);if(response.status!=='ok')throw new Error();expect(response.data.selected_recordings).toHaveLength(16);expect(response.data.capture_assessment.actions.every(row=>row.retention.policyDigests.length===64)).toBe(true);
 const exact=body+' '.repeat(128*1024-new TextEncoder().encode(body).length);
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(exact+' ',{headers:{'Content-Type':'application/json'}})));await expect(operations.call('preview_recording_save',{recording_handles:rows.map(row=>row.recording_handle)},'csrf',new AbortController().signal)).rejects.toThrow();
 vi.stubGlobal('fetch',vi.fn().mockResolvedValue(json(preview)));await expect(operations.call('list_recordings',{target_ref:target},'csrf',new AbortController().signal)).rejects.toThrow();
});
