import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RecordingsPanel } from './RecordingsPanel';
import { Recordings } from './recordings';
import { SyntheticRecordings, inventoryResult, recording, savePreviewResult } from './test-fixtures';
import { session, target, SyntheticOperations, result, id } from '../capture/test-fixtures';
import { CaptureWorkspace } from '../capture/CaptureWorkspace';
import { Investigation } from '../capture/investigation';

const controllers: Recordings[] = [];
afterEach(() => { cleanup(); controllers.forEach(controller => controller.reset()); controllers.length = 0; vi.unstubAllGlobals(); window.history.replaceState(null, '', '/'); });
it('shows unknown coverage and the real current cap before selection, then source-age assessment without another approval', async () => {
  const client = new SyntheticRecordings(); const controller = new Recordings(client); controllers.push(controller); const submit = vi.fn();
  render(<RecordingsPanel session={session} scope={new AbortController().signal} target={target} submit={submit} controller={controller}/>);
  expect(await screen.findByText(/Available history and gaps have not been measured/)).toBeTruthy();
  expect(screen.getByText(/Current incident limit: 1 pod/)).toBeTruthy();
  fireEvent.click(screen.getByRole('checkbox', { name: 'api-1 · traffic' }));
  await screen.findByRole('heading', { name: 'Save the selected history' });
  expect(screen.getByText(/Policy recurring sharing instructions are not inherited/)).toBeTruthy();
  expect(screen.getByText(/from original source acquisition/)).toBeTruthy();
  expect(submit).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Save last 30s now' }));
  const preview = savePreviewResult(); if (preview.status !== 'ok') throw new Error('fixture');
  await vi.waitFor(() => expect(submit).toHaveBeenCalledWith(preview.data.preview_id, preview.data.capture_id, expect.any(String)));
  expect(client.calls.map(call => call.name)).toEqual(['list_recordings', 'preview_recording_save', 'preview_recording_save']);
});
it('does not silently remove a selected pod to satisfy a cap', async () => {
  const client = new SyntheticRecordings(); client.responder = name => name === 'list_recordings' ? inventoryResult([recording(), recording(2)]) : savePreviewResult();
  const controller = new Recordings(client); controllers.push(controller);
  render(<RecordingsPanel session={session} scope={new AbortController().signal} target={target} submit={vi.fn()} controller={controller}/>);
  const first = await screen.findByRole('checkbox', { name: 'api-1 · traffic' });
  fireEvent.click(first); await screen.findByRole('heading', { name: 'Save the selected history' }); fireEvent.click(screen.getByRole('checkbox', { name: 'api-2 · traffic' }));
  expect((first as HTMLInputElement).checked).toBe(true);
  expect((screen.getByRole('checkbox', { name: 'api-2 · traffic' }) as HTMLInputElement).checked).toBe(false);
  expect(screen.getByRole('alert').textContent).toMatch(/at most 1 pod/);
});
it('keeps the disabled client gate visible and never previews or submits', async () => {
  const client = new SyntheticRecordings(); client.responder = () => { const value = inventoryResult(); if (value.status === 'ok') value.data.capture_enabled = false; return value; };
  const controller = new Recordings(client); controllers.push(controller); const submit = vi.fn();
  render(<RecordingsPanel session={session} scope={new AbortController().signal} target={target} submit={submit} controller={controller}/>);
  expect(await screen.findByText(/Saving is not enabled for this client/)).toBeTruthy();
  fireEvent.click(screen.getByRole('checkbox', { name: 'api-1 · traffic' }));
  expect((screen.getByRole('button', { name: 'Review save' }) as HTMLButtonElement).disabled).toBe(true);
  expect(client.calls).toHaveLength(1); expect(submit).not.toHaveBeenCalled();
});
it('opens recordings from the real target form and hands immediate save into capture progress', async () => {
  const preview = savePreviewResult(); if (preview.status !== 'ok') throw new Error('fixture');
  const fetcher = vi.fn().mockImplementation(async (path: string) => new Response(JSON.stringify(path.endsWith('/list_recordings') ? inventoryResult() : preview), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  const client = new SyntheticOperations();
  client.responder = name => name === 'request_capture'
    ? result<'request_capture'>({ capture_id: preview.data.capture_id, phase: 'Accepted', operation: 'recordingSave', navigation_uri: 'https://asservat.invalid/captures/' + preview.data.capture_id })
    : result<'get_capture'>({ capture_id: preview.data.capture_id, revision: 1, phase: 'Finalizing', operation: 'recordingSave', actions: [{ action_id: 'traffic', phase: 'Finalizing' }], can_cancel: false, blockers: [], retry_after_seconds: 5, navigation_uri: 'https://asservat.invalid/captures/' + preview.data.capture_id });
  const investigation = new Investigation(client, () => id(6));
  const view = render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={investigation}/>);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: target.cluster_id } });
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: target.namespace } });
  fireEvent.change(screen.getByLabelText('Workload or pod name'), { target: { value: target.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Save existing recordings now' }));
  await screen.findByRole('checkbox', { name: 'api-1 · traffic' });
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/list_recordings');
  expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({ target_ref: target, limit: 20 });
  fireEvent.click(screen.getByRole('checkbox', { name: 'api-1 · traffic' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Save last 30s now' }));
  await screen.findByRole('heading', { name: 'Recording save progress' });
  expect(client.calls.map(call => call.name)).toEqual(['request_capture', 'get_capture']);
  expect(client.calls[0].input).toEqual({ preview_id: preview.data.preview_id, idempotency_key: id(6) });
  expect(fetcher.mock.calls.map(call => call[0])).toEqual(['/api/v1/operations/list_recordings', '/api/v1/operations/preview_recording_save', '/api/v1/operations/preview_recording_save']);
  view.unmount(); investigation.reset();
});
