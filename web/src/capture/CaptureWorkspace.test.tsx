import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CaptureWorkspace } from './CaptureWorkspace';
import { Investigation } from './investigation';
import { SyntheticOperations, session, target, previewResult, progressResult, id, resolvedClosedResult, resolvedAcceptedResult } from './test-fixtures';
import { returnPath } from '../routes';
import { BrowserSession } from '../auth/session';
import { SessionGate } from '../auth/SessionGate';

const controllers: Investigation[] = [];
afterEach(() => { cleanup(); for (const controller of controllers) controller.reset(); controllers.length = 0; vi.useRealTimers(); vi.unstubAllGlobals(); window.history.replaceState(null, '', '/'); });
function mount() {
  const client = new SyntheticOperations(); const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  return { client, controller };
}
async function review() {
  const setup = mount();
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: target.cluster_id } });
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: target.namespace } });
  fireEvent.change(screen.getByLabelText('Workload or pod name'), { target: { value: target.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Find diagnostics' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Review collection' }));
  await screen.findByRole('heading', { name: 'Review collection' });
  return setup;
}
it('uses actual catalog output and explains exact pod selection, impact limits and relative deletion', async () => {
  await review();
  expect(screen.getByText('payments / api-a')).toBeTruthy();
  expect(screen.getByText('pod-uid')).toBeTruthy();
  expect(screen.getByText(/first eligible pod by name/)).toBeTruthy();
  expect(screen.getByText(/output limit, not a prediction/)).toBeTruthy();
  expect(screen.getByText('Up to 1 hour after submission. Time waiting for collection counts toward this limit.')).toBeTruthy();
  expect(screen.getByText('Within 65 minutes of that same submission.')).toBeTruthy();
  expect(screen.getByText(/cannot delete copies downloaded to local tools/)).toBeTruthy();
});
it('labels finite retention and kind choices independently of their options', () => {
  const { controller } = mount();
  const kind = screen.getByLabelText('Kind', { exact: true });
  expect(kind.tagName).toBe('SELECT');
  fireEvent.change(kind, { target: { value: 'StatefulSet' } });
  expect(controller.snapshot().draft.target.kind).toBe('StatefulSet');
  fireEvent.click(screen.getByText('Change evidence retention'));
  const retention = screen.getByLabelText('Requested access duration', { exact: true });
  expect(retention.tagName).toBe('SELECT');
  fireEvent.change(retention, { target: { value: '3600' } });
  expect(controller.snapshot().draft.retention).toBe('3600');
});
it('shows only accepted progress and distinguishes verification from available evidence', async () => {
  const { client } = await review();
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  expect(await screen.findByRole('heading', { name: 'Waiting to start' })).toBeTruthy();
  expect(screen.getByText(/Collection has not been confirmed/)).toBeTruthy();
  client.responder = () => progressResult('Finalizing', 2);
  fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
  expect(await screen.findByRole('heading', { name: 'Verifying and publishing evidence' })).toBeTruthy();
  expect(screen.getByText(/still needs verification and publication/)).toBeTruthy();
  expect(screen.queryByText('Collection complete')).toBeNull();
});
it('offers retry of an uncertain receipt without a new capture button', async () => {
  const { client } = await review(); client.responder = () => { throw new Error('uncertain'); };
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  expect(await screen.findByRole('button', { name: 'Retry same request' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Collect pod status' })).toBeNull();
  expect(screen.getByText(/does not create another capture/)).toBeTruthy();
});
it('offers explicit resolution before editing an uncertain request', async () => {
  const { client } = await review(); client.responder = () => { throw new Error('lost reply'); };
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  expect(await screen.findByRole('button', { name: 'Resolve before editing' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Edit request' })).toBeNull();
  expect(screen.getByText(/If it was accepted/)).toBeTruthy();
});
it('keeps an unavailable backend explicit without inventing catalog entries', async () => {
  const { client, controller } = mount(); client.responder = () => { throw new Error('secret target inventory'); };
  act(() => controller.setDraft({ target, retention: '' }));
  fireEvent.click(screen.getByRole('button', { name: 'Find diagnostics' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('service is unavailable'));
  expect(screen.queryByRole('button', { name: 'Review collection' })).toBeNull();
  expect(screen.queryByText(/secret target/)).toBeNull();
});
it('does not enable collection from a disabled preview', async () => {
  const { controller, client } = await review();
  const preview = previewResult(); if (preview.status !== 'ok') throw new Error(); preview.data.capture_enabled = false;
  client.responder = () => preview; await act(() => controller.preview());
  await waitFor(() => expect(screen.getByRole('button', { name: 'Collect pod status' }).hasAttribute('disabled')).toBe(true));
});
it('keeps a retry and target editing available after review refresh fails', async () => {
  const { controller, client } = await review();
  client.responder = () => { throw new Error('service unavailable'); };
  await act(() => controller.preview());
  expect(screen.getByRole('alert').textContent).toContain('service is unavailable');
  expect(screen.getByRole('button', { name: 'Review collection' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Change target' })).toBeTruthy();
});
it('preserves the reviewed handle through two real session-controller refreshes while clearing protected review text', async () => {
  vi.useFakeTimers();
  const authenticated = { ...session, expires_at: new Date(Date.now() + 600_000).toISOString() };
  const fetcher = vi.fn().mockImplementation(async (path: string) => new Response(JSON.stringify(path === '/auth/csrf' ? { csrf_token: session.csrf_token } : authenticated), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  const identity = new BrowserSession(); const client = new SyntheticOperations();
  const controller = new Investigation(client, () => id(6)); controllers.push(controller);
  render(<SessionGate controller={identity}>{(current, scope) => <CaptureWorkspace session={current} scope={scope} controller={controller}/>}</SessionGate>);
  try {
    await act(() => identity.resume());
    await act(async () => {
      controller.setDraft({ target, retention: '60' });
      await controller.discover(); await controller.preview(controller.snapshot().diagnostics![0]);
    });
    expect(screen.getByText('payments / api-a')).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(120_000));
    expect(fetcher.mock.calls.filter(([path]) => path === '/auth/refresh')).toHaveLength(3);
    expect(screen.queryByText('payments / api-a')).toBeNull();
    expect(screen.getByRole('button', { name: 'Continue reviewed request' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Continue reviewed request' }));
    await act(() => vi.advanceTimersByTimeAsync(1));
    expect(client.calls.filter(call => call.name === 'preview_capture')).toHaveLength(1);
    expect(client.calls.find(call => call.name === 'request_capture')!.input).toEqual({ preview_id: id(173), idempotency_key: id(6) });
  } finally { identity.close(); }
});
it('preserves only known local routes for sign-in return navigation', () => {
  expect(returnPath('/captures/' + id(8))).toBe('/captures/' + id(8));
  expect(returnPath('/captures/new')).toBe('/captures/new');
  for (const path of ['//external.invalid', '/auth/logout', '/captures/new?token=x', '/captures/secret', '/captures/' + id(8) + '/raw']) expect(returnPath(path)).toBe('/');
});

it('explains closure without claiming a cancelled capture and edits only after acknowledgement', async () => {
  const { client } = await review(); client.responder = () => { throw new Error('lost reply'); };
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  await screen.findByRole('button', { name: 'Resolve before editing' });
  client.responder = () => resolvedClosedResult();
  fireEvent.click(screen.getByRole('button', { name: 'Resolve before editing' }));
  await screen.findByRole('heading', { name: 'Request closed' });
  expect(screen.getByText(/cannot start a capture/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Collect pod status' })).toBeNull();
  expect(screen.queryByText('payments / api-a')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Edit request' }));
  expect(screen.getByRole('heading', { name: 'Collect evidence' })).toBeTruthy();
  expect((screen.getByLabelText('Workload or pod name') as HTMLInputElement).value).toBe('api');
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
  expect(client.calls.filter(c => c.name === 'preview_capture')).toHaveLength(1);
});
it('opens progress when resolution finds acceptance, without offering another collection', async () => {
  const { client } = await review(); client.responder = () => { throw new Error('lost reply'); };
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  await screen.findByRole('button', { name: 'Resolve before editing' });
  client.responder = name => name === 'resolve_capture_request' ? resolvedAcceptedResult() : progressResult();
  fireEvent.click(screen.getByRole('button', { name: 'Resolve before editing' }));
  await screen.findByRole('heading', { name: 'Waiting to start' });
  expect(screen.queryByRole('button', { name: 'Edit request' })).toBeNull();
  expect(client.calls.filter(c => c.name === 'request_capture')).toHaveLength(1);
});

it('links only the currently authorized case supplied by progress', async () => {
  const { client, controller } = await review();
  fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  await screen.findByRole('heading', { name: 'Waiting to start' });
  expect(screen.queryByRole('link', { name: 'View evidence' })).toBeNull();
  const result = progressResult('Succeeded', 2); if (result.status !== 'ok') throw new Error(); result.data.case_id = id(2);
  client.responder = () => result; await act(() => controller.refreshProgress());
  expect(screen.getByRole('link', { name: 'View evidence' }).getAttribute('href')).toBe('/cases/' + id(2));
  client.responder = () => { throw new Error('permission lost'); }; await act(() => controller.refreshProgress());
  expect(screen.queryByRole('link', { name: 'View evidence' })).toBeNull();
});
it('offers explicit acquisition continuation without claiming acceptance means it started', async () => {
  const { client } = await review(); fireEvent.click(screen.getByRole('button', { name: 'Collect pod status' }));
  const button = await screen.findByRole('button', { name: 'Continue collection' });
  expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(1);
  expect(screen.getByText(/Collection has not been confirmed/)).toBeTruthy();
  fireEvent.click(button);
  await waitFor(() => expect(client.calls.filter(call => call.name === 'request_capture')).toHaveLength(2));
  expect(client.calls.filter(call => call.name === 'request_capture')[1].input).toEqual({ preview_id: id(173), idempotency_key: id(6), continue_acquisition: true });
  expect(screen.getByRole('link', { name: 'Start a new investigation' }).getAttribute('href')).toBe('/captures/new');
});
