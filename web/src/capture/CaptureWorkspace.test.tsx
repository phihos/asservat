import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CaptureWorkspace } from './CaptureWorkspace';
import { Investigation } from './investigation';
import { SyntheticOperations, session, target, result, previewResult, progressResult, id, resolvedClosedResult, resolvedAcceptedResult, recordingPreviewResult, approvalPendingResult, historyResult, settingsResult, catalogResult } from './test-fixtures';
import { returnPath } from '../routes';
import { BrowserSession } from '../auth/session';
import { SessionGate } from '../auth/SessionGate';

const controllers: Investigation[] = [];
it('opens saved recorder settings, edits the filter and window, and prepares a fresh review without collecting', async () => {
  const { client } = mount();
  const recording = recordingPreviewResult(); const saved = settingsResult();
  if (recording.status !== 'ok' || saved.status !== 'ok' || !('recipe_spec' in saved.data.settings)) throw new Error();
  saved.data.settings.profile_composition = recording.data.profile_composition;
  saved.data.settings.profile_composition!.authored.components[0].overrides!.push({ actionID: 'http', field: 'packetAfter', value: '3s' });
  client.responder = name => name === 'list_diagnostics' ? catalogResult() : name === 'list_capture_history' ? historyResult([id(41)]) : name === 'get_capture_settings' ? saved : recordingPreviewResult(id(41));
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: target.cluster_id } });
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: target.namespace } });
  fireEvent.change(screen.getByLabelText('Workload or pod name'), { target: { value: target.name } });
  fireEvent.click(screen.getByRole('button', { name: 'Find diagnostics' }));
  fireEvent.click(await screen.findByRole('button', { name: 'View settings' }));
  await screen.findByRole('heading', { name: 'Saved settings' });
  fireEvent.change(screen.getByLabelText('http / http / packetFilter'), { target: { value: 'tcp port 8443' } });
  fireEvent.change(screen.getByLabelText('http / http / packetAfter'), { target: { value: '5s' } });
  fireEvent.change(screen.getByLabelText('Maximum duration'), { target: { value: '20s' } });
  fireEvent.click(screen.getByRole('button', { name: 'Review these settings' }));
  await screen.findByRole('heading', { name: 'Review collection' });
  const sent = client.calls.find(call => call.name === 'preview_capture')!.input;
  expect(sent).toMatchObject({ repeated_from_capture_id: id(41), profile_composition: { maxDuration: '20s', components: [{ id: 'http', profileRef: { version: 'v1' }, overrides: [{ field: 'packetFilter', value: 'tcp port 8443' }, { field: 'packetAfter', value: '5s' }] }, {}, {}] } });
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
});
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
it('selects bounded follow-up queries and downloads in the same collection review', async () => {
  const { client, controller } = mount();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  const action = recording.data.capture_assessment.actions[0].actionID;
  recording.data.result_access_actions = [{ action_id: action, operations: ['download_artifact', 'pcap_query'] }];
  client.responder = () => recording;
  act(() => controller.setDraft({ target, retention: '' }));
  await act(async () => { await controller.previewComposition(recording.data.profile_composition!.authored); });
  fireEvent.click(screen.getByLabelText('Include follow-up access in this approval'));
  fireEvent.change(screen.getByLabelText('Follow-up operations'), { target: { value: 'both' } });
  fireEvent.change(screen.getByLabelText('Shared disclosure byte budget'), { target: { value: '9000000' } });
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  const sent = client.calls.find(c => c.name === 'request_capture')!.input as Record<string, unknown>;
  expect(sent.result_access).toMatchObject({ actionIds: [action], operations: ['download_artifact', 'pcap_query'], maxBytes: 9000000, maxArtifacts: 1 });
  expect(sent.result_access).not.toHaveProperty('clientIDs');
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
  // ADR-234: the unavailable answer offers the caller's own explanation.
  expect(screen.getByRole('button', { name: 'Why?' })).toBeTruthy();
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

it('renders the reviewed recorder assessment and requests approval without claiming collection', async () => {
  const { controller, client } = await review();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  client.responder = name => name === 'preview_capture' ? recording : approvalPendingResult();
  await act(async () => { await controller.previewComposition(recording.data.profile_composition!.authored); });
  expect(screen.getByText(/Saved evidence is limited to/).textContent).toContain((recording.data.max_bytes / 1024).toLocaleString());
  expect(screen.queryByText(/Saved status is limited to 4 KiB/)).toBeNull();
  expect(screen.queryByText(/No application process is started/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  expect(await screen.findByRole('link', { name: 'View approval' })).toHaveProperty('pathname', '/approvals/' + id(41));
  expect(screen.getByRole('button', { name: 'Continue after approval' })).toBeTruthy();
  expect(controller.snapshot().captureID).toBeUndefined();
});

it('renders grouped recording actions with exact child identity and retained Pod labels', async () => {
  window.history.replaceState(null, '', '/captures/' + id(8));
  const client = new SyntheticOperations(); const controller = new Investigation(client); controllers.push(controller);
  const reported = { reason: '  grouped reason\n<&>  ', reason_state: 'available', capture_id: id(8), revision: 1, phase: 'Partial', operation: 'recordingSave', can_cancel: false, blockers: [], navigation_uri: 'https://asservat.invalid/captures/' + id(8), actions: [
    { action_id: 'traffic', action_instance_id: id(101), pod_uid: 'original-pod-a', pod_name: 'api-a', phase: 'Succeeded' },
    { action_id: 'traffic', action_instance_id: id(102), pod_uid: 'original-pod-b', pod_name: 'api-b', phase: 'Cancelled' },
  ] };
  client.responder = () => result<'get_capture'>(reported);
  const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
  try {
    render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
    await screen.findByRole('heading', { name: 'Recording save progress' });
    expect(screen.getByText('api-a')).toBeTruthy(); expect(screen.getByText('api-b')).toBeTruthy();
    expect(screen.getAllByText('traffic')).toHaveLength(2);
    expect(document.querySelectorAll('.progress-actions li')).toHaveLength(2);
    expect(screen.getAllByRole('region', {name:'Save reason'})).toHaveLength(1);
    expect(screen.getByRole('region', {name:'Save reason'}).querySelector('p')!.textContent).toBe(reported.reason);
    expect(errors.mock.calls.some(call => call.some(value => String(value).includes('same key')))).toBe(false);
    expect(client.calls.every(call => call.name === 'get_capture' && !!call.input && typeof call.input === 'object' && 'capture_id' in call.input && call.input.capture_id === id(8))).toBe(true);
    expect(document.querySelector('a[href="/captures/' + id(101) + '"]')).toBeNull();
  } finally { errors.mockRestore(); }
});

it('requests grouped cancellation once on the parent while stored results remain visible', async () => {
 window.history.replaceState(null,'','/captures/'+id(8));const client=new SyntheticOperations();const controller=new Investigation(client);controllers.push(controller);let requested=false;
 client.responder=name=>{
  if(name==='cancel_capture'){requested=true;return result<'cancel_capture'>({capture_id:id(8),revision:2,phase:'Running',cancellation_requested:true,navigation_uri:'https://asservat.invalid/captures/'+id(8)});}
  return result<'get_capture'>({capture_id:id(8),revision:requested?2:1,phase:'Running',operation:'recordingSave',can_cancel:!requested,cancellation_requested:requested,blockers:[],case_id:id(50),navigation_uri:'https://asservat.invalid/captures/'+id(8),actions:[
   {action_id:'traffic',action_instance_id:id(101),pod_uid:'pod-a',pod_name:'api-a',phase:'Succeeded'},
   {action_id:'traffic',action_instance_id:id(102),pod_uid:'pod-b',pod_name:'api-b',phase:'Running'},
  ]});
 };
 render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
 fireEvent.click(await screen.findByRole('button',{name:'Cancel recording save'}));
 await screen.findByText(/Cancellation requested. Waiting for unfinished snapshots/);
 expect(screen.getByRole('link',{name:'View evidence'}).getAttribute('href')).toBe('/cases/'+id(50));expect(screen.getByRole('heading',{name:'Saving recorded history'})).toBeTruthy();
 expect(screen.queryByText('Collection cancelled')).toBeNull();expect(screen.queryByRole('button',{name:'Cancel recording save'})).toBeNull();
 expect(client.calls.filter(call=>call.name==='cancel_capture')).toHaveLength(1);expect(client.calls.every(call=>!!call.input&&typeof call.input==='object'&&'capture_id'in call.input&&call.input.capture_id===id(8))).toBe(true);
});

it('keeps parent capture progress available when descriptive reason has retired',async()=>{
 window.history.replaceState(null,'','/captures/'+id(8));const client=new SyntheticOperations();const controller=new Investigation(client);controllers.push(controller);
 client.responder=()=>{const response=progressResult();if(response.status==='ok'){response.data.reason_state='unavailable';response.data.operation='recordingSave';}return response;};
 render(<CaptureWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
 expect(await screen.findByText(/The save reason is unavailable/)).toBeTruthy();
 expect(document.querySelector('.progress-actions')).toBeTruthy();expect(screen.queryByRole('region',{name:'Save reason'})).toBeNull();
});

async function rawFollowupReview() {
  const setup = mount();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  const [packet, syscall, profile] = recording.data.profile_composition!.actionMap.map(action => action.actionID);
  recording.data.result_access_actions = [
    { action_id: packet, operations: ['download_artifact', 'pcap_query'] },
    { action_id: syscall, operations: ['download_artifact', 'syscall_query'] },
    { action_id: profile, operations: ['download_artifact'] },
  ];
  setup.client.responder = () => recording;
  act(() => setup.controller.setDraft({ target, retention: '' }));
  await act(async () => { await setup.controller.previewComposition(recording.data.profile_composition!.authored); });
  fireEvent.click(screen.getByLabelText('Include follow-up access in this approval'));
  return { ...setup, recording, packet, syscall, profile };
}
it('derives server-advertised mixed query operations without losing either source', async () => {
  const { client, packet, syscall } = await rawFollowupReview();
  fireEvent.change(screen.getByLabelText('Follow-up operations'), { target: { value: 'query' } });
  expect(screen.getByRole('option', { name: 'Saved packet and syscall argument queries' })).toBeTruthy();
  expect(screen.getByLabelText('http / http')).toBeTruthy();
  expect(screen.getByLabelText('calls / syscalls')).toBeTruthy();
  expect(screen.queryByLabelText('context / processes')).toBeNull();
  expect(screen.queryByLabelText('context / sockets')).toBeNull();
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toMatchObject({ result_access: { actionIds: [packet, syscall], operations: ['pcap_query', 'syscall_query'], maxArtifacts: 2, maxBytes: 2 * 49152 } });
});
it('includes profile downloads beside server-advertised packet and argument queries', async () => {
  const { client, recording, packet, syscall, profile } = await rawFollowupReview();
  fireEvent.change(screen.getByLabelText('Follow-up operations'), { target: { value: 'both' } });
  expect(screen.getByLabelText('context / processes')).toBeTruthy();
  expect((screen.getByLabelText('Shared disclosure byte budget') as HTMLInputElement).value).toBe(String(recording.data.max_bytes + 2 * 49152));
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  const sent = client.calls.find(call => call.name === 'request_capture')!.input as Record<string, unknown>;
  expect(sent.result_access).toMatchObject({ actionIds: [packet, syscall, profile], operations: ['download_artifact', 'pcap_query', 'syscall_query'], maxArtifacts: 3 });
  expect(sent.result_access).not.toHaveProperty('clientIDs');
});
it('removes a deselected source query operation and refuses queryless combined selection', async () => {
  const { client, syscall } = await rawFollowupReview();
  fireEvent.change(screen.getByLabelText('Follow-up operations'), { target: { value: 'both' } });
  fireEvent.click(screen.getByLabelText('http / http'));
  fireEvent.click(screen.getByLabelText('calls / syscalls'));
  expect((screen.getByRole('button', { name: 'Request approval' }) as HTMLButtonElement).disabled).toBe(true);
  expect(client.calls.some(call => call.name === 'request_capture')).toBe(false);
  fireEvent.click(screen.getByLabelText('context / processes'));
  fireEvent.click(screen.getByLabelText('calls / syscalls'));
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toMatchObject({ result_access: { actionIds: [syscall], operations: ['download_artifact', 'syscall_query'], maxArtifacts: 1 } });
});
it('offers syscall-only follow-up from the server and preserves download-only choices', async () => {
  const { client, controller } = mount();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  const action = recording.data.profile_composition!.actionMap[1].actionID;
  recording.data.result_access_actions = [{ action_id: action, operations: ['download_artifact', 'syscall_query'] }];
  client.responder = () => recording;
  act(() => controller.setDraft({ target, retention: '' }));
  await act(async () => { await controller.previewComposition(recording.data.profile_composition!.authored); });
  fireEvent.click(screen.getByLabelText('Include follow-up access in this approval'));
  expect(screen.getByRole('option', { name: 'Saved syscall argument queries' })).toBeTruthy();
  expect(screen.queryByRole('option', { name: 'Saved packet queries' })).toBeNull();
  fireEvent.change(screen.getByLabelText('Follow-up operations'), { target: { value: 'query' } });
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toMatchObject({ result_access: { actionIds: [action], operations: ['syscall_query'], maxBytes: 49152 } });
});
it('retains the download-only server choice without inventing query options', async () => {
  const { client, controller } = mount();
  const recording = recordingPreviewResult(); if (recording.status !== 'ok') throw new Error();
  const action = recording.data.profile_composition!.actionMap[2].actionID;
  recording.data.result_access_actions = [{ action_id: action, operations: ['download_artifact'] }];
  client.responder = () => recording;
  act(() => controller.setDraft({ target, retention: '' }));
  await act(async () => { await controller.previewComposition(recording.data.profile_composition!.authored); });
  fireEvent.click(screen.getByLabelText('Include follow-up access in this approval'));
  expect((screen.getByLabelText('Follow-up operations') as HTMLSelectElement).options).toHaveLength(1);
  expect(screen.getByLabelText('context / processes')).toBeTruthy();
  client.responder = () => approvalPendingResult();
  fireEvent.click(screen.getByRole('button', { name: 'Request approval' }));
  await screen.findByRole('link', { name: 'View approval' });
  expect(client.calls.find(call => call.name === 'request_capture')!.input).toMatchObject({ result_access: { actionIds: [action], operations: ['download_artifact'] } });
});
it('derives four parent operations from mixed advertised log packet syscall and profile choices',async()=>{const{client,controller}=mount();const p=recordingPreviewResult();if(p.status!=='ok')throw Error();const ids=p.data.profile_composition!.actionMap.map(a=>a.actionID);p.data.result_access_actions=[{action_id:ids[0],operations:['download_artifact','pcap_query']},{action_id:ids[1],operations:['download_artifact','syscall_query']},{action_id:ids[2],operations:['download_artifact']},{action_id:ids[3],operations:['download_artifact','get_logs']}];client.responder=()=>p;act(()=>controller.setDraft({target,retention:''}));await act(()=>controller.previewComposition(p.data.profile_composition!.authored));fireEvent.click(screen.getByLabelText('Include follow-up access in this approval'));fireEvent.change(screen.getByLabelText('Follow-up operations'),{target:{value:'both'}});expect(screen.getByRole('option',{name:'Downloads and saved packet, syscall argument and log queries'})).toBeTruthy();client.responder=()=>approvalPendingResult();fireEvent.click(screen.getByRole('button',{name:'Request approval'}));await screen.findByRole('link',{name:'View approval'});expect(client.calls.find(c=>c.name==='request_capture')!.input).toMatchObject({result_access:{operations:['download_artifact','get_logs','pcap_query','syscall_query'],actionIds:ids,maxArtifacts:4}});});
