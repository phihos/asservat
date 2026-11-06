import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RawAccessPanel } from './RawAccessPanel';
import type { Operations } from '../approvals/http';
import type { Artifact } from './http';
import { caseResult, session, id } from './test-fixtures';
import { result } from '../capture/test-fixtures';
import { validInput_request_raw_access, validOutput_request_raw_access } from '../generated/validate-approvals';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
function artifact(n: number, size?: number): Artifact {
  const c = caseResult(); if (c.status !== 'ok') throw new Error();
  return { ...c.data.artifacts[0], artifact_id: id(n), digest: n.toString(16).padStart(64, '0'), data_class: 'raw', verified_native_bytes: size, target: { cluster_id: id(1), namespace_uid: 'ns', workload_uid: 'workload', pod_uid: 'pod', namespace: 'payments', workload_name: 'api' } };
}

it('requests selected whole files with exact sizes and reuses an uncertain request unchanged', async () => {
  const call = vi.fn().mockRejectedValueOnce(new Error('unknown')).mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Pending' }));
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[artifact(3, 512), artifact(4, 1024), artifact(5)]} client={{ call } as Operations} newID={() => 'same-key'}/>);
  const boxes = screen.getAllByRole('checkbox');
  expect((boxes[2] as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(boxes[0]); fireEvent.click(boxes[1]);
  expect(screen.getByLabelText('Total download byte budget')).toHaveProperty('value', '1536');
  expect(screen.getByText(/10000 download operations/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await screen.findByRole('alert');
  const input = call.mock.calls[0][1];
  expect(input).toEqual({ case_id: id(2), artifact_digests: [artifact(3).digest, artifact(4).digest], operations: ['download_artifact'], reason: 'Inspect incident', max_bytes: 1536, expires_in_seconds: 3600, idempotency_key: 'same-key' });
  expect(validInput_request_raw_access(input)).toBe(true);
  expect(screen.getByRole('group')).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same approval request' }));
  expect(await screen.findByRole('link', { name: 'Review download approval' })).toHaveProperty('href', expect.stringContaining('/approvals/' + id(41)));
  expect(call.mock.calls[1][1]).toEqual(input);
  expect(screen.getByText(/starts no collection/)).toBeTruthy();
});

it('bounds selection to64 and refuses empty, duplicate or oversized selectors while retaining future operation contracts', () => {
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={Array.from({ length: 65 }, (_, n) => artifact(n + 3, 1))}/>);
  const boxes = screen.getAllByRole('checkbox');
  for (const b of boxes.slice(0, 64)) fireEvent.click(b);
  expect(boxes[64]).toHaveProperty('disabled', true);
  const input = { case_id: id(2), artifact_digests: Array.from({ length: 64 }, (_, n) => artifact(n + 3).digest), operations: ['download_artifact'], reason: 'incident', max_bytes: 64, expires_in_seconds: 3600, idempotency_key: 'key' };
  expect(validInput_request_raw_access(input)).toBe(true);
  for (const artifact_digests of [[], [...input.artifact_digests, artifact(80).digest], [artifact(3).digest, artifact(3).digest]]) expect(validInput_request_raw_access({ ...input, artifact_digests })).toBe(false);
  for (const operations of [[], ['download_artifact', 'download_artifact']]) expect(validInput_request_raw_access({ ...input, operations })).toBe(false);
  expect(validInput_request_raw_access({ ...input, operations: ['read_memory'] })).toBe(true);
  for (const phase of ['Expired', 'Revoked']) expect(validOutput_request_raw_access(result({ grant_id: id(41), phase }))).toBe(true);
});

it('cancels the request on session scope end without exposing a late approval', async () => {
  let resolve!: (value: unknown) => void;
  const call = vi.fn((..._args: unknown[]) => new Promise(r => { resolve = r; }));
  const scope = new AbortController();
  const view = render(<RawAccessPanel session={session} scope={scope.signal} caseID={id(2)} artifacts={[artifact(3, 0)]} client={{ call } as Operations}/>);
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByLabelText('Total download byte budget')).toHaveProperty('value', '1');
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await waitFor(() => expect(call).toHaveBeenCalledOnce());
  scope.abort(); resolve(result({ grant_id: id(41), phase: 'Pending' }));
  await waitFor(() => expect(call.mock.calls[0][3]).toHaveProperty('aborted', true));
  expect(screen.queryByRole('link', { name: 'Review download approval' })).toBeNull();
  view.unmount();
});

const refusal = (retryable: boolean) => ({ ...result({ code: 'InvalidRequest', message: 'Choose a shorter approval period.', retryable }), status: 'error' });
const jsonReply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

it('unlocks a definitive validated refusal and submits edited values with a new key', async () => {
  const denied = refusal(false);
  expect(validOutput_request_raw_access(denied)).toBe(true);
  const fetch = vi.fn().mockResolvedValueOnce(jsonReply(denied)).mockResolvedValueOnce(jsonReply(result({ grant_id: id(41), phase: 'Pending' })));
  vi.stubGlobal('fetch', fetch);
  const newID = vi.fn().mockReturnValueOnce('first-key').mockReturnValueOnce('edited-key');
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[artifact(3, 512)]} newID={newID}/>);
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  expect((await screen.findByRole('alert')).textContent).toBe('Choose a shorter approval period.');
  expect(screen.getByRole('group')).toHaveProperty('disabled', false);
  fireEvent.change(screen.getByLabelText('Approval period in seconds'), { target: { value: '300' } });
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect selected incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await screen.findByRole('link', { name: 'Review download approval' });
  const first = JSON.parse(fetch.mock.calls[0][1].body);
  const second = JSON.parse(fetch.mock.calls[1][1].body);
  expect(first).toMatchObject({ idempotency_key: 'first-key', expires_in_seconds: 3600, reason: 'Inspect incident' });
  expect(second).toEqual({ ...first, idempotency_key: 'edited-key', expires_in_seconds: 300, reason: 'Inspect selected incident' });
  expect(fetch.mock.calls[1][1].headers['Idempotency-Key']).toBe('edited-key');
  expect(newID).toHaveBeenCalledTimes(2);
});

it.each(['transport', 'http-refusal', 'invalid-envelope', 'retryable', 'pending'])('retains exact immutable request after %s uncertainty', async mode => {
  const fetch = vi.fn();
  if (mode === 'transport') fetch.mockRejectedValueOnce(new Error('connection lost'));
  else if (mode === 'http-refusal') fetch.mockResolvedValueOnce(jsonReply(refusal(false), 403));
  else if (mode === 'invalid-envelope') fetch.mockResolvedValueOnce(jsonReply({ status: 'error', data: refusal(false).data }));
  else if (mode === 'retryable') fetch.mockResolvedValueOnce(jsonReply(refusal(true)));
  else {
    const pending = { ...result({ query_handle: 'pending-query', retry_after_seconds: 1 }), status: 'pending' };
    expect(validOutput_request_raw_access(pending)).toBe(true);
    fetch.mockResolvedValueOnce(jsonReply(pending));
  }
  fetch.mockResolvedValueOnce(jsonReply(result({ grant_id: id(41), phase: 'Pending' })));
  vi.stubGlobal('fetch', fetch);
  const newID = vi.fn(() => 'original-key');
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[artifact(3, 512)]} newID={newID}/>);
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await screen.findByRole('alert');
  expect(screen.getByRole('group')).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same approval request' }));
  await screen.findByRole('link', { name: 'Review download approval' });
  expect(fetch.mock.calls[1][1].body).toBe(fetch.mock.calls[0][1].body);
  expect(fetch.mock.calls[1][1].headers['Idempotency-Key']).toBe('original-key');
  expect(newID).toHaveBeenCalledOnce();
});

it('lets a refused selection discard an artifact that expired during the request', async () => {
  const now = Date.now();
  const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
  try {
    const expired = { ...artifact(3, 512), expires_at: new Date(now + 1000).toISOString() };
    const current = { ...artifact(4, 1024), expires_at: new Date(now + 3600000).toISOString() };
    const call = vi.fn().mockImplementationOnce(async () => { clock.mockReturnValue(now + 2000); return refusal(false); }).mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Pending' }));
    let key = 0;
    render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[expired, current]} newID={() => `request-${++key}`} client={{ call } as Operations}/>);
    fireEvent.click(screen.getAllByRole('checkbox')[0]);
    fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect incident' } });
    fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
    await screen.findByRole('alert');
    expect(screen.getAllByRole('checkbox')[0]).toHaveProperty('disabled', false);
    fireEvent.click(screen.getAllByRole('checkbox')[0]);
    expect(screen.getAllByRole('checkbox')[0]).toHaveProperty('checked', false);
    expect(screen.getAllByRole('checkbox')[0]).toHaveProperty('disabled', true);
    fireEvent.click(screen.getAllByRole('checkbox')[1]);
    fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
    await screen.findByRole('link', { name: 'Review download approval' });
    expect(call.mock.calls[1][1]).toMatchObject({ artifact_digests: [current.digest], max_bytes: 1024, idempotency_key: 'request-2' });
  } finally { clock.mockRestore(); }
});

it('requests query-only access without charging the whole native size and checks the original approval', async () => {
  const saved = { ...artifact(3, 8 * 1024 * 1024), kind: 'packetCapture', native_format: 'pcapng-raw' };
  const onGrant = vi.fn();
  const call = vi.fn().mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Pending' })).mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Approved' }));
  render(<RawAccessPanel purpose="packet-query" onGrant={onGrant} session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[saved]} prefilledArtifactID={saved.artifact_id} client={{ call } as Operations} newID={() => 'query-access-key'}/>);
  expect(screen.getByLabelText('Total disclosure byte budget')).toHaveProperty('value', '49152');
  fireEvent.change(screen.getByLabelText('Reason for raw access'), { target: { value: 'Inspect selected packet headers' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request query approval' }));
  await screen.findByRole('link', { name: 'Review query approval' });
  expect(call.mock.calls[0][1]).toMatchObject({ operations: ['pcap_query'], max_bytes: 49152, idempotency_key: 'query-access-key' });
  expect(onGrant).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Check approval' }));
  await waitFor(() => expect(onGrant).toHaveBeenCalledExactlyOnceWith(id(41)));
  expect(call.mock.calls[1].slice(0, 2)).toEqual(['get_grant', { grant_id: id(41) }]);
});

it('shares one budget for selected query and whole-file download access', async () => {
  const saved = { ...artifact(3, 100000), kind: 'packetCapture', native_format: 'pcapng-raw' };
  const onGrant = vi.fn();
  const call = vi.fn().mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Approved' }));
  render(<RawAccessPanel purpose="packet-query" onGrant={onGrant} session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[saved]} prefilledArtifactID={saved.artifact_id} client={{ call } as Operations}/>);
  fireEvent.change(screen.getByLabelText('Allowed operations'), { target: { value: 'both' } });
  expect(screen.getByLabelText('Total disclosure byte budget')).toHaveProperty('value', '149152');
  fireEvent.change(screen.getByLabelText('Reason for raw access'), { target: { value: 'Inspect packets and open Wireshark' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request query approval' }));
  await waitFor(() => expect(onGrant).toHaveBeenCalledExactlyOnceWith(id(41)));
  expect(call.mock.calls[0][1]).toMatchObject({ operations: ['download_artifact', 'pcap_query'], max_bytes: 149152 });
});
it('obtains get_logs-only current-client approval and exposes only approved original grant',async()=>{const logs={...artifact(3,4096),kind:'logs',native_format:'asservat-logs/v1'};const onGrant=vi.fn();const call=vi.fn().mockResolvedValueOnce(result({grant_id:id(41),phase:'Pending'})).mockResolvedValueOnce(result({grant_id:id(41),phase:'Approved'}));render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[logs]} prefilledArtifactID={logs.artifact_id} purpose="log-query" onGrant={onGrant} client={{call} as Operations}/>);expect(call).not.toHaveBeenCalled();fireEvent.change(screen.getByLabelText('Reason for raw access'),{target:{value:'Read saved incident logs'}});fireEvent.click(screen.getByRole('button',{name:'Request query approval'}));await screen.findByRole('button',{name:'Check approval'});expect(call.mock.calls[0][1]).toMatchObject({operations:['get_logs'],artifact_digests:[logs.digest],max_bytes:49152});expect(validInput_request_raw_access(call.mock.calls[0][1])).toBe(true);expect(onGrant).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Check approval'}));await waitFor(()=>expect(onGrant).toHaveBeenCalledWith(id(41)));expect(call.mock.calls[1][0]).toBe('get_grant');});
