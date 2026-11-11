import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { session } from '../evidence/test-fixtures';
import { ProcessingWorkspace } from './ProcessingWorkspace';
import type { DiscoveryPage, DiscoveryReply, ProcessingDiscoveryClient } from './discovery-http';
import type { ErasureStatusReply, ProcessingErasureClient } from './erasure-http';
import { ProcessingFailure, type ProcessingClient, type Rule, type Receipt } from './http';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const candidate = (artifact = 3): DiscoveryPage['candidates'][number] => ({
  artifact_id: id(artifact), capture_id: id(4), case_id: id(5), cluster_id: id(6), namespace_uid: 'namespace-uid', workload_uid: 'workload-uid',
  purpose_ref: 'diagnostics', native_type: 'podStatus', data_class: 'metadata', origin: 'derived', anchor_at: '2026-11-10T17:22:00Z',
  expires_at: '2026-11-11T17:22:00Z', delete_by: '2026-11-11T18:22:00Z', custody_state: 'stored_unpublished', parents: [id(7)],
});
const reply = (candidates: DiscoveryPage['candidates'], next?: DiscoveryPage['next']): DiscoveryReply => ({
  schema_version: 'mcp-result/v1', request_id: id(99), data_class: 'metadata', status: 'ok', warnings: [], provenance: [], truncated: false,
  next_cursor: null, narrowing_hint: null, data: { candidates, ...(next ? { next } : {}) },
});
const fill = (name: string, value: string) => fireEvent.change(screen.getByLabelText(name, { exact: true }), { target: { value } });
const search = () => fireEvent.submit(screen.getByRole('button', { name: 'Search evidence' }).closest('form')!);
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('sends an explicit case search through the audited operation and selects the exact candidate for restriction', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(reply([candidate()])), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  const change = vi.fn<ProcessingClient['change']>().mockImplementation(async (input, key) => {
    if (input.action !== 'restrict_processing') throw Error('expected a restriction');
    return {
      rootID: id(1), epoch: id(2), requestID: key, ruleID: input.ruleID, operationID: key, state: 'restricted', revision: 1, sequence: 2,
      observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString(),
    };
  });
  const scope = new AbortController();
  render(<ProcessingWorkspace session={session} scope={scope.signal} client={{ read: vi.fn(), change }} newID={() => id(20)} artifactID=""/>);
  fill('Case ID', id(5)); fill('Purpose reference (optional)', 'diagnostics');
  expect(fetcher).not.toHaveBeenCalled();
  search();
  const row = await screen.findByRole('article', { name: 'Evidence candidate '+id(3) });
  expect(within(row).getByText('Pod status · metadata · diagnostics')).toBeTruthy();
  expect(within(row).getByText('Recorded direct parents')).toBeTruthy();
  expect(within(row).getByText(id(7))).toBeTruthy();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/search_processing_evidence');
  const request = fetcher.mock.calls[0][1]!;
  expect(request).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(JSON.parse(request.body as string)).toEqual({ case_id: id(5), limit: 12, purpose_ref: 'diagnostics' });
  fireEvent.click(within(row).getByRole('button', { name: 'Select artifact for restriction' }));
  const input = screen.getByLabelText('Artifact ID', { exact: true }) as HTMLInputElement;
  expect(input.value).toBe(id(3)); expect(document.activeElement).toBe(input);
  expect(change).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Restrict processing' }));
  await screen.findByText(/Processing restricted\./);
  expect(change).toHaveBeenCalledWith({ action: 'restrict_processing', artifactID: id(3), ruleID: id(20), expectedRevision: 0 }, id(20), session.csrf_token, scope.signal);
});

it('keeps the exact workload and UTC interval across an empty page with a continuation', async () => {
  const cursor = { artifact_id: id(2), anchor_at: '2026-11-10T17:21:00.123456Z' };
  const call = vi.fn<ProcessingDiscoveryClient['search']>().mockResolvedValueOnce(reply([], cursor)).mockResolvedValueOnce(reply([candidate()]));
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} discoveryClient={{ search: call }} artifactID=""/>);
  fill('Search by', 'workload'); fill('Cluster ID', id(6)); fill('Namespace UID', 'namespace-uid'); fill('Workload UID', 'workload-uid');
  fill('Acquired from (UTC)', '2026-11-10T17:00'); fill('Acquired until (UTC)', '2026-11-10T18:00');
  search();
  await screen.findByText('No matching candidates on this page.');
  expect(call.mock.calls[0][0]).toEqual({ cluster_id: id(6), namespace_uid: 'namespace-uid', workload_uid: 'workload-uid', acquired_from: '2026-11-10T17:00:00.000Z', acquired_until: '2026-11-10T18:00:00.000Z', limit: 12 });
  expect(call).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Next evidence page' }));
  await screen.findByRole('article', { name: 'Evidence candidate '+id(3) });
  expect(call.mock.calls[1][0]).toEqual({ ...call.mock.calls[0][0], after: cursor });
  fill('Purpose reference (optional)', 'retention-review');
  expect(screen.queryByRole('article')).toBeNull();
  expect(call).toHaveBeenCalledTimes(2);
});

it('discards late search results when the operator session scope changes', async () => {
  const oldScope = new AbortController(), nextScope = new AbortController();
  let finish!: (value: DiscoveryReply) => void;
  const call = vi.fn<ProcessingDiscoveryClient['search']>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValueOnce(reply([candidate(9)]));
  const view = render(<ProcessingWorkspace session={session} scope={oldScope.signal} discoveryClient={{ search: call }} artifactID=""/>);
  fill('Case ID', id(5)); search();
  act(() => oldScope.abort());
  view.rerender(<ProcessingWorkspace session={session} scope={nextScope.signal} discoveryClient={{ search: call }} artifactID=""/>);
  expect((screen.getByLabelText('Case ID') as HTMLInputElement).value).toBe('');
  await act(async () => finish(reply([candidate()])));
  expect(screen.queryByRole('article')).toBeNull();
  fill('Case ID', id(5)); search();
  await screen.findByRole('article', { name: 'Evidence candidate '+id(9) });
  expect(call.mock.calls[1][2]).toBe(nextScope.signal);
});

it('refuses to present a successful reply from another case', async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify(reply([{ ...candidate(), case_id: id(8) }])), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} artifactID=""/>);
  fill('Case ID', id(5)); search();
  await screen.findByRole('alert');
  expect(screen.queryByRole('article')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Select artifact for restriction' })).toBeNull();
});

const erasureStatus = (requestID: string, deletionState: 'pending' | 'deleted'): ErasureStatusReply => ({
  schema_version: 'mcp-result/v1', request_id: id(99), data_class: 'metadata', status: 'ok', warnings: [], provenance: [], truncated: false,
  next_cursor: null, narrowing_hint: null,
  data: {
    request_id: requestID, artifact_id: id(3), accepted_at: '2026-11-10T17:23:00Z', access_until: '2026-11-10T17:23:00Z',
    delete_by: '2026-11-11T18:22:00Z', effective_delete_by: '2026-11-11T18:10:00Z',
    audit_state: 'acknowledged', deletion_state: deletionState,
    ...(deletionState === 'deleted' ? { deleted_at: '2026-11-10T17:26:00Z' } : {}),
  },
});
const checkErasureStatus = () => fireEvent.submit(screen.getByRole('button', { name: 'Check erasure status' }).closest('form')!);

it('confirms a discovered artifact, retries its same erasure request, and reads deletion status only on demand', async () => {
  const discoveryClient = { search: vi.fn<ProcessingDiscoveryClient['search']>().mockResolvedValue(reply([{ ...candidate(), origin: 'capture', parents: [] }])) };
  const change = vi.fn<ProcessingClient['change']>().mockRejectedValueOnce(new ProcessingFailure(503)).mockImplementationOnce(async (_input, key) => ({
    rootID: id(1), epoch: id(2), requestID: key, operationID: id(8), state: 'erasureRequested', sequence: 2,
    observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString(),
  }));
  const newID = vi.fn(() => id(20));
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(new Response(JSON.stringify(erasureStatus(id(20), 'pending')), { headers: { 'Content-Type': 'application/json' } }))
    .mockResolvedValueOnce(new Response(JSON.stringify(erasureStatus(id(20), 'deleted')), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  const scope = new AbortController();
  const view = render(<ProcessingWorkspace session={session} scope={scope.signal} discoveryClient={discoveryClient} client={{ read: vi.fn(), change }} newID={newID} artifactID={id(9)}/>);
  expect(screen.queryByRole('button', { name: 'Request early erasure' })).toBeNull();
  fill('Case ID', id(5)); search();
  const row = await screen.findByRole('article', { name: 'Evidence candidate '+id(3) });
  const review = () => fireEvent.click(within(row).getByRole('button', { name: 'Request early erasure' }));
  review();
  expect(document.activeElement).toBe(screen.getByRole('heading', { name: 'Confirm early erasure' }));
  const confirmation = screen.getByRole('region', { name: 'Confirm early erasure' });
  expect(within(confirmation).getByText(id(3))).toBeTruthy();
  expect(within(confirmation).getByText(/existing hard deletion deadline still applies/)).toBeTruthy();
  fireEvent.click(within(confirmation).getByRole('button', { name: 'Cancel early erasure' }));
  expect(change).not.toHaveBeenCalled();
  expect(newID).not.toHaveBeenCalled();

  review();
  fireEvent.click(screen.getByRole('button', { name: 'Confirm early erasure' }));
  const retry = await screen.findByRole('button', { name: 'Retry same erasure request' });
  expect(change).toHaveBeenCalledTimes(1);
  fireEvent.click(retry);
  await screen.findByText(/Early erasure request accepted/);
  expect(change.mock.calls[0]).toEqual([{ action: 'request_early_erasure', artifactID: id(3) }, id(20), session.csrf_token, scope.signal]);
  expect(change.mock.calls[1]).toEqual(change.mock.calls[0]);
  expect(newID).toHaveBeenCalledTimes(1);
  expect(fetcher).not.toHaveBeenCalled();
  expect((screen.getByLabelText('Erasure request ID') as HTMLInputElement).value).toBe(id(20));

  checkErasureStatus();
  await screen.findByText('Deletion pending.');
  expect(screen.getByText('Current hard deletion deadline')).toBeTruthy();
  expect(screen.queryByText('Managed deletion verified.')).toBeNull();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_processing_erasure');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', redirect: 'error', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual({ request_id: id(20) });

  view.unmount();
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal}/>);
  expect((screen.getByLabelText('Erasure request ID') as HTMLInputElement).value).toBe('');
  expect(fetcher).toHaveBeenCalledTimes(1);
  fill('Erasure request ID', id(20)); checkErasureStatus();
  await screen.findByText('Managed deletion verified.');
  expect(screen.getByText('Verified deletion time')).toBeTruthy();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('discards erasure status across session scope loss and refuses a mismatched request ID', async () => {
  const oldScope = new AbortController(), nextScope = new AbortController();
  let finish!: (reply: ErasureStatusReply) => void;
  const read = vi.fn<ProcessingErasureClient['read']>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }))
    .mockResolvedValueOnce(erasureStatus(id(21), 'deleted'));
  const client = { read };
  const view = render(<ProcessingWorkspace session={session} scope={oldScope.signal} erasureClient={client}/>);
  fill('Erasure request ID', id(20)); checkErasureStatus();
  act(() => oldScope.abort());
  view.rerender(<ProcessingWorkspace session={session} scope={nextScope.signal} erasureClient={client}/>);
  expect((screen.getByLabelText('Erasure request ID') as HTMLInputElement).value).toBe('');
  await act(async () => finish(erasureStatus(id(20), 'deleted')));
  expect(screen.queryByText('Managed deletion verified.')).toBeNull();
  fill('Erasure request ID', id(20)); checkErasureStatus();
  await screen.findByText('Erasure status is unavailable for this request ID.');
  expect(screen.queryByText('Managed deletion verified.')).toBeNull();
});

it('restricts the full workload interval from an empty successful search and releases its durable scope after reload', async () => {
  const workloadScope: Rule['scope'] = {
    kind: 'workloadInterval', clusterID: id(6), namespaceUID: 'namespace-uid', workloadUID: 'workload-uid',
    acquiredFrom: '2026-11-10T17:00:00.000Z', acquiredUntil: '2026-11-10T18:00:00.000Z',
  };
  const call = vi.fn<ProcessingDiscoveryClient['search']>().mockResolvedValue(reply([], { artifact_id: id(2), anchor_at: '2026-11-10T17:21:00Z' }));
  const change = vi.fn<ProcessingClient['change']>().mockImplementation(async (input, key) => {
    if (input.action !== 'restrict_processing' && input.action !== 'release_processing') throw Error('expected rule change');
    return { rootID: id(1), epoch: id(2), requestID: key, operationID: id(8), ruleID: input.ruleID,
      state: input.action === 'restrict_processing' ? 'restricted' : 'released', revision: input.expectedRevision+1, sequence: 2,
      observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString() };
  });
  const read = vi.fn<ProcessingClient['read']>().mockImplementation(async () => ({
    rootID: id(1), epoch: id(2), initialized: true, sequence: 2, observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString(),
    rules: [{ id: id(20), revision: 1, state: 'restricted', scope: workloadScope, administrationUntil: '2026-11-12T18:00:00Z', retireBy: '2026-11-13T18:00:00Z' }],
  }));
  let next = 20;
  const newID = vi.fn(() => id(next++));
  const client = { read, change };
  const view = render(<ProcessingWorkspace session={session} scope={new AbortController().signal} discoveryClient={{ search: call }} client={client} newID={newID}/>);
  fill('Search by', 'workload'); fill('Cluster ID', id(6)); fill('Namespace UID', 'namespace-uid'); fill('Workload UID', 'workload-uid');
  fill('Acquired from (UTC)', '2026-11-10T17:00'); fill('Acquired until (UTC)', '2026-11-10T18:00');
  fill('Purpose reference (optional)', 'diagnostics');
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
  search();
  await screen.findByText('No matching candidates on this page.');
  const review = screen.getByRole('button', { name: 'Review workload restriction' });
  fireEvent.click(review);
  let confirmation = screen.getByRole('region', { name: 'Confirm workload restriction' });
  expect(document.activeElement).toBe(within(confirmation).getByRole('heading'));
  for (const value of [id(6), 'namespace-uid', 'workload-uid', workloadScope.acquiredFrom, workloadScope.acquiredUntil]) {
    expect(within(confirmation).getByText(value, { exact: true })).toBeTruthy();
  }
  expect(within(confirmation).getByText(/all purposes/)).toBeTruthy();
  expect(within(confirmation).getByText(/every page/)).toBeTruthy();
  expect(within(confirmation).getByText(/published later/)).toBeTruthy();
  expect(within(confirmation).getByText(/purpose filter.*only.*discovery/i)).toBeTruthy();
  expect(change).not.toHaveBeenCalled();
  fireEvent.click(within(confirmation).getByRole('button', { name: 'Cancel workload restriction' }));
  expect(newID).not.toHaveBeenCalled();
  fireEvent.click(review);
  confirmation = screen.getByRole('region', { name: 'Confirm workload restriction' });
  fireEvent.click(within(confirmation).getByRole('button', { name: 'Confirm workload restriction' }));
  await screen.findByText(/Processing restricted./);
  expect(change.mock.calls[0].slice(0, 3)).toEqual([{ action: 'restrict_processing', ruleID: id(20), expectedRevision: 0, scope: workloadScope }, id(21), session.csrf_token]);
  expect(call).toHaveBeenCalledTimes(1);
  expect(read).not.toHaveBeenCalled();

  view.unmount();
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={client} newID={newID}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Release restriction' }));
  await screen.findByText(/Restriction released./);
  expect(change.mock.calls[1].slice(0, 3)).toEqual([{ action: 'release_processing', ruleID: id(20), expectedRevision: 1, scope: workloadScope }, id(22), session.csrf_token]);
  expect(read).toHaveBeenCalledTimes(1);
});

const fillWorkloadSearch = () => {
  fill('Search by', 'workload'); fill('Cluster ID', id(6)); fill('Namespace UID', 'namespace-uid'); fill('Workload UID', 'workload-uid');
  fill('Acquired from (UTC)', '2026-11-10T17:00'); fill('Acquired until (UTC)', '2026-11-10T18:00');
};

it('offers workload review only after a successful current workload search and clears it when criteria change', async () => {
  let finish!: (value: DiscoveryReply) => void;
  const call = vi.fn<ProcessingDiscoveryClient['search']>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }))
    .mockRejectedValueOnce(new ProcessingFailure(503)).mockResolvedValueOnce(reply([]));
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} discoveryClient={{ search: call }}/>);
  fillWorkloadSearch(); search();
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
  await act(async () => finish(reply([])));
  expect(screen.getByRole('button', { name: 'Review workload restriction' })).toBeTruthy();
  fill('Workload UID', 'edited-workload-uid');
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
  search(); await screen.findByRole('alert');
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
  fill('Search by', 'case'); fill('Case ID', id(5)); search();
  await screen.findByText('No matching candidates on this page.');
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
});

it('keeps a reviewed workload request across same-user refresh and drops late mutation results on scope loss', async () => {
  const scope = new AbortController(), nextScope = new AbortController();
  const call = vi.fn<ProcessingDiscoveryClient['search']>().mockResolvedValue(reply([]));
  let finish!: (value: Receipt) => void;
  const change = vi.fn<ProcessingClient['change']>().mockRejectedValueOnce(new ProcessingFailure(503))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const newID = vi.fn().mockReturnValueOnce(id(20)).mockReturnValueOnce(id(21));
  const client = { read: vi.fn(), change };
  const view = render(<ProcessingWorkspace session={session} scope={scope.signal} discoveryClient={{ search: call }} client={client} newID={newID}/>);
  fillWorkloadSearch(); search();
  fireEvent.click(await screen.findByRole('button', { name: 'Review workload restriction' }));
  view.rerender(<ProcessingWorkspace session={{ ...session, csrf_token: 'D'.repeat(43) }} scope={scope.signal} discoveryClient={{ search: call }} client={client} newID={newID}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Confirm workload restriction' }));
  await screen.findByRole('button', { name: 'Retry same change' });
  expect(change).toHaveBeenCalledTimes(1);
  expect(change.mock.calls[0][0]).toEqual({
    action: 'restrict_processing', ruleID: id(20), expectedRevision: 0,
    scope: { kind: 'workloadInterval', clusterID: id(6), namespaceUID: 'namespace-uid', workloadUID: 'workload-uid',
      acquiredFrom: '2026-11-10T17:00:00.000Z', acquiredUntil: '2026-11-10T18:00:00.000Z' },
  });
  view.rerender(<ProcessingWorkspace session={{ ...session, csrf_token: 'E'.repeat(43) }} scope={scope.signal} discoveryClient={{ search: call }} client={client} newID={newID}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same change' }));
  expect(change.mock.calls[1].slice(0, 2)).toEqual(change.mock.calls[0].slice(0, 2));
  expect(change.mock.calls[0][2]).toBe('D'.repeat(43));
  expect(change.mock.calls[1][2]).toBe('E'.repeat(43));
  expect(newID).toHaveBeenCalledTimes(2);
  act(() => scope.abort());
  view.rerender(<ProcessingWorkspace session={session} scope={nextScope.signal} discoveryClient={{ search: call }} client={client} newID={newID}/>);
  await act(async () => finish({ rootID: id(1), epoch: id(2), requestID: id(21), operationID: id(8), ruleID: id(20),
    state: 'restricted', revision: 1, sequence: 2, observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString() }));
  expect(screen.queryByText(/Processing restricted./)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Retry same change' })).toBeNull();
  expect(screen.queryByRole('region', { name: 'Confirm workload restriction' })).toBeNull();
  expect((screen.getByLabelText('Case ID') as HTMLInputElement).value).toBe('');
});

it('clears a workload confirmation when its session scope ends', async () => {
  const scope = new AbortController();
  const change = vi.fn();
  render(<ProcessingWorkspace session={session} scope={scope.signal} discoveryClient={{ search: vi.fn().mockResolvedValue(reply([])) }} client={{ read: vi.fn(), change }}/>);
  fillWorkloadSearch(); search();
  fireEvent.click(await screen.findByRole('button', { name: 'Review workload restriction' }));
  expect(screen.getByRole('region', { name: 'Confirm workload restriction' })).toBeTruthy();
  act(() => scope.abort());
  expect(screen.queryByRole('region', { name: 'Confirm workload restriction' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Review workload restriction' })).toBeNull();
  expect(change).not.toHaveBeenCalled();
});
