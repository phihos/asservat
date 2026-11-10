import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { session } from '../evidence/test-fixtures';
import { ProcessingWorkspace } from './ProcessingWorkspace';
import type { DiscoveryPage, DiscoveryReply, ProcessingDiscoveryClient } from './discovery-http';
import type { ProcessingClient } from './http';

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
