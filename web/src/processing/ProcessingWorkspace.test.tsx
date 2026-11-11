import { cleanup, fireEvent, render, screen, act } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ProcessingWorkspace } from './ProcessingWorkspace';
import { ProcessingFailure, type Change, type Inventory, type ProcessingClient, type Receipt } from './http';
import { processingArtifactIDFromPath } from '../routes';
import { session } from '../live/test-fixtures';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const page = (revision = 1): Inventory => ({ rootID: id(1), epoch: id(2), initialized: true, sequence: 2, observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString(), rules: [{ id: id(3), revision, state: revision % 2 ? 'restricted' : 'released', scope: { kind: 'artifact', location: { clusterID: id(4), artifactID: id(5), attemptID: id(6) } }, administrationUntil: '2020-01-01T00:00:00Z', retireBy: '2030-01-01T00:00:00Z' }] });
const receipt = (input: Change, key: string): Receipt => {
  const common = { rootID: id(1), epoch: id(2), requestID: key, operationID: id(7), sequence: 3, observedAt: new Date().toISOString(), validUntil: new Date(Date.now()+5000).toISOString() };
  if (input.action === 'request_early_erasure') return { ...common, state: 'erasureRequested' };
  if (input.action === 'initialize_processing') return { ...common, state: 'initialized', revision: 0 };
  return { ...common, state: input.action === 'release_processing' ? 'released' : 'restricted', revision: input.expectedRevision+1, ruleID: input.ruleID };
};
afterEach(cleanup);
it('loads explicitly and releases the exact persisted scope/revision after the administrative deadline', async () => {
  const read = vi.fn(async () => page()), change = vi.fn(async (input: Change, key: string) => receipt(input, key));
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={{ read, change }} newID={() => id(8)} artifactID={id(5)}/>);
  expect(read).not.toHaveBeenCalled(); expect(change).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); await screen.findByText('State: restricted. Revision 1.');
  expect(change).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole('button', { name: 'Release restriction' })); await screen.findByText(/Restriction released\./);
  expect(change).toHaveBeenCalledWith({ action: 'release_processing', ruleID: id(3), expectedRevision: 1, scope: page().rules[0].scope }, id(8), session.csrf_token, expect.any(AbortSignal));
  expect(read).toHaveBeenCalledTimes(1);
});
it('restricts the public artifact ID and preserves the original request after an uncertain reply', async () => {
  const change = vi.fn<ProcessingClient['change']>().mockRejectedValueOnce(new ProcessingFailure(503)).mockImplementationOnce(async (input, key) => receipt(input, key)); let next = 10;
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={{ read: async () => page(), change }} newID={() => id(next++)} artifactID={id(5)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Restrict processing' })); await screen.findByRole('button', { name: 'Retry same change' });
  expect(change.mock.calls[0][0]).toEqual({ action: 'restrict_processing', artifactID: id(5), ruleID: id(10), expectedRevision: 0 });
  fireEvent.click(screen.getByRole('button', { name: 'Retry same change' })); await screen.findByText(/Processing restricted\./);
  expect(change.mock.calls[1]).toEqual(change.mock.calls[0]);
});
it('requires refreshed inventory after conflict before releasing a new exact revision', async () => {
  const read = vi.fn<ProcessingClient['read']>().mockResolvedValueOnce(page()).mockResolvedValueOnce(page(3));
  const change = vi.fn<ProcessingClient['change']>().mockRejectedValueOnce(new ProcessingFailure(409)).mockImplementationOnce(async (input, key) => receipt(input, key)); let next = 8;
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={{ read, change }} newID={() => id(next++)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); await screen.findByText('State: restricted. Revision 1.');
  fireEvent.click(screen.getByRole('button', { name: 'Release restriction' })); await screen.findByText(/The rule or request changed/);
  expect(screen.queryByRole('button', { name: 'Retry same change' })).toBeNull(); expect(screen.queryByRole('button', { name: 'Release restriction' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); await screen.findByText('State: restricted. Revision 3.');
  fireEvent.click(screen.getByRole('button', { name: 'Release restriction' })); await screen.findByText(/Restriction released\./);
  expect(change.mock.calls[1][0]).toMatchObject({ expectedRevision: 3 }); expect(change.mock.calls[1][1]).not.toBe(change.mock.calls[0][1]);
});
it('clears metadata on scope loss and rejects late read results', async () => {
  let finish!: (out: Inventory) => void; const scope = new AbortController();
  render(<ProcessingWorkspace session={session} scope={scope.signal} client={{ read: () => new Promise(resolve => { finish = resolve; }), change: vi.fn() }} artifactID={id(5)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); act(() => scope.abort()); await act(async () => finish(page()));
  expect(screen.queryByText('State: restricted. Revision 1.')).toBeNull(); expect((screen.getByLabelText('Artifact ID') as HTMLInputElement).value).toBe('');
});
it('initializes only after reading server state and permits only one valid artifact path selection', async () => {
  const change = vi.fn(async (input: Change, key: string) => receipt(input, key));
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={{ read: async () => ({ ...page(), initialized: false, rules: [] }), change }} newID={() => id(8)}/>);
  expect(screen.queryByRole('button', { name: 'Initialize processing' })).toBeNull(); fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Initialize processing' })); await screen.findByText(/Processing initialized\./); expect(change.mock.calls[0][0]).toEqual({ action: 'initialize_processing' });
  expect(processingArtifactIDFromPath('/processing/artifacts/'+id(5))).toBe(id(5)); expect(processingArtifactIDFromPath('/processing/artifacts/not-an-id')).toBeUndefined();
});
it('retries an uncertain release with its original input/key and refreshed same-user CSRF', async () => {
  const scope = new AbortController();
  const change = vi.fn<ProcessingClient['change']>().mockRejectedValueOnce(new ProcessingFailure(503)).mockImplementationOnce(async (input, key) => receipt(input, key));
  const client = { read: async () => page(), change };
  const view = render(<ProcessingWorkspace session={session} scope={scope.signal} client={client} newID={() => id(8)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); await screen.findByText('State: restricted. Revision 1.');
  fireEvent.click(screen.getByRole('button', { name: 'Release restriction' })); await screen.findByRole('button', { name: 'Retry same change' });
  view.rerender(<ProcessingWorkspace session={{ ...session, csrf_token: 'D'.repeat(43) }} scope={scope.signal} client={client} newID={() => id(9)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same change' })); await screen.findByText(/Restriction released\./);
  expect(change.mock.calls[1].slice(0, 2)).toEqual(change.mock.calls[0].slice(0, 2));
  expect(change.mock.calls[1][2]).toBe('D'.repeat(43)); expect(change.mock.calls[0][2]).toBe(session.csrf_token);
});
it('ignores a late accepted change after losing the current session scope', async () => {
  const scope = new AbortController(); let finish!: (value: Receipt) => void;
  const change = vi.fn<ProcessingClient['change']>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  render(<ProcessingWorkspace session={session} scope={scope.signal} client={{ read: async () => page(), change }} artifactID={id(5)} newID={() => id(8)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Restrict processing' })); act(() => scope.abort());
  await act(async () => finish(receipt(change.mock.calls[0][0], change.mock.calls[0][1])));
  expect(screen.queryByText(/Processing restricted\./)).toBeNull(); expect(screen.queryByRole('button', { name: 'Retry same change' })).toBeNull();
  expect((screen.getByLabelText('Artifact ID') as HTMLInputElement).value).toBe('');
});
it('pages explicitly with the server cursor and replaces the visible page', async () => {
  const first = page(); first.rules = Array.from({ length: 50 }, (_, n) => ({ ...first.rules[0], id: id(n+3) })); first.nextCursor = id(52);
  const second = page(); second.rules[0].id = id(53);
  const read = vi.fn<ProcessingClient['read']>().mockResolvedValueOnce(first).mockResolvedValueOnce(second);
  render(<ProcessingWorkspace session={session} scope={new AbortController().signal} client={{ read, change: vi.fn() }}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); fireEvent.click(await screen.findByRole('button', { name: 'Next rules' }));
  await screen.findByRole('region', { name: 'Processing rule '+id(53) });
  expect(read.mock.calls.map(args => args[1])).toEqual([undefined,id(52)]);
  expect(screen.queryByRole('region', { name: 'Processing rule '+id(3) })).toBeNull(); expect(screen.queryByRole('button', { name: 'Next rules' })).toBeNull();
});
it('starts a new session scope without retaining old metadata or blocking on an old request', async () => {
  const oldScope = new AbortController(), nextScope = new AbortController(); let finish!: (out: Inventory) => void, finishNext!: (out: Inventory) => void;
  const read = vi.fn<ProcessingClient['read']>().mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockImplementationOnce(() => new Promise(resolve => { finishNext = resolve; }));
  const client = { read, change: vi.fn() };
  const view = render(<ProcessingWorkspace session={session} scope={oldScope.signal} client={client} artifactID={id(5)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' })); act(() => oldScope.abort());
  view.rerender(<ProcessingWorkspace session={{ ...session, principal: { ...session.principal, subject_id: 'another-operator' } }} scope={nextScope.signal} client={client} artifactID={id(6)}/>);
  expect((screen.getByRole('button', { name: 'Refresh processing rules' }) as HTMLButtonElement).disabled).toBe(false);
  expect((screen.getByLabelText('Artifact ID') as HTMLInputElement).value).toBe(id(6));
  fireEvent.click(screen.getByRole('button', { name: 'Refresh processing rules' }));
  await act(async () => finish(page()));
  expect((screen.getByRole('button', { name: 'Refresh processing rules' }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByText('State: restricted. Revision 1.')).toBeNull();
  await act(async () => finishNext(page(3))); await screen.findByText('State: restricted. Revision 3.');
});
