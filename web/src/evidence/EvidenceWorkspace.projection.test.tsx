import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { SyntheticEvidence, caseResult, id, session } from './test-fixtures';
import { excerpt, pending, result, queryHandle } from '../projection/test-fixtures';

const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
function mount(client = new SyntheticEvidence(), scope = new AbortController()) {
  const controller = new Evidence(client);
  const view = render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
  return { ...view, client, controller, scope };
}

it('opens the actual approved-read HTTP path from saved evidence without preparing a download', async () => {
  const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(excerpt()));
  vi.stubGlobal('fetch', fetcher);
  const { client, unmount } = mount();
  const inspect = await screen.findByRole('button', { name: 'Inspect saved status' });
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(inspect);
  await screen.findByLabelText('Approved pod status');
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_file_excerpt');
  const request = fetcher.mock.calls[0][1]!;
  expect(JSON.parse(request.body as string)).toEqual({ case_id: id(2), artifact_id: id(3), line_start: 1, max_lines: 14 });
  expect(request).toMatchObject({ method: 'POST', credentials: 'same-origin', redirect: 'error', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
  expect(screen.getByRole('button', { name: 'Download' })).toBeTruthy();
  unmount();
  expect(screen.queryByLabelText('Approved pod status')).toBeNull();
});

it('keeps pending polling explicit and uses only the original query handle', async () => {
  vi.useFakeTimers();
  let monotonic = 1000;
  vi.spyOn(performance, 'now').mockImplementation(() => monotonic);
  let calls = 0;
  const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(++calls === 1 ? pending() : result()));
  vi.stubGlobal('fetch', fetcher);
  let mounted!: ReturnType<typeof mount>;
  await act(async () => { mounted = mount(); });
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Inspect saved status' })); });
  expect(screen.getByRole('button', { name: 'Check result' }).hasAttribute('disabled')).toBe(true);
  monotonic += 2000;
  await act(() => vi.advanceTimersByTimeAsync(2000));
  expect(fetcher).toHaveBeenCalledOnce();
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Check result' })); });
  expect(screen.getByLabelText('Approved pod status')).toBeTruthy();
  expect(fetcher.mock.calls[1][0]).toBe('/api/v1/operations/get_query_result');
  expect(JSON.parse(fetcher.mock.calls[1][1]!.body as string)).toEqual({ query_handle: queryHandle });
  expect(mounted.client.calls.map(call => call.name)).toEqual(['get_case']);
  monotonic += 10_000;
  await act(() => vi.advanceTimersByTimeAsync(10_000));
  expect(screen.queryByLabelText('Approved pod status')).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it('keeps simultaneous artifact views separate and closes only the selected view', async () => {
  const client = new SyntheticEvidence(); const value = caseResult();
  if (value.status !== 'ok') throw new Error();
  value.data.artifacts.push({ ...value.data.artifacts[0], artifact_id: id(4) });
  client.responder = () => value;
  const fetcher = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    const output = excerpt(); output.data.lines[0] = JSON.parse(init!.body as string).artifact_id;
    return json(output);
  });
  vi.stubGlobal('fetch', fetcher);
  mount(client);
  const buttons = await screen.findAllByRole('button', { name: 'Inspect saved status' });
  fireEvent.click(buttons[0]);
  await screen.findByLabelText('Approved pod status');
  fireEvent.click(buttons[1]);
  await screen.findByText(new RegExp(id(4)));
  const views = screen.getAllByRole('region', { name: 'Saved pod status' });
  expect(within(views[0]).getByLabelText('Approved pod status').textContent).toContain(id(3));
  expect(within(views[1]).getByLabelText('Approved pod status').textContent).toContain(id(4));
  fireEvent.click(within(views[0]).getByRole('button', { name: 'Close view' }));
  expect(within(views[0]).queryByLabelText('Approved pod status')).toBeNull();
  expect(within(views[1]).getByLabelText('Approved pod status')).toBeTruthy();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
});

it.each(['scope loss', 'case access loss', 'unmount'])('cancels the view-owned request on %s without a replacement query', async mode => {
  let requestSignal: AbortSignal | undefined;
  const fetcher = vi.fn((_url: RequestInfo | URL, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
    requestSignal = init?.signal ?? undefined;
    requestSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), { once: true });
  }));
  vi.stubGlobal('fetch', fetcher);
  const mounted = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect saved status' }));
  await screen.findByText('Checking access and preparing the saved status…');
  await act(async () => {
    if (mode === 'scope loss') mounted.scope.abort();
    else if (mode === 'unmount') mounted.unmount();
    else { mounted.client.responder = () => { throw new Error('denied'); }; await mounted.controller.refresh(); }
  });
  expect(requestSignal?.aborted).toBe(true);
  expect(screen.queryByLabelText('Approved pod status')).toBeNull();
  expect(screen.queryByRole('button', { name: 'Inspect saved status' })).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(mounted.client.calls.every(call => call.name === 'get_case')).toBe(true);
});

it.each(['raw', 'extract', 'other kind', 'expired'])('does not offer the fixed approved projection for %s', async mode => {
  const client = new SyntheticEvidence(); const value = caseResult();
  if (value.status !== 'ok') throw new Error();
  const artifact = value.data.artifacts[0];
  if (mode === 'raw' || mode === 'extract') artifact.data_class = mode;
  else if (mode === 'other kind') artifact.kind = 'pcapng';
  else artifact.expires_at = artifact.handling_notice.expiresAt = new Date(Date.now() - 1000).toISOString();
  client.responder = () => value;
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  mount(client);
  await screen.findByRole('button', { name: 'Refresh evidence details' });
  expect(screen.queryByRole('button', { name: 'Inspect saved status' })).toBeNull();
  expect(fetcher).not.toHaveBeenCalled();
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
});

it('shows a closed unavailable result without substituting native download or retrying a query', async () => {
  const fetcher = vi.fn(async () => new Response('private provider failure', { status: 503 }));
  vi.stubGlobal('fetch', fetcher);
  const { client } = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Inspect saved status' }));
  expect((await screen.findByRole('alert')).textContent).toBe('The saved status is unavailable or your access could not be checked.');
  expect(screen.queryByText('private provider failure')).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
});
