import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CaptureWorkspace } from './CaptureWorkspace';
import { Investigation } from './investigation';
import { progressResult, session, id } from './test-fixtures';
import { validOutput_get_capture } from '../generated/validate-capture';

const controllers: Investigation[] = [];
afterEach(() => { cleanup(); controllers.forEach(controller => controller.reset()); controllers.length = 0; vi.unstubAllGlobals(); vi.useRealTimers(); window.history.replaceState(null, '', '/'); });
const messages = {
  ProfileUnavailable: 'The Go profile endpoint is unavailable or disabled. No profile was collected for this action. Check the endpoint configuration before preparing a new request.',
  ProfilerBusy: 'A conflicting profile session is already running. Asservat did not stop it. No profile was collected for this action.',
};
function refusal(reason: string, phase: 'Failed' | 'Running' = 'Failed') {
  const value = progressResult(); if (value.status !== 'ok') throw new Error();
  value.data.phase = phase; value.data.actions = [{ action_id: 'cpu-profile', phase, reason_code: reason }]; delete value.data.retry_after_seconds;
  return value;
}
async function mount(value: unknown) {
  const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher); window.history.replaceState(null, '', '/captures/' + id(8));
  const controller = new Investigation(); controllers.push(controller); const scope = new AbortController();
  render(<CaptureWorkspace controller={controller} session={session} scope={scope.signal}/>);
  return { fetcher, scope };
}
it.each(['ProfileUnavailable', 'ProfilerBusy'] as const)('renders safe %s guidance through the real HTTP decoder without acquisition, retry or a case link', async reason => {
  const value = refusal(reason); expect(validOutput_get_capture(value)).toBe(true);
  const { fetcher, scope } = await mount(value);
  expect(await screen.findByRole('heading', { name: 'Collection failed' })).toBeTruthy();
  expect(screen.getByText(messages[reason])).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'View evidence' })).toBeNull();
  expect(screen.queryByRole('button', { name: /Collect|Retry|Continue/ })).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_capture');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual({ capture_id: id(8) });
  expect(new Headers(fetcher.mock.calls[0][1]!.headers).has('Authorization')).toBe(false);
  vi.useFakeTimers(); await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
  expect(fetcher).toHaveBeenCalledOnce();
  act(() => scope.abort()); expect(screen.queryByText(messages[reason])).toBeNull();
});
it('retains generic failure display without rendering unrecognized reason text or speculative endpoint advice', async () => {
  await mount(refusal('<img src=x onerror=alert(1)>'));
  await screen.findByRole('heading', { name: 'Collection failed' });
  expect(screen.queryByText(messages.ProfileUnavailable)).toBeNull(); expect(screen.queryByText(messages.ProfilerBusy)).toBeNull();
  expect(document.querySelectorAll('img')).toHaveLength(0); expect(screen.queryByText(/onerror/)).toBeNull();
});
it('does not label a running action with terminal refusal guidance', async () => {
  const { scope } = await mount(refusal('ProfileUnavailable', 'Running'));
  await screen.findByRole('heading', { name: 'Collecting evidence' });
  expect(screen.queryByText(messages.ProfileUnavailable)).toBeNull(); act(() => scope.abort());
});
