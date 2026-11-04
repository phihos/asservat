import { act, cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { operations } from './http';
import { caseResult, id, session } from './test-fixtures';
import { validOutput_get_case } from '../generated/validate-evidence';

const controllers: Evidence[] = [];
afterEach(() => { cleanup(); controllers.forEach(controller => controller.reset()); controllers.length = 0; vi.unstubAllGlobals(); });
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const acquisition = () => ({ requested_type: 'cpu', mode: 'interval', requested_duration_ms: 10000, force_gc: false, execution_mode: 'onTrigger', started_at: '2026-11-04T08:30:00.123456Z', completed_at: '2026-11-04T08:30:10.654321Z', clock_uncertainty_ms: null, process_attribution: 'unknown', window_kind: 'httpAcquisition', timestamp_precision: 'microsecond' });
function profileCase() {
  const value = caseResult(); if (value.status !== 'ok') throw new Error();
  const artifact = value.data.artifacts[0];
  artifact.kind = 'profile'; artifact.data_class = 'raw'; artifact.native_format = 'pprof';
  // The test starts at the JSON boundary so it also detects stale generated contracts.
  Object.assign(artifact, { profile_acquisition: acquisition() });
  return value;
}
async function mount(value: unknown) {
  const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(value)); vi.stubGlobal('fetch', fetcher);
  const controller = new Evidence(); controllers.push(controller); const scope = new AbortController();
  render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
  return { controller, scope, fetcher };
}
it('decodes a real HTTP case response and separates requested interval, HTTP timing and unknown attribution', async () => {
  const value = profileCase(); const { scope, fetcher } = await mount(value);
  const table = await screen.findByRole('table', { name: 'Profile collection timing' });
  expect(within(table).getByText('2026-11-04T08:30:00.123456Z').closest('time')?.dateTime).toBe('2026-11-04T08:30:00.123456Z');
  expect(within(table).getByText('2026-11-04T08:30:10.654321Z')).toBeTruthy();
  expect(within(table).getByText(/Requested duration: 10 s/)).toBeTruthy();
  expect(screen.getByText(/HTTP acquisition does not establish the precise sample interval or cumulative history/)).toBeTruthy();
  expect(screen.getByText(/Clock uncertainty and serving process attribution are unknown/)).toBeTruthy();
  expect(screen.getByText(/Matching Pod identity does not prove the same process or restart/)).toBeTruthy();
  expect(screen.getByText(/on trigger.*pre-trigger recording/)).toBeTruthy();
  expect(fetcher).toHaveBeenCalledOnce();
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_case');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual({ case_id: id(2) });
  act(() => scope.abort()); expect(screen.queryByRole('table', { name: 'Profile collection timing' })).toBeNull();
});
it('shows legacy timing and cumulative duration as unknown, without an epoch or inferred history', async () => {
  const value = profileCase(); const row = value.data.artifacts[0];
  Object.assign(row, { profile_acquisition: { ...acquisition(), requested_type: 'allocs', mode: 'cumulative', requested_duration_ms: null, started_at: null, completed_at: null } });
  value.data.artifacts.push({ ...row, artifact_id: id(4), profile_acquisition: undefined });
  await mount(value); const table = within(await screen.findByRole('table', { name: 'Profile collection timing' }));
  expect(table.getByRole('cell', { name: /^allocs · cumulative/ })).toBeTruthy();
  expect(table.getByText(/No requested interval/)).toBeTruthy();
  expect(table.getAllByText('Unknown')).toHaveLength(4);
  expect(table.getByText('Request parameters unavailable')).toBeTruthy();
  expect(table.queryByText(/1970|0 s|same process/)).toBeNull();
});
it.each([
  { started_at: null }, { completed_at: null }, { started_at: '2026-11-04T08:31:00Z' },
  { started_at: '2026-11-04T08:30:10.654322Z' },
  { started_at: '2026-11-04T08:30:00.1234567Z' }, { clock_uncertainty_ms: 0 },
  { process_attribution: 'sameProcess' }, { composition: 'private-value' }, { requested_duration_ms: 0 },
])('refuses invalid timing through the actual HTTP decoder: %j', async patch => {
  const value = profileCase(); Object.assign(value.data.artifacts[0], { profile_acquisition: { ...acquisition(), ...patch } });
  vi.stubGlobal('fetch', vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(value)));
  await expect(operations.call('get_case', { case_id: id(2) }, session.csrf_token, new AbortController().signal)).rejects.toThrow();
});
it('keeps the generic timeline and refuses timing attached to non-profile evidence', async () => {
  const value = profileCase(); value.data.timeline = [{ time: '2026-11-04T08:29:00Z', kind: 'collection', summary: 'Existing saved event' }];
  expect(validOutput_get_case(value)).toBe(true);
  await mount(value); await screen.findByRole('table', { name: 'Profile collection timing' });
  expect(screen.getByText(/Existing saved event/)).toBeTruthy();
  value.data.artifacts[0].kind = 'context';
  vi.stubGlobal('fetch', vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(value)));
  await expect(operations.call('get_case', { case_id: id(2) }, session.csrf_token, new AbortController().signal)).rejects.toThrow();
});
