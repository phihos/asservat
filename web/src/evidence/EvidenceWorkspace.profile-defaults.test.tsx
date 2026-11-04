import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { caseResult, id, session } from './test-fixtures';
import { profileSummary, profileVersion } from '../projection/test-fixtures';

const controllers: Evidence[] = [];
afterEach(() => { cleanup(); controllers.forEach(controller => controller.reset()); controllers.length = 0; vi.unstubAllGlobals(); });
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('prefills a saved heap summary before its first query and gets units only from the verified result', async () => {
  const value = caseResult(); if (value.status !== 'ok') throw new Error();
  const artifact = value.data.artifacts[0];
  artifact.kind = 'profile'; artifact.data_class = 'raw'; artifact.native_format = 'pprof'; artifact.digest = profileVersion;
  artifact.profile_acquisition = { requested_type: 'heap', mode: 'snapshot', requested_duration_ms: null, force_gc: false, execution_mode: 'onTrigger', started_at: null, completed_at: null, clock_uncertainty_ms: null, process_attribution: 'unknown', window_kind: 'httpAcquisition', timestamp_precision: 'microsecond' };
  const original = profileSummary();
  const summary = { ...original, data: { ...original.data, sample_type: 'inuse_space', unit: 'bytes', duration_seconds: null } };
  const fetcher = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
    if (url === '/api/v1/operations/get_case') return json(value);
    if (url === '/api/v1/operations/get_profile_summary') return json(summary);
    throw new Error('unexpected request');
  });
  vi.stubGlobal('fetch', fetcher);
  const controller = new Evidence(); controllers.push(controller); const scope = new AbortController();
  render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
  const view = within(await screen.findByRole('region', { name: 'Saved profile summary' }));
  expect((view.getByLabelText('Sample type') as HTMLInputElement).value).toBe('inuse_space');
  expect(view.queryByText('Unit')).toBeNull(); expect(view.queryByText('bytes')).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
  fireEvent.click(view.getByRole('button', { name: 'Inspect saved profile' }));
  await view.findByRole('table', { name: 'Profile function costs' });
  expect(view.getByText('bytes')).toBeTruthy(); expect(view.getByText('Unavailable')).toBeTruthy();
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[1][0]).toBe('/api/v1/operations/get_profile_summary');
  expect(JSON.parse(fetcher.mock.calls[1][1]!.body as string)).toEqual({ case_id: id(2), artifact_id: id(3), sample_type: 'inuse_space', top_n: 20 });
  expect(fetcher.mock.calls[1][1]).toMatchObject({ credentials: 'same-origin', headers: { 'X-CSRF-Token': session.csrf_token } });
  expect(new Headers(fetcher.mock.calls[1][1]!.headers).has('Authorization')).toBe(false);
  act(() => scope.abort()); expect(screen.queryByRole('region', { name: 'Saved profile summary' })).toBeNull();
});
