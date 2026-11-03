import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { SyntheticEvidence, caseResult, id, session } from './test-fixtures';
import { profileComparison, profileVersion, baselineVersion } from '../projection/test-fixtures';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
function profileCase() {
  const value = caseResult(); if (value.status !== 'ok') throw new Error();
  const artifact = value.data.artifacts[0];
  artifact.kind = 'profile'; artifact.data_class = 'raw'; artifact.native_format = 'pprof'; artifact.digest = profileVersion;
  value.data.artifacts.push({ ...artifact, artifact_id: id(4), digest: baselineVersion });
  return value;
}
it('compares only explicitly selected profiles already visible in the same case, without a raw download', async () => {
  const client = new SyntheticEvidence(); const value = profileCase(); const expired = new Date(Date.now() - 1000).toISOString();
  value.data.artifacts.push({ ...value.data.artifacts[0], artifact_id: id(5), native_format: 'runtime-trace' }, { ...value.data.artifacts[0], artifact_id: id(6), expires_at: expired, handling_notice: { ...value.data.artifacts[0].handling_notice, expiresAt: expired } });
  client.responder = () => value;
  const fetcher = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => json(profileComparison())); vi.stubGlobal('fetch', fetcher);
  const scope = new AbortController(); const controller = new Evidence(client);
  render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
  const views = await screen.findAllByRole('region', { name: 'Saved profile comparison' });
  expect(views).toHaveLength(2); expect(fetcher).not.toHaveBeenCalled();
  const first = within(views[0]); const picker = first.getByLabelText('Baseline profile');
  expect(within(picker).getAllByRole('option')).toHaveLength(3);
  expect(first.getByRole('button', { name: 'Compare profiles' }).hasAttribute('disabled')).toBe(true);
  fireEvent.change(picker, { target: { value: id(4) } }); fireEvent.click(first.getByRole('button', { name: 'Compare profiles' }));
  await first.findByRole('table', { name: 'Profile comparison function costs' });
  expect(fetcher).toHaveBeenCalledOnce(); expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/compare_profiles');
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual({ case_id: id(2), artifact_id: id(3), baseline_case_id: id(2), baseline_artifact_id: id(4), sample_type: 'cpu', normalization: 'perSecond', top_n: 20 });
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
  client.responder = () => { const next = profileCase(); next.data.artifacts = next.data.artifacts.slice(0, 1); return next; };
  await act(() => controller.refresh()); expect(screen.queryByRole('table', { name: 'Profile comparison function costs' })).toBeNull(); expect(fetcher).toHaveBeenCalledOnce();
});
it('does not offer comparison from a shared-only case', async () => {
  const client = new SyntheticEvidence(); const value = profileCase(); value.data.case.access = 'shared'; client.responder = () => value;
  const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  render(<EvidenceWorkspace controller={new Evidence(client)} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  await screen.findByRole('button', { name: 'Refresh evidence details' });
  expect(screen.queryByRole('region', { name: 'Saved profile comparison' })).toBeNull(); expect(fetcher).not.toHaveBeenCalled();
});

it('loads a selected existing baseline case before comparing the two exact source roles', async () => {
  const client = new SyntheticEvidence(); client.responder = () => profileCase();
  const baselineCase = profileCase(); baselineCase.data.case.case_id = id(7); baselineCase.data.artifacts = [{ ...baselineCase.data.artifacts[0], artifact_id: id(6), digest: baselineVersion }];
  const comparison = profileComparison(); comparison.data.baseline_case_id = id(7); comparison.data.baseline_artifact_id = id(6); comparison.provenance[0].artifactID = id(6);
  const fetcher = vi.fn(async (url: RequestInfo | URL) => json(String(url).endsWith('/get_case') ? baselineCase : comparison)); vi.stubGlobal('fetch', fetcher);
  const scope = new AbortController();
  render(<EvidenceWorkspace controller={new Evidence(client)} session={session} scope={scope.signal} caseID={id(2)}/>);
  const views = await screen.findAllByRole('region', { name: 'Saved profile comparison' }); const panel = within(views[0].parentElement!); const view = within(views[0]);
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.change(panel.getByLabelText('Baseline evidence link or case ID'), { target: { value: '/cases/' + id(7) } });
  expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(panel.getByRole('button', { name: 'Load baseline case profiles' }));
  await view.findByRole('option', { name: `Profile ${id(6)} · case ${id(7)}` });
  expect(fetcher).toHaveBeenCalledOnce(); expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_case');
  fireEvent.change(view.getByLabelText('Baseline profile'), { target: { value: id(6) } }); fireEvent.click(view.getByRole('button', { name: 'Compare profiles' }));
  await view.findByRole('table', { name: 'Profile comparison function costs' });
  expect(fetcher).toHaveBeenCalledTimes(2); expect(fetcher.mock.calls[1][0]).toBe('/api/v1/operations/compare_profiles');
  fireEvent.change(panel.getByLabelText('Baseline evidence link or case ID'), { target: { value: id(8) } });
  expect(view.queryByRole('table')).toBeNull(); expect(view.queryByRole('option', { name: `Profile ${id(6)} · case ${id(7)}` })).toBeNull();
  expect(fetcher).toHaveBeenCalledTimes(2);
});

it.each(['shared', 'wrong case'])('refuses an unusable baseline case: %s', async mode => {
  const client = new SyntheticEvidence(); client.responder = () => profileCase();
  const baseline = profileCase(); baseline.data.case.case_id = mode === 'wrong case' ? id(8) : id(7); baseline.data.artifacts = [{ ...baseline.data.artifacts[0], artifact_id: id(6), digest: baselineVersion }];
  if (mode === 'shared') baseline.data.case.access = 'shared';
  const fetcher = vi.fn(async () => json(baseline)); vi.stubGlobal('fetch', fetcher);
  render(<EvidenceWorkspace controller={new Evidence(client)} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  const views = await screen.findAllByRole('region', { name: 'Saved profile comparison' }); const panel = within(views[0].parentElement!);
  fireEvent.change(panel.getByLabelText('Baseline evidence link or case ID'), { target: { value: id(7) } }); fireEvent.click(panel.getByRole('button', { name: 'Load baseline case profiles' }));
  if (mode === 'shared') await panel.findByText('No available profiles in this baseline case.'); else await panel.findByRole('alert');
  expect(panel.queryByRole('option', { name: `Profile ${id(6)} · case ${id(7)}` })).toBeNull(); expect(fetcher).toHaveBeenCalledOnce();
});
