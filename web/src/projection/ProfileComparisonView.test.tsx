import React, { useLayoutEffect } from 'react';
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProfileComparisonView } from './ProfileComparisonView';
import { ContextProjection } from './projection';
import { SyntheticProjection, profileComparison, incompatibleProfiles, profileVersion, baselineVersion, id, session } from './test-fixtures';
afterEach(cleanup);
const baseline = { artifactID: id(4), version: baselineVersion, label: 'Earlier saved profile' };

it('requires an explicit visible baseline and renders function names as text', async () => {
  const client = new SyntheticProjection(); const value = profileComparison();
  value.data.rows[0].function = '<img src="https://outside.invalid" onerror="alert(1)">'; client.responder = () => value;
  const controller = ContextProjection.comparison(client); const scope = new AbortController();
  const { container } = render(<ProfileComparisonView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion} baselines={[baseline]}/>);
  expect(client.calls).toHaveLength(0); expect(screen.getByRole('button', { name: 'Compare profiles' }).hasAttribute('disabled')).toBe(true);
  fireEvent.change(screen.getByLabelText('Baseline profile'), { target: { value: id(4) } });
  fireEvent.click(screen.getByRole('button', { name: 'Compare profiles' }));
  await screen.findByRole('table', { name: 'Profile comparison function costs' });
  expect(container.querySelector('img')).toBeNull(); expect(screen.getByText(value.data.rows[0].function)).toBeTruthy();
  expect(screen.getByRole('table', { name: 'Profile acquisition details' })).toBeTruthy();
  expect(screen.getByText('A short sample does not establish a regression.')).toBeTruthy();
  expect(client.calls).toHaveLength(1); scope.abort(); await waitFor(() => expect(screen.queryByRole('table')).toBeNull());
});
it.each(['baseline', 'incident'])('hides the previous comparison during the first render of a replaced %s version', async role => {
  const client = new SyntheticProjection(); client.responder = () => profileComparison();
  const controller = ContextProjection.comparison(client); const scope = new AbortController(); const observations: boolean[] = [];
  function Probe({ changed }: { changed: boolean }) { useLayoutEffect(() => { if (changed) observations.push(!!document.querySelector('table')); }, [changed]); return null; }
  const view = (changed: boolean) => <><ProfileComparisonView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={changed && role === 'incident' ? '9'.repeat(64) : profileVersion} baselines={[{ ...baseline, version: changed && role === 'baseline' ? '9'.repeat(64) : baselineVersion }]}/><Probe changed={changed}/></>;
  const rendered = render(view(false)); fireEvent.change(screen.getByLabelText('Baseline profile'), { target: { value: id(4) } }); fireEvent.click(screen.getByRole('button', { name: 'Compare profiles' })); await screen.findByRole('table', { name: 'Profile comparison function costs' });
  rendered.rerender(view(true)); expect(observations).toEqual([false]); expect(client.calls).toHaveLength(1);
});
it('clears the result when the selected baseline leaves the authorized case list', async () => {
  const client = new SyntheticProjection(); client.responder = () => profileComparison();
  const controller = ContextProjection.comparison(client); const scope = new AbortController();
  const view = (baselines: typeof baseline[]) => <ProfileComparisonView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion} baselines={baselines}/>;
  const rendered = render(view([baseline])); fireEvent.change(screen.getByLabelText('Baseline profile'), { target: { value: id(4) } }); fireEvent.click(screen.getByRole('button', { name: 'Compare profiles' })); await screen.findByRole('table', { name: 'Profile comparison function costs' });
  rendered.rerender(view([])); expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('button', { name: 'Compare profiles' }).hasAttribute('disabled')).toBe(true); expect(client.calls).toHaveLength(1);
});
it('shows a fixed semantic incompatibility notice and does not display a server message', async () => {
  const client = new SyntheticProjection(); const value = incompatibleProfiles(); value.data.message = 'private provider details'; client.responder = () => value;
  const controller = ContextProjection.comparison(client); const scope = new AbortController();
  render(<ProfileComparisonView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion} baselines={[baseline]}/>);
  fireEvent.change(screen.getByLabelText('Baseline profile'), { target: { value: id(4) } }); fireEvent.click(screen.getByRole('button', { name: 'Compare profiles' }));
  await screen.findByText('These profiles cannot be compared for the selected sample type and normalization.');
  expect(screen.queryByText('private provider details')).toBeNull(); expect(screen.queryByRole('table')).toBeNull(); expect(client.calls).toHaveLength(1);
});
