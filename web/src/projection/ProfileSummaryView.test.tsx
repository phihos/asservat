import React, { useLayoutEffect } from 'react';
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProfileSummaryView } from './ProfileSummaryView';
import { ContextProjection } from './projection';
import { SyntheticProjection, profileSummary, profileVersion, id, session } from './test-fixtures';
afterEach(cleanup);
it('renders function names as text, distinguishes unavailable fractions and clears on session loss', async () => {
  const client = new SyntheticProjection(); const value = profileSummary();
  value.data.top[0].function = '<img src="https://outside.invalid" onerror="alert(1)">'; value.data.top[0].fraction = null;
  client.responder = () => value;
  const controller = ContextProjection.profile(client); const scope = new AbortController();
  const { container } = render(<ProfileSummaryView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion}/>);
  expect(client.calls).toHaveLength(0); fireEvent.click(screen.getByRole('button', { name: 'Inspect saved profile' }));
  await screen.findByRole('table', { name: 'Profile function costs' });
  expect(container.querySelector('img')).toBeNull(); expect(screen.getByText(value.data.top[0].function)).toBeTruthy(); expect(screen.getByText('Unavailable')).toBeTruthy();
  scope.abort(); await waitFor(() => expect(screen.queryByRole('table')).toBeNull());
});
it('hides the previous result during the first render of a changed immutable source', async () => {
  const client = new SyntheticProjection(); client.responder = () => profileSummary();
  const controller = ContextProjection.profile(client); const scope = new AbortController(); const observations: boolean[] = [];
  function Probe({ version }: { version: string }) {
    useLayoutEffect(() => { if (version !== profileVersion) observations.push(!!document.querySelector('table')); }, [version]); return null;
  }
  const view = (version: string) => <><ProfileSummaryView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={version}/><Probe version={version}/></>;
  const rendered = render(view(profileVersion)); fireEvent.click(screen.getByRole('button', { name: 'Inspect saved profile' })); await screen.findByRole('table');
  rendered.rerender(view('8'.repeat(64))); expect(observations).toEqual([false]); expect(client.calls).toHaveLength(1);
});
