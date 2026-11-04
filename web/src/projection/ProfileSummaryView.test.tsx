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

it.each([['heap', 'inuse_space'], ['cpu', 'cpu'], [undefined, 'cpu'], ['unknown-runtime-type', 'cpu']])('suggests %s acquisition sample type without querying', (requestedType, expected) => {
  const client = new SyntheticProjection(); const controller = ContextProjection.profile(client);
  render(<ProfileSummaryView controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)} artifactID={id(3)} version={profileVersion} requestedType={requestedType}/>);
  expect((screen.getByLabelText('Sample type') as HTMLInputElement).value).toBe(expected);
  expect(client.calls).toHaveLength(0); expect(screen.queryByText('Unit')).toBeNull();
});
it('preserves a same-source edit and resets suggestions when the artifact, case or immutable version changes', () => {
  const client = new SyntheticProjection(); const controller = ContextProjection.profile(client); const scope = new AbortController();
  const view = (artifactID: string, version: string, requestedType?: string, caseID = id(2)) => <ProfileSummaryView controller={controller} session={session} scope={scope.signal} caseID={caseID} artifactID={artifactID} version={version} requestedType={requestedType}/>;
  const rendered = render(view(id(3), profileVersion, 'cpu'));
  const field = () => screen.getByLabelText('Sample type') as HTMLInputElement;
  fireEvent.change(field(), { target: { value: 'alloc_space' } });
  rendered.rerender(view(id(3), profileVersion, 'cpu')); expect(field().value).toBe('alloc_space');
  // Metadata becoming available for an unchanged source must not overwrite an edit.
  rendered.rerender(view(id(3), profileVersion, 'heap')); expect(field().value).toBe('alloc_space');
  rendered.rerender(view(id(4), profileVersion, 'heap')); expect(field().value).toBe('inuse_space');
  fireEvent.change(field(), { target: { value: 'inuse_objects' } });
  rendered.rerender(view(id(4), profileVersion, 'heap')); expect(field().value).toBe('inuse_objects');
  rendered.rerender(view(id(4), '8'.repeat(64), 'heap')); expect(field().value).toBe('inuse_space');
  fireEvent.change(field(), { target: { value: 'alloc_objects' } });
  rendered.rerender(view(id(4), '8'.repeat(64), 'heap', id(5))); expect(field().value).toBe('inuse_space');
  rendered.rerender(view(id(3), profileVersion, 'cpu')); expect(field().value).toBe('cpu');
  expect(client.calls).toHaveLength(0);
});
