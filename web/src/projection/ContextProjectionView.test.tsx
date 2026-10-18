import React, { useLayoutEffect } from 'react';
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ContextProjectionView } from './ContextProjectionView';
import { ContextProjection } from './projection';
import { SyntheticProjection, excerpt, id, session } from './test-fixtures';
afterEach(cleanup);
it('renders saved untrusted strings as text and clears the view on close and scope loss', async () => {
  const client = new SyntheticProjection(); const value = excerpt();
  value.data.lines[0] = '<img src="https://outside.invalid" onerror="alert(1)">'; client.responder = () => value;
  const controller = new ContextProjection(client); const scope = new AbortController();
  const { container } = render(<ContextProjectionView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)}/>);
  expect(client.calls).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved status' }));
  await screen.findByLabelText('Approved pod status');
  expect(container.querySelector('img')).toBeNull(); expect(container.querySelector('pre')?.textContent).toContain('<img');
  fireEvent.click(screen.getByRole('button', { name: 'Close view' }));
  expect(screen.queryByLabelText('Approved pod status')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved status' }));
  await screen.findByLabelText('Approved pod status'); scope.abort();
  await waitFor(() => expect(screen.queryByLabelText('Approved pod status')).toBeNull());
});

it('never commits the previous excerpt when the artifact changes before passive effects', async () => {
  const client = new SyntheticProjection(); const controller = new ContextProjection(client);
  const scope = new AbortController(); const observations: string[] = [];
  function Probe({ artifactID }: { artifactID: string }) {
    useLayoutEffect(() => {
      if (artifactID === id(4)) observations.push(document.querySelector('pre[aria-label="Approved pod status"]')?.textContent ?? '');
    }, [artifactID]);
    return null;
  }
  const view = (artifactID: string) => <><ContextProjectionView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={artifactID}/><Probe artifactID={artifactID}/></>;
  const rendered = render(view(id(3)));
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved status' }));
  await screen.findByLabelText('Approved pod status');
  rendered.rerender(view(id(4)));
  expect(observations).toEqual(['']);
  expect(screen.queryByLabelText('Approved pod status')).toBeNull();
  expect(client.calls).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved status' }));
  await screen.findByLabelText('Approved pod status');
  expect(client.calls[1].input).toMatchObject({ artifact_id: id(4) });
});
