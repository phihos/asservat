import React, { useLayoutEffect } from 'react';
import { afterEach, expect, it } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SyscallProjectionView } from './SyscallProjectionView';
import { ContextProjection } from './projection';
import { SyntheticProjection, syscallSummary, syscallEvents, profileVersion, id, session } from './test-fixtures';
afterEach(cleanup);

function mount(client = new SyntheticProjection(), scope = new AbortController()) {
  const controller = ContextProjection.syscalls(client);
  const view = render(<SyscallProjectionView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion}/>);
  return { ...view, client, controller, scope };
}

it('renders fixed summary values as text, explains unknown coverage and clears on scope loss', async () => {
  const client = new SyntheticProjection(); const output = syscallSummary();
  output.data.rows = [{ ...output.data.rows[0], syscall: '<img src=x onerror=alert(1)>' }];
  client.responder = () => output;
  const { container, scope } = mount(client);
  expect(client.calls).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' }));
  await screen.findByRole('table', { name: 'Syscall counts' });
  expect(container.querySelector('img')).toBeNull(); expect(screen.getByText(output.data.rows[0].syscall)).toBeTruthy();
  expect(screen.getByText('These counts describe only the saved file. Acquisition coverage, dropped events and truncation are unknown.')).toBeTruthy();
  await act(async () => scope.abort());
  await waitFor(() => expect(screen.queryByRole('table')).toBeNull());
  expect(client.calls).toHaveLength(1);
});

it('edits bounded event filters explicitly, displays source metadata and never offers arguments', async () => {
  const client = new SyntheticProjection(); client.responder = () => syscallEvents();
  const { container } = mount(client);
  fireEvent.change(screen.getByLabelText('Syscall view'), { target: { value: 'events' } });
  fireEvent.change(screen.getByLabelText('Syscall names, separated by commas'), { target: { value: 'write' } });
  fireEvent.click(screen.getByLabelText('Errors only'));
  expect(client.calls).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' }));
  await screen.findByRole('table', { name: 'Recorded syscall events' });
  expect(client.calls[0]).toMatchObject({ name: 'get_syscall_events', input: { syscall_names: ['write'], errors_only: true, limit: 100 } });
  expect(screen.getByRole('cell', { name: /Process: p:10:11@boot@epoch/ })).toBeTruthy(); expect(screen.getByRole('cell', { name: /error · ENOENT/ })).toBeTruthy();
  expect([...container.querySelectorAll('option')].map(option => option.value)).toEqual(['summary', 'events']);
  fireEvent.change(screen.getByLabelText('Syscall names, separated by commas'), { target: { value: 'read' } });
  expect(screen.queryByRole('table')).toBeNull(); expect(client.calls).toHaveLength(1);
});

it('uses the original filter on next page and clears both the cursor and result when filters change', async () => {
  const client = new SyntheticProjection(); client.responder = () => syscallEvents('1:' + 'a'.repeat(32));
  mount(client);
  fireEvent.change(screen.getByLabelText('Syscall view'), { target: { value: 'events' } });
  fireEvent.change(screen.getByLabelText('Syscall names, separated by commas'), { target: { value: 'write' } });
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Next page' }));
  await waitFor(() => expect(client.calls).toHaveLength(2));
  expect(client.calls[1]).toMatchObject({ input: { syscall_names: ['write'], cursor: '1:' + 'a'.repeat(32) } });
  // The duplicate continuation response is refused, so stale pagination cannot
  // be repeated indefinitely by the view.
  await screen.findByRole('alert');
  fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '10' } });
  expect(screen.queryByRole('button', { name: 'Next page' })).toBeNull(); expect(client.calls).toHaveLength(2);
});

it('hides old syscall results before passive attachment effects when the immutable source changes', async () => {
  const client = new SyntheticProjection(); client.responder = () => syscallSummary();
  const controller = ContextProjection.syscalls(client); const scope = new AbortController(); const observations: boolean[] = [];
  function Probe({ version }: { version: string }) {
    useLayoutEffect(() => { if (version !== profileVersion) observations.push(!!document.querySelector('table')); }, [version]); return null;
  }
  const view = (version: string) => <><SyscallProjectionView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={version}/><Probe version={version}/></>;
  const rendered = render(view(profileVersion)); fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' })); await screen.findByRole('table');
  rendered.rerender(view('8'.repeat(64))); expect(observations).toEqual([false]); expect(client.calls).toHaveLength(1);
});

it.each([
  ['write,', ['write']],
  [' write, read, write, , ', ['read', 'write']],
])('normalizes comma-separated names before querying: %s', async (names, expected) => {
  const client = new SyntheticProjection(); client.responder = () => syscallEvents();
  mount(client);
  fireEvent.change(screen.getByRole('combobox', { name: 'Syscall view' }), { target: { value: 'events' } });
  fireEvent.change(screen.getByLabelText('Syscall names, separated by commas'), { target: { value: names } });
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' }));
  await screen.findByRole('table', { name: 'Recorded syscall events' });
  expect(client.calls).toHaveLength(1);
  expect(client.calls[0]).toMatchObject({ name: 'get_syscall_events', input: { syscall_names: expected } });
  expect(screen.queryByRole('alert')).toBeNull();
});
