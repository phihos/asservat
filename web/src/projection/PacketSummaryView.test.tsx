import { useLayoutEffect } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PacketSummaryView } from './PacketSummaryView';
import { ContextProjection } from './projection';
import { SyntheticProjection, packetSummary, profileVersion, id, session } from './test-fixtures';
afterEach(() => { cleanup(); vi.useRealTimers(); });
it.each(['captureExclusions', 'snapshotOutputLimit', 'unavailable'])('labels %s without inventing measured network loss', async reporting => {
  const client = new SyntheticProjection(), value = packetSummary(); value.data.drop_reporting = reporting;
  if (reporting === 'unavailable') value.data.drops = null;
  value.warnings = ['<img src="https://outside.invalid/" onerror="alert(1)">']; client.responder = () => value;
  const scope = new AbortController(), controller = ContextProjection.packet(client);
  const { container } = render(<PacketSummaryView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion}/>);
  expect(client.calls).toHaveLength(0); expect(screen.queryByRole('table')).toBeNull(); expect(container.querySelector('input')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved packets' })); await screen.findByRole('table', { name: 'Saved packet conversations' });
  expect(screen.getByText('192.0.2.1:40000')).toBeTruthy(); expect(screen.getByText(/not measured network loss/)).toBeTruthy();
  expect(screen.getByText(value.warnings[0])).toBeTruthy(); expect(container.querySelector('img')).toBeNull();
  expect(screen.getByText(reporting === 'snapshotOutputLimit' ? 'Snapshot output-limit exclusions' : 'Reported capture exclusions')).toBeTruthy();
  if (reporting === 'unavailable') expect(screen.getByText('Unknown')).toBeTruthy();
  scope.abort(); await waitFor(() => expect(screen.queryByRole('table')).toBeNull()); expect(client.calls).toHaveLength(1);
});
it('removes a previous result before rendering a different immutable source and never queries on attach', async () => {
  const client = new SyntheticProjection(); client.responder = () => packetSummary(); const scope = new AbortController(), controller = ContextProjection.packet(client); const observations: boolean[] = [];
  function Probe({ version }: { version: string }) { useLayoutEffect(() => { if (version !== profileVersion) observations.push(!!document.querySelector('table')); }, [version]); return null; }
  const view = (version: string) => <><PacketSummaryView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={version}/><Probe version={version}/></>;
  const rendered = render(view(profileVersion)); fireEvent.click(screen.getByRole('button', { name: 'Inspect saved packets' })); await screen.findByRole('table');
  rendered.rerender(view('8'.repeat(64))); expect(observations).toEqual([false]); expect(client.calls).toHaveLength(1);
});

it('clears an expired view and attaches a fresh session without an implicit repeat', async () => {
  vi.useFakeTimers(); let now = 0;
  const client = new SyntheticProjection(); client.responder = () => packetSummary();
  const controller = ContextProjection.packet(client, () => now), scope = new AbortController();
  const view = (current: typeof session) => <PacketSummaryView controller={controller} session={current} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion}/>;
  const rendered = render(view(session)); await act(() => controller.inspect());
  expect(screen.getByRole('table')).toBeTruthy(); now = 10_000;
  await act(() => vi.advanceTimersByTimeAsync(10_000));
  expect(screen.queryByRole('table')).toBeNull(); expect(screen.getByRole('status').textContent).toContain('view has expired');
  rendered.rerender(view({ ...session })); expect(screen.getByRole('button', { name: 'Inspect saved packets' })).toBeTruthy();
  expect(client.calls).toHaveLength(1); scope.abort();
});
it('shows an empty saved file and a bounded top100 without claiming complete conversation coverage', async () => {
  const client = new SyntheticProjection(), value = packetSummary(); value.data.packets = 101; value.data.conversations_total = 101; value.data.conversations_truncated = true;
  value.data.conversations = Array.from({ length: 100 }, (_, i) => ({ source: `192.0.2.1:${1000 + i}`, destination: '192.0.2.2:443', protocol: 'TCP', packets: 1 }));
  client.responder = () => value; const controller = ContextProjection.packet(client), scope = new AbortController();
  render(<PacketSummaryView controller={controller} session={session} scope={scope.signal} caseID={id(2)} artifactID={id(3)} version={profileVersion}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved packets' })); await screen.findByRole('table');
  expect(screen.getByText(/top 100 of 101 directional conversations/)).toBeTruthy(); expect(screen.getAllByRole('row')).toHaveLength(101);
  value.data.packets = 0; value.data.conversations_total = 0; value.data.conversations = []; value.data.conversations_truncated = false; value.data.drops = null; value.data.drop_reporting = 'unavailable';
  fireEvent.click(screen.getByRole('button', { name: 'Inspect again' })); await screen.findByText('No packet records were retained in this saved file.'); scope.abort();
});
