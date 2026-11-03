import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { SyntheticEvidence, caseResult, id, session } from './test-fixtures';
import { profileVersion, syscallEvents, syscallSummary } from '../projection/test-fixtures';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });

it.each(['metadata', 'raw'] as const)('opens both approved syscall views from a saved %s source without a native download', async source => {
  const client = new SyntheticEvidence(); const value = caseResult();
  if (value.status !== 'ok') throw new Error('fixture');
  const artifact = value.data.artifacts[0];
  artifact.kind = 'syscallTrace'; artifact.data_class = source; artifact.digest = profileVersion;
  artifact.native_format = source === 'raw' ? 'asservat-syscall-arguments/v1' : 'asservat-syscall-events/v1';
  client.responder = () => value;
  const fetcher = vi.fn(async (url: RequestInfo | URL) => json(String(url).endsWith('get_syscall_events') ? syscallEvents() : syscallSummary()));
  vi.stubGlobal('fetch', fetcher);
  const scope = new AbortController(); const controller = new Evidence(client);
  render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
  const inspect = await screen.findByRole('button', { name: 'Inspect saved syscalls' });
  expect(fetcher).not.toHaveBeenCalled(); fireEvent.click(inspect);
  await screen.findByRole('table', { name: 'Syscall counts' });
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_syscall_summary');
  fireEvent.change(screen.getByLabelText('Syscall view'), { target: { value: 'events' } });
  fireEvent.click(screen.getByRole('button', { name: 'Inspect saved syscalls' }));
  await screen.findByRole('table', { name: 'Recorded syscall events' });
  expect(fetcher.mock.calls[1][0]).toBe('/api/v1/operations/get_syscall_events');
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
  // Evidence details disappearing also unmounts and clears these independent
  // managed views, even when the broader browser scope remains alive.
  client.responder = () => { throw new Error('denied'); };
  await act(async () => controller.refresh());
  await waitFor(() => expect(screen.queryByRole('table')).toBeNull());
});

it.each(['wrong-format', 'wrong-class', 'expired', 'raw-share'])('does not offer the syscall projection for %s', async change => {
  const client = new SyntheticEvidence(); const value = caseResult();
  if (value.status !== 'ok') throw new Error('fixture');
  const artifact = value.data.artifacts[0]; artifact.kind = 'syscallTrace'; artifact.data_class = 'metadata'; artifact.native_format = 'asservat-syscall-events/v1';
  if (change === 'wrong-format') artifact.native_format = 'pcapng';
  if (change === 'wrong-class') artifact.data_class = 'extract';
  if (change === 'expired') artifact.expires_at = artifact.handling_notice.expiresAt = new Date(Date.now() - 1000).toISOString();
  if (change === 'raw-share') { artifact.data_class = 'raw'; artifact.native_format = 'asservat-syscall-arguments/v1'; value.data.case.access = 'shared'; }
  client.responder = () => value; const fetcher = vi.fn(); vi.stubGlobal('fetch', fetcher);
  render(<EvidenceWorkspace controller={new Evidence(client)} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  await screen.findByRole('button', { name: 'Refresh evidence details' });
  expect(screen.queryByRole('button', { name: 'Inspect saved syscalls' })).toBeNull(); expect(fetcher).not.toHaveBeenCalled();
});
