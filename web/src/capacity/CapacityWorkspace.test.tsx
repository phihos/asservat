import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { CapacityWorkspace } from './CapacityWorkspace';
import { validOutput_get_live_capacity } from '../generated/validate-capacity';
import type { LiveCapacityClient, LiveCapacityOutput } from './capacity-http';
import { session } from '../live/test-fixtures';

const cluster = '22222222-3333-4444-8555-666666666666';
const ok = (complete = true): LiveCapacityOutput => ({
  schema_version: 'mcp-result/v1', request_id: cluster, data_class: 'metadata', status: 'ok', warnings: [], provenance: [], truncated: false, next_cursor: null, narrowing_hint: null,
  data: { cluster_id: cluster, observed_at: '2026-11-10T08:00:00Z', fresh_until: '2026-11-10T08:00:05Z', message: complete ? 'Counters and rates cover every current live-enabled node report.' : 'At least one predecessor is missing; rates are unavailable.', nodes: 1, rates_unavailable: complete ? 0 : 1, rates_complete: complete,
    live: { cohorts: 2, scan_events: 20, scan_bytes: 200, scan_cpu_nanos: 3000, delivered_rows: 4, delivered_bytes: 400, refused_admissions: 2 },
    rates: { scan_events_per_second: 2.5, scan_bytes_per_second: 50, scan_cpu_nanos_per_second: 1000, delivered_rows_per_second: 0.5, delivered_bytes_per_second: 20, refused_admissions_per_second: 1 },
  },
});

afterEach(cleanup);
it('reads one cluster explicitly and hides partial rates and stale results', async () => {
  expect(validOutput_get_live_capacity(ok())).toBe(true);
  const calls: string[] = [];
  const client: LiveCapacityClient = { read: async id => { calls.push(id); return ok(); } };
  const scope = new AbortController();
  render(<CapacityWorkspace session={session} scope={scope.signal} client={client}/>);
  expect(calls).toHaveLength(0);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: cluster } });
  fireEvent.click(screen.getByRole('button', { name: 'Read live capacity' }));
  await waitFor(() => expect(calls).toEqual([cluster]));
  expect(screen.getByLabelText('Cumulative live runtime')).toBeTruthy();
  expect(screen.getByLabelText('Live runtime rates')).toBeTruthy();
  expect(screen.getAllByText('20', { exact: true })).toHaveLength(2);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: cluster.slice(0, -1) + '7' } });
  expect(screen.queryByLabelText('Cumulative live runtime')).toBeNull();
  expect(screen.queryByLabelText('Live runtime rates')).toBeNull();
  scope.abort();
});

it('explains incomplete rates and administrator refusal through the real result contract', async () => {
  const client: LiveCapacityClient = { read: async () => ok(false) };
  const scope = new AbortController();
  const view = render(<CapacityWorkspace session={session} scope={scope.signal} client={client}/>);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: cluster } });
  fireEvent.click(screen.getByRole('button', { name: 'Read live capacity' }));
  await waitFor(() => expect(screen.getByText('At least one predecessor is missing; rates are unavailable.')).toBeTruthy());
  expect(screen.queryByLabelText('Live runtime rates')).toBeNull();
  view.unmount();
  const refused: LiveCapacityOutput = { schema_version: 'mcp-result/v1', request_id: cluster, data_class: 'metadata', status: 'error', warnings: [], provenance: [], truncated: false, next_cursor: null, narrowing_hint: null, data: { code: 'AdministratorRequired', message: 'A current fleet operator is required.', retryable: false } };
  expect(validOutput_get_live_capacity(refused)).toBe(true);
  render(<CapacityWorkspace session={session} scope={scope.signal} client={{ read: async () => refused }}/>);
  fireEvent.change(screen.getByLabelText('Cluster ID'), { target: { value: cluster } });
  fireEvent.click(screen.getByRole('button', { name: 'Read live capacity' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('A current fleet operator is required.'));
  scope.abort();
});
