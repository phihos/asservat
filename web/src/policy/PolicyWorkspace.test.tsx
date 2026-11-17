import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyWorkspace } from './PolicyWorkspace';
import { Policies } from './policies';
import { operations, type Input, type Operation, type Operations, type Output } from './http';
import { validInput_get_policy_status, validOutput_get_policy_status, validOutput_deactivate_policy } from '../generated/validate-policy';
import { validOutput_revoke_share, validOutput_stop_future_sharing } from '../generated/validate-sharing';
import type { Operations as ShareOperations } from '../sharing/http';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free policy fixtures for unit tests only.
type Kind = 'exit' | 'probe' | 'alert' | 'log' | 'resource';
const detectors: Record<Kind, unknown> = {
  exit: { kind: 'exit', reasons: ['Error', 'OOMKilled'] },
  probe: { kind: 'probe', probe_type: 'Readiness', minimum_failures: 2, window_seconds: 60 },
  alert: { kind: 'alert' },
  log: { kind: 'log', match: 'regexp', json_field: true, window_seconds: 30 },
  resource: { kind: 'resource', metric: 'cpuQuotaRatio', operator: 'gt', threshold: 0.8, sample_interval_seconds: 60 },
};
const ref = { cluster: 'local', namespace: 'team-a' };
const status = (state: string, kind: Kind = 'exit') => result<'get_capture'>({
  policy_name: 'regional-restarts', namespace: 'team-a', policy_uid: 'policy-uid', acceptance_id: id(9), state, generation: 1, expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  collection_kind: 'podStatus', executor: { kind: 'policy', policy_uid: 'policy-uid' }, executions_spent: 2, collected_bytes_spent: 8192, max_collected_bytes: 65536, watched_pods: 3, occurrences: 2, captured: 1,
  recent: [kind !== 'exit'
    ? { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: kind, failed_at: '2026-10-26T12:00:00Z', created_at: new Date().toISOString() }
    : { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: 'exit', restarts: 1, created_at: new Date().toISOString() }],
  suppressions: [{ reason: 'cooldown', count: 10, first_at: new Date().toISOString(), last_at: new Date().toISOString() },
    ...(kind === 'log' ? [{ reason: 'overlong', count: 3, first_at: new Date().toISOString(), last_at: new Date().toISOString() }] : [])],
  detector: detectors[kind],
}) as unknown as Output<'get_policy_status'>;

class SyntheticPolicies implements Operations {
  calls: { name: Operation; input: unknown; csrf: string }[] = [];
  state = 'active';
  kind: Kind = 'exit';
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), csrf });
    if (name === 'deactivate_policy') { this.state = 'deactivated'; return result({ policy_name: 'regional-restarts', namespace: 'team-a', policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false }) as unknown as Output<N>; }
    return status(this.state, this.kind) as Output<N>;
  }
}

const controllers: Policies[] = [];
afterEach(() => { cleanup(); for (const c of controllers) c.reset(); controllers.length = 0; vi.unstubAllGlobals(); });
function mount() {
  const client = new SyntheticPolicies(); let n = 20; const controller = new Policies(client, () => id(n++)); controllers.push(controller);
  render(<PolicyWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  return { client, controller };
}
function show(name: string) {
  fireEvent.change(screen.getByLabelText('Namespace'), { target: { value: ref.namespace } });
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: name } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
}

it('fixtures match the canonical policy contracts', () => {
  expect(validOutput_get_policy_status(status('deactivated'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'probe'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'alert'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'log'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'resource'))).toBe(true);
  expect(validOutput_deactivate_policy(result({ policy_name: 'p', namespace: 'team-a', acceptance_id: id(9), state: 'deactivated', replay: true }))).toBe(true);
  expect(validOutput_get_policy_status(status('renewalDue'))).toBe(true);
  expect(validOutput_get_policy_status(status('changed'))).toBe(false);
  expect(validInput_get_policy_status({ ...ref, policy_name: 'p' })).toBe(true);
  expect(validInput_get_policy_status({ policy_name: 'p' })).toBe(false);
});

it('shows content-free status and deactivates with CSRF and one idempotency key', async () => {
  const { client } = mount();
  expect((screen.getByLabelText('Cluster') as HTMLInputElement).value).toBe('local');
  show('regional-restarts');
  expect(await screen.findByText('Active')).toBeTruthy();
  expect(client.calls[0].input).toEqual({ ...ref, policy_name: 'regional-restarts' });
  expect(screen.getByText(`${(8192).toLocaleString()} of ${(65536).toLocaleString()} bytes`)).toBeTruthy();
  expect(screen.getByText('10 × cooldown or workload budget')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'View capture' }).getAttribute('href')).toBe('/captures/' + id(8));
  fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));
  expect(await screen.findByText('Deactivated')).toBeTruthy();
  const stop = client.calls.find(c => c.name === 'deactivate_policy')!;
  expect(stop.csrf).toBe(session.csrf_token);
  expect(stop.input).toEqual({ ...ref, policy_name: 'regional-restarts', idempotency_key: id(20) });
  expect(screen.queryByRole('button', { name: 'Deactivate' })).toBeNull();
  expect(screen.getByText(/Change the DebugPolicy to start a new revision/)).toBeTruthy();
  // RenewalDue keeps the policy running and points at the approvals inbox.
  client.state = 'renewalDue';
  fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
  expect(await screen.findByText(/renewal due: an approver can renew it in the approvals inbox/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Deactivate' })).toBeTruthy();
});

it('names the detector and shows a probe occurrence by its failure time', async () => {
  const { client } = mount();
  client.kind = 'probe';
  show('regional-probes');
  expect(await screen.findByText('Readiness probe failures: 2 failures within 60 s (Kubernetes Events)')).toBeTruthy();
  expect(screen.getByText(/probe failure at/)).toBeTruthy();
  expect(screen.queryByText(/\(restart /)).toBeNull();
});

it('names the alert detector and shows an alert occurrence by its start time', async () => {
  const { client } = mount();
  client.kind = 'alert';
  show('regional-alerts');
  expect(await screen.findByText('Firing Alertmanager alerts naming a pod of the workload')).toBeTruthy();
  expect(screen.getByText(/alert started at/)).toBeTruthy();
  expect(screen.queryByText(/\(restart /)).toBeNull();
});

it('names the log and resource detectors without their pattern (ADR-241)', async () => {
  const { client } = mount();
  client.kind = 'log';
  show('regional-logs');
  expect(await screen.findByText('Container log records matching a regular expression in a JSON field within 30 s (Kubernetes log API)')).toBeTruthy();
  expect(screen.getByText(/matching log record at/)).toBeTruthy();
  expect(screen.getByText(/3 × log records longer than the record limit, not evaluated/)).toBeTruthy();
  client.kind = 'resource';
  fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
  expect(await screen.findByText('CPU usage / CPU limit > 0.8, samples at most 60 s old (Kubernetes metrics API)')).toBeTruthy();
  expect(screen.getByText(/resource condition met at/)).toBeTruthy();
});

// ADR-239: a policy with recurring sharing states it; Stop future sharing and
// Revoke all shares call the sharing operations with the acceptance ID.
it('states recurring sharing, stops it and revokes all its shares', async () => {
  const client = new SyntheticPolicies();
  const shareCalls: { name: string; input: unknown; csrf: string }[] = [];
  let stopped = false, revoked = false;
  const original = client.call.bind(client);
  client.call = (async (name: Operation, input: unknown, csrf: string) => {
    const reply = await original(name, input as never, csrf) as Output<'get_policy_status'>;
    if (name !== 'get_policy_status' || reply.status !== 'ok') return reply;
    const state = revoked ? 'revoked' : stopped ? 'stopped' : 'active';
    return { ...reply, data: { ...reply.data, sharing: { state, recipients: 2, shared_captures: 3, max_captures: 10, not_after: '2026-10-28T18:00:00Z', revision: 1 + (stopped ? 1 : 0) + (revoked ? 1 : 0),
      ...(stopped ? { stopped_at: '2026-10-26T11:00:00Z' } : {}), ...(revoked ? { revoked_at: '2026-10-26T12:00:00Z' } : {}) } } };
  }) as typeof client.call;
  const shares: ShareOperations = {
    async call(name, input, csrf) {
      shareCalls.push({ name, input: structuredClone(input), csrf });
      if (name === 'stop_future_sharing') { stopped = true; return result({ sharing_intent_id: id(9), state: 'Stopped', revision: 2 }) as never; }
      revoked = true;
      return result({ sharing_intent_id: id(9), phase: 'Revoked', revision: 3 }) as never;
    },
  };
  let n = 30; const controller = new Policies(client, () => id(n++), shares); controllers.push(controller);
  render(<PolicyWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  show('regional-restarts');
  expect(await screen.findByText(/^Repeated collections will be shared with 2 recipients until .*: 3 of 10 captures shared \(sharing\)$/)).toBeTruthy();
  const status = await client.call('get_policy_status', { ...ref, policy_name: 'p' }, 'C'.repeat(43));
  expect(validOutput_get_policy_status(status)).toBe(true);
  expect(validOutput_stop_future_sharing(result({ sharing_intent_id: id(9), state: 'Stopped', revision: 2 }))).toBe(true);
  expect(validOutput_revoke_share(result({ sharing_intent_id: id(9), phase: 'Revoked', revision: 3 }))).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Stop future sharing' }));
  expect(await screen.findByText(/future sharing stopped/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Stop future sharing' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Revoke all shares' }));
  expect(await screen.findByText(/\(revoked\)$/)).toBeTruthy();
  expect(shareCalls).toEqual([
    { name: 'stop_future_sharing', input: { sharing_intent_id: id(9), expected_revision: 1, idempotency_key: id(30) }, csrf: session.csrf_token },
    { name: 'revoke_share', input: { sharing_intent_id: id(9), expected_revision: 2, idempotency_key: id(31) }, csrf: session.csrf_token },
  ]);
  expect(screen.queryByRole('button', { name: 'Revoke all shares' })).toBeNull();
});

it('sends the identical idempotency header for policy commands', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(result({ policy_name: 'p', namespace: 'team-a', acceptance_id: id(9), state: 'deactivated', replay: false })), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await operations.call('deactivate_policy', { ...ref, policy_name: 'p', idempotency_key: id(3) }, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/deactivate_policy');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});

