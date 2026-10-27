import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyWorkspace } from './PolicyWorkspace';
import { Policies } from './policies';
import { operations, type Input, type Operation, type Operations, type Output } from './http';
import { validOutput_get_policy_status, validOutput_deactivate_policy, validOutput_activate_policy } from '../generated/validate-policy';
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
const status = (state: string, kind: Kind = 'exit') => result<'get_capture'>({
  policy_uid: 'policy-uid', acceptance_id: id(9), state, generation: 1, expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  executor: { kind: 'policy', policy_uid: 'policy-uid' }, executions_spent: 2, max_executions: 10, collected_bytes_spent: 8192, max_collected_bytes: 65536, observed_bytes_spent: 0, max_observed_bytes: 0, watched_pods: 3, occurrences: 2, captured: 1,
  recent: [kind !== 'exit'
    ? { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: kind, failed_at: '2026-10-26T12:00:00Z', created_at: new Date().toISOString() }
    : { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: 'exit', restarts: 1, created_at: new Date().toISOString() }],
  suppressions: [{ reason: 'cooldown', count: 10, first_at: new Date().toISOString(), last_at: new Date().toISOString() },
    ...(kind === 'log' ? [{ reason: 'overlong', count: 3, first_at: new Date().toISOString(), last_at: new Date().toISOString() }] : [])],
  detector: detectors[kind],
}) as unknown as Output<'get_policy_status'>;
const failure = (code: string, message: string) => ({ ...result<'get_capture'>({}), status: 'error', data: { code, message, retryable: false } }) as unknown as Output<Operation>;

class SyntheticPolicies implements Operations {
  calls: { name: Operation; input: unknown; csrf: string }[] = [];
  state = 'active';
  unknown = false;
  kind: Kind = 'exit';
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), csrf });
    if (name === 'deactivate_policy') { this.state = 'deactivated'; return result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false }) as unknown as Output<N>; }
    if (name === 'activate_policy') return failure('PolicyDeactivated', 'This policy revision was deactivated and cannot be activated again.') as Output<N>;
    return (this.unknown ? failure('NotAvailable', 'Not available.') : status(this.state, this.kind)) as Output<N>;
  }
}

const controllers: Policies[] = [];
afterEach(() => { cleanup(); for (const c of controllers) c.reset(); controllers.length = 0; vi.unstubAllGlobals(); });
function mount() {
  const client = new SyntheticPolicies(); let n = 20; const controller = new Policies(client, () => id(n++)); controllers.push(controller);
  render(<PolicyWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  return { client, controller };
}

it('fixtures match the canonical policy contracts', () => {
  expect(validOutput_get_policy_status(status('deactivated'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'probe'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'alert'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'log'))).toBe(true);
  expect(validOutput_get_policy_status(status('active', 'resource'))).toBe(true);
  expect(validOutput_deactivate_policy(result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: true }))).toBe(true);
  expect(validOutput_activate_policy(failure('PolicyDeactivated', 'x'))).toBe(true);
});

it('shows content-free status and deactivates with CSRF and one idempotency key', async () => {
  const { client } = mount();
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText('Active')).toBeTruthy();
  expect(screen.getByText('2 of 10 used')).toBeTruthy();
  expect(screen.getByText(`${(8192).toLocaleString()} of ${(65536).toLocaleString()} bytes reserved`)).toBeTruthy();
  expect(screen.getByText('0 of 0 bytes charged before filtering')).toBeTruthy();
  expect(screen.getByText(/budgets are shared across captures and grants/)).toBeTruthy();
  expect(screen.getByText('10 × cooldown or workload budget')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'View capture' }).getAttribute('href')).toBe('/captures/' + id(8));
  expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }));
  expect(await screen.findByText('Deactivated')).toBeTruthy();
  const stop = client.calls.find(c => c.name === 'deactivate_policy')!;
  expect(stop.csrf).toBe(session.csrf_token);
  expect(stop.input).toEqual({ policy_name: 'regional-restarts', idempotency_key: id(20) });
  expect(screen.queryByRole('button', { name: 'Deactivate' })).toBeNull();
  // An unchanged deactivated revision cannot be activated again: no button, only the hint.
  expect(screen.queryByRole('button', { name: 'Activate' })).toBeNull();
  expect(screen.getByText(/change the DebugPolicy to activate a new revision/)).toBeTruthy();
  // After the DebugPolicy changes, status reports `changed` and Activate returns.
  client.state = 'changed';
  fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
  expect(await screen.findByText('Changed since activation')).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Activate' })).toBeTruthy();
});

it('names the detector and shows a probe occurrence by its failure time', async () => {
  const { client } = mount();
  client.kind = 'probe';
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-probes' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText('Readiness probe failures: 2 failures within 60 s (Kubernetes Events)')).toBeTruthy();
  expect(screen.getByText(/probe failure at/)).toBeTruthy();
  expect(screen.queryByText(/\(restart /)).toBeNull();
});

it('names the alert detector and shows an alert occurrence by its start time', async () => {
  const { client } = mount();
  client.kind = 'alert';
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-alerts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText('Firing Alertmanager alerts naming a pod of the workload')).toBeTruthy();
  expect(screen.getByText(/alert started at/)).toBeTruthy();
  expect(screen.queryByText(/\(restart /)).toBeNull();
});

it('names the log and resource detectors without their pattern (ADR-241)', async () => {
  const { client } = mount();
  client.kind = 'log';
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-logs' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText('Container log records matching a regular expression in a JSON field within 30 s (Kubernetes log API)')).toBeTruthy();
  expect(screen.getByText(/matching log record at/)).toBeTruthy();
  expect(screen.getByText(/3 × log records longer than the record limit, not evaluated/)).toBeTruthy();
  client.kind = 'resource';
  fireEvent.click(screen.getByRole('button', { name: 'Check status' }));
  expect(await screen.findByText('CPU usage / CPU limit > 0.8, samples at most 60 s old (Kubernetes metrics API)')).toBeTruthy();
  expect(screen.getByText(/resource condition met at/)).toBeTruthy();
});

it('offers activation of a policy without status and shows the server refusal', async () => {

  const { client } = mount();
  client.unknown = true;
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Activate' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/cannot be activated again/));
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
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText(/^Repeated collections will be shared with 2 recipients until .*: 3 of 10 captures shared \(sharing\)$/)).toBeTruthy();
  const status = await client.call('get_policy_status', { policy_name: 'p' }, 'C'.repeat(43));
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

// ADR-239 (REQ-SHR-005): a sharing policy is activated only after the user
// saw the server's review and chose "Activate and share".
it('shows the sharing review before activating a sharing policy', async () => {
  const client = new SyntheticPolicies();
  client.unknown = true;
  const activations: unknown[] = [];
  const original = client.call.bind(client);
  client.call = (async (name: Operation, input: unknown, csrf: string) => {
    if (name !== 'activate_policy') return original(name, input as never, csrf);
    activations.push(structuredClone(input));
    if (!(input as { sharing_reviewed?: boolean }).sharing_reviewed) return failure('SharingReviewRequired', 'Repeated collections will be shared with Group incident-response: at most the next 10 capture(s) of this policy until 2026-10-28T18:00:00Z.');
    client.unknown = false;
    return result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'active', expires_at: '2026-10-28T18:00:00Z', max_executions: 10, replay: false }) as never;
  }) as typeof client.call;
  let n = 40; const controller = new Policies(client, () => id(n++)); controllers.push(controller);
  render(<PolicyWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Activate' }));
  expect(await screen.findByText(/^Repeated collections will be shared with Group incident-response/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Activate and share' }));
  expect(await screen.findByText('Active')).toBeTruthy();
  expect(activations).toEqual([{ policy_name: 'regional-restarts', idempotency_key: id(40) }, { policy_name: 'regional-restarts', idempotency_key: id(41), sharing_reviewed: true }]);
  expect(screen.queryByRole('button', { name: 'Activate and share' })).toBeNull();
});

it('sends the identical idempotency header for policy commands', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false })), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await operations.call('deactivate_policy', { policy_name: 'p', idempotency_key: id(3) }, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/deactivate_policy');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});

it('rejects missing shared pools and does not present charges as gathered output', () => {
 const reply = structuredClone(status('active'));
 if (reply.status !== 'ok') throw new Error('fixture');
 const missing = structuredClone(reply) as unknown as { data: Record<string, unknown> };
 delete missing.data.observed_bytes_spent;
 expect(validOutput_get_policy_status(missing)).toBe(false);
 reply.data.observed_bytes_spent = 8192; reply.data.max_observed_bytes = 8192;
 expect(validOutput_get_policy_status(reply)).toBe(true);
});
