import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyWorkspace } from './PolicyWorkspace';
import { Policies } from './policies';
import { operations, type Input, type Operation, type Operations, type Output } from './http';
import { validOutput_get_policy_status, validOutput_deactivate_policy, validOutput_activate_policy } from '../generated/validate-policy';
import { validOutput_revoke_share } from '../generated/validate-sharing';
import type { Operations as ShareOperations } from '../sharing/http';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free policy fixtures for unit tests only.
const status = (state: string, kind: 'exit' | 'probe' | 'alert' = 'exit') => result<'get_capture'>({
  policy_uid: 'policy-uid', acceptance_id: id(9), state, generation: 1, expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  executor: { kind: 'policy', policy_uid: 'policy-uid' }, executions_spent: 2, max_executions: 10, watched_pods: 3, occurrences: 2, captured: 1,
  recent: [kind !== 'exit'
    ? { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: kind, failed_at: '2026-10-26T12:00:00Z', created_at: new Date().toISOString() }
    : { occurrence_id: id(10), capture_id: id(8), outcome: 'captured', detector: 'exit', restarts: 1, created_at: new Date().toISOString() }],
  suppressions: [{ reason: 'cooldown', count: 10, first_at: new Date().toISOString(), last_at: new Date().toISOString() }],
  detector: kind === 'probe' ? { kind: 'probe', probe_type: 'Readiness', minimum_failures: 2, window_seconds: 60 } : kind === 'alert' ? { kind: 'alert' } : { kind: 'exit', reasons: ['Error', 'OOMKilled'] },
}) as unknown as Output<'get_policy_status'>;
const failure = (code: string, message: string) => ({ ...result<'get_capture'>({}), status: 'error', data: { code, message, retryable: false } }) as unknown as Output<Operation>;

class SyntheticPolicies implements Operations {
  calls: { name: Operation; input: unknown; csrf: string }[] = [];
  state = 'active';
  unknown = false;
  kind: 'exit' | 'probe' | 'alert' = 'exit';
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
  expect(validOutput_deactivate_policy(result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: true }))).toBe(true);
  expect(validOutput_activate_policy(failure('PolicyDeactivated', 'x'))).toBe(true);
});

it('shows content-free status and deactivates with CSRF and one idempotency key', async () => {
  const { client } = mount();
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText('Active')).toBeTruthy();
  expect(screen.getByText('2 of 10 used')).toBeTruthy();
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

it('offers activation of a policy without status and shows the server refusal', async () => {
  const { client } = mount();
  client.unknown = true;
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Activate' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/cannot be activated again/));
});

// ADR-239: a policy with recurring sharing states it, and Revoke all shares
// calls revoke_share with the acceptance as sharing_intent_id.
it('states recurring sharing and revokes all its shares', async () => {
  const client = new SyntheticPolicies();
  const shareCalls: { name: string; input: unknown; csrf: string }[] = [];
  let revoked = false;
  const original = client.call.bind(client);
  client.call = (async (name: Operation, input: unknown, csrf: string) => {
    const reply = await original(name, input as never, csrf) as Output<'get_policy_status'>;
    if (name !== 'get_policy_status' || reply.status !== 'ok') return reply;
    return { ...reply, data: { ...reply.data, sharing: { state: revoked ? 'revoked' : 'active', recipients: 2, shared_captures: 3, max_captures: 10, not_after: '2026-10-28T18:00:00Z', ...(revoked ? { revoked_at: '2026-10-26T12:00:00Z' } : {}) } } };
  }) as typeof client.call;
  const shares: ShareOperations = {
    async call(name, input, csrf) {
      shareCalls.push({ name, input: structuredClone(input), csrf }); revoked = true;
      return result({ sharing_intent_id: id(9), phase: 'Revoked', revision: 2 }) as never;
    },
  };
  let n = 30; const controller = new Policies(client, () => id(n++), shares); controllers.push(controller);
  render(<PolicyWorkspace session={session} scope={new AbortController().signal} controller={controller}/>);
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  expect(await screen.findByText(/^Repeated collections will be shared with 2 recipients until .*: 3 of 10 captures shared \(sharing\)$/)).toBeTruthy();
  const status = await client.call('get_policy_status', { policy_name: 'p' }, 'C'.repeat(43));
  expect(validOutput_get_policy_status(status)).toBe(true);
  expect(validOutput_revoke_share(result({ sharing_intent_id: id(9), phase: 'Revoked', revision: 2 }))).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Revoke all shares' }));
  expect(await screen.findByText(/\(revoked\)$/)).toBeTruthy();
  expect(shareCalls).toEqual([{ name: 'revoke_share', input: { sharing_intent_id: id(9), expected_revision: 1, idempotency_key: id(30) }, csrf: session.csrf_token }]);
  expect(screen.queryByRole('button', { name: 'Revoke all shares' })).toBeNull();
});

it('sends the identical idempotency header for policy commands', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false })), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await operations.call('deactivate_policy', { policy_name: 'p', idempotency_key: id(3) }, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/deactivate_policy');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});
