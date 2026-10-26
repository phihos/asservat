import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyWorkspace } from './PolicyWorkspace';
import { Policies } from './policies';
import { operations, type Input, type Operation, type Operations, type Output } from './http';
import { validOutput_get_policy_status, validOutput_deactivate_policy, validOutput_activate_policy } from '../generated/validate-policy';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free policy fixtures for unit tests only.
const status = (state: string) => result<'get_capture'>({
  policy_uid: 'policy-uid', acceptance_id: id(9), state, generation: 1, expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  executor: { kind: 'policy', policy_uid: 'policy-uid' }, executions_spent: 2, max_executions: 10, watched_pods: 3, occurrences: 2, captured: 1,
  recent: [{ occurrence_id: id(10), capture_id: id(8), outcome: 'captured', restarts: 1, created_at: new Date().toISOString() }],
  suppressions: [{ reason: 'cooldown', count: 10, first_at: new Date().toISOString(), last_at: new Date().toISOString() }],
}) as unknown as Output<'get_policy_status'>;
const failure = (code: string, message: string) => ({ ...result<'get_capture'>({}), status: 'error', data: { code, message, retryable: false } }) as unknown as Output<Operation>;

class SyntheticPolicies implements Operations {
  calls: { name: Operation; input: unknown; csrf: string }[] = [];
  state = 'active';
  unknown = false;
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), csrf });
    if (name === 'deactivate_policy') { this.state = 'deactivated'; return result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false }) as unknown as Output<N>; }
    if (name === 'activate_policy') return failure('PolicyDeactivated', 'This policy revision was deactivated and cannot be activated again.') as Output<N>;
    return (this.unknown ? failure('NotAvailable', 'Not available.') : status(this.state)) as Output<N>;
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
});

it('offers activation of a policy without status and shows the server refusal', async () => {
  const { client } = mount();
  client.unknown = true;
  fireEvent.change(screen.getByLabelText('Policy name'), { target: { value: 'regional-restarts' } });
  fireEvent.click(screen.getByRole('button', { name: 'Show policy' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Activate' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/cannot be activated again/));
});

it('sends the identical idempotency header for policy commands', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(result({ policy_uid: 'policy-uid', acceptance_id: id(9), state: 'deactivated', replay: false })), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await operations.call('deactivate_policy', { policy_name: 'p', idempotency_key: id(3) }, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/deactivate_policy');
  expect(fetcher.mock.calls[0][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});
