import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { ApprovalsWorkspace } from './ApprovalsWorkspace';
import type { Input, Operation, Operations, Output } from './http';
import { validInput_decide_review, validOutput_get_grant, validOutput_list_reviews, validOutput_decide_review } from '../generated/validate-approvals';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free approval fixtures for unit tests only.
const now = Date.now();
const iso = (offset: number) => new Date(now + offset).toISOString();
const principal = (subject: string) => ({ issuer: 'https://identity.invalid', subject, client_id: 'console' });
const row = {
  grant_id: id(41), phase: 'Pending', revision: 1, kind: 'adHocCapture', capture_id: id(42), preview_id: id(43), execution_digest: 'ab'.repeat(32), review_digest: 'cd'.repeat(32),
  target: { cluster_id: id(1), namespace: 'payments', workload_kind: 'Deployment', workload_name: 'api', pod_name: 'api-a' }, data_class: 'extract',
  reasons: [{ action_id: 'a1', code: 'rawBytePredicate' }], requested_by: principal('synthetic-developer'), requested_at: iso(-60_000), review_until: iso(3_540_000), plan_deadline: iso(240_000),
  lifetime_seconds: 3600, can_decide: true, can_revoke: true, approval_navigation_uri: 'https://asservat.example.invalid/approvals/' + id(41),
};
const grant = { ...row, observation_limits: { max_session_seconds: 15, max_observed_bytes: 1 << 30, max_bytes_per_second: 16 << 20, max_concurrent_sessions: 1 },
  actions: [{ action_id: 'a1', kind: 'packetCapture', execution_mode: 'ongoing', before: '30s', after: '10s', filter: 'tcp[13] & 2 != 0', filter_digest: 'ef'.repeat(32), filter_instructions: 4, max_bytes: 16 << 20, ring_max_bytes: 16 << 20, ring_max_age: '50s', sensitive: ['rawBytePredicate'] }] };

class SyntheticApprovals implements Operations {
  calls: { name: Operation; input: unknown }[] = [];
  decision?: Output<'decide_review'>;
  async call<N extends Operation>(name: N, input: Input<N>): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input) });
    if (name === 'list_reviews') return result((input as Input<'list_reviews'>).view === 'pending' ? { approvals: [row] } : { approvals: [] }) as Output<N>;
    if (name === 'get_grant') return result(grant) as Output<N>;
    if (name === 'decide_review') return (this.decision ?? result({ grant_id: id(41), phase: 'Approved', revision: 2, not_after: iso(3_600_000) })) as Output<N>;
    return result({ grant_id: id(41), phase: 'Revoked', revision: 2 }) as Output<N>;
  }
}

afterEach(cleanup);

it('fixtures match the canonical grant contracts', () => {
  expect(validOutput_list_reviews(result({ approvals: [row] }))).toBe(true);
  expect(validOutput_get_grant(result(grant))).toBe(true);
  expect(validOutput_decide_review(result({ grant_id: id(41), phase: 'Approved', revision: 2 }))).toBe(true);
  expect(validInput_decide_review({ grant_id: id(41), decision: 'approve', reason: 'incident', idempotency_key: 'k' })).toBe(true);
  expect(validInput_decide_review({ grant_id: id(41), decision: 'maybe', reason: 'incident', idempotency_key: 'k' })).toBe(false);
});

it('lists the inbox and the caller\'s requests', async () => {
  const client = new SyntheticApprovals();
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client}/>);
  expect(await screen.findByRole('link', { name: 'Deployment api' })).toHaveProperty('href', expect.stringContaining('/approvals/' + id(41)));
  expect(await screen.findByText('You have not requested an approval.')).toBeTruthy();
  expect(client.calls.map(c => c.name)).toEqual(['list_reviews', 'list_reviews']);
});

it('shows the exact plan and records one decision with a reason', async () => {
  const client = new SyntheticApprovals();
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)} newID={() => 'key-1'}/>);
  expect(await screen.findByText('tcp[13] & 2 != 0')).toBeTruthy();
  expect(screen.getByText(/raw byte comparison/)).toBeTruthy();
  expect(screen.getByText(/Observation limits bound by this approval/)).toBeTruthy();
  const approve = screen.getByRole('button', { name: 'Approve' });
  expect(approve.getAttribute('data-disabled')).not.toBeNull();
  fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: 'incident 42' } });
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
  await waitFor(() => expect(client.calls.some(c => c.name === 'decide_review')).toBe(true));
  expect(client.calls.find(c => c.name === 'decide_review')?.input).toEqual({ grant_id: id(41), decision: 'approve', reason: 'incident 42', idempotency_key: 'key-1' });
});

it('explains a step-up refusal without hiding the plan', async () => {
  const client = new SyntheticApprovals();
  client.decision = { ...result({}), status: 'error', data: { code: 'StepUpRequired', message: 'Approving needs a recent step-up sign-in.', retryable: true } } as unknown as Output<'decide_review'>;
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  await screen.findByText('tcp[13] & 2 != 0');
  fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: 'ok' } });
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('step-up'));
  expect(screen.getByText('tcp[13] & 2 != 0')).toBeTruthy();
});
