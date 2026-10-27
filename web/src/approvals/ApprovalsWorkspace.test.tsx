import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ApprovalsWorkspace } from './ApprovalsWorkspace';
import type { Input, Operation, Operations, Output } from './http';
import { validInput_decide_review, validOutput_get_grant, validOutput_list_reviews, validOutput_decide_review } from '../generated/validate-approvals';
import { id, result, session, SyntheticOperations, acceptedResult, resolvedAcceptedResult } from '../capture/test-fixtures';

// Synthetic, content-free approval fixtures for unit tests only.
const now = Date.now();
const iso = (offset: number) => new Date(now + offset).toISOString();
const principal = (subject: string) => ({ issuer: 'https://identity.invalid', subject, client_id: 'console' });
const row = {
  grant_id: id(41), phase: 'Pending', revision: 1, kind: 'adHocCapture', capture_id: id(42), preview_id: id(43), execution_digest: 'ab'.repeat(32), review_digest: 'cd'.repeat(32),
  target: { cluster_id: id(1), namespace: 'payments', workload_kind: 'Deployment', workload_name: 'api', pod_name: 'api-a' }, data_class: 'extract',
  reasons: [{ action_id: 'a1', code: 'rawBytePredicate' }], requested_by: principal('synthetic-developer'), requested_at: iso(-60_000), review_until: iso(3_540_000), preview_deadline: iso(-240_000), capture_deadline_rule: 'acceptanceWithinGrant', capture_window_seconds: 300,
  lifetime_seconds: 3600, can_decide: true, can_revoke: true, approval_navigation_uri: 'https://asservat.example.invalid/approvals/' + id(41),
};
const grant = { ...row, can_resume: false, can_resolve: false, observation_limits: { max_session_seconds: 15, max_observed_bytes: 1 << 30, max_bytes_per_second: 16 << 20, max_concurrent_sessions: 1 },
  actions: [{ action_id: 'a1', kind: 'packetCapture', execution_mode: 'ongoing', before: '30s', after: '10s', filter: 'tcp[13] & 2 != 0', filter_digest: 'ef'.repeat(32), filter_instructions: 4, max_bytes: 16 << 20, ring_max_bytes: 16 << 20, ring_max_age: '50s', sensitive: ['rawBytePredicate'] }] };

class SyntheticApprovals implements Operations {
  calls: { name: Operation; input: unknown }[] = [];
  decision?: Output<'decide_review'>;
  detail = grant;
  async call<N extends Operation>(name: N, input: Input<N>): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input) });
    if (name === 'list_reviews') return result((input as Input<'list_reviews'>).view === 'pending' ? { approvals: [row] } : { approvals: [] }) as Output<N>;
    if (name === 'get_grant') return result(this.detail) as Output<N>;
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
  expect(screen.getByRole('link', { name: 'Sign in with step-up' }).getAttribute('href')).toBe('/auth/step-up?return_to=' + encodeURIComponent('/approvals/' + id(41)));
  expect(screen.getByText(/Observation limits bound by this approval/)).toBeTruthy();
  expect(screen.getByText(/submitting this plan starts a capture window of at most 5 minutes/)).toBeTruthy();
  expect(screen.queryByText(/plan's start deadline/)).toBeNull();
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

it('resumes one exact original preview with the same key after a lost reply and remount', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Approved', can_resume: true, can_resolve: true };
  const capture = new SyntheticOperations(); capture.responder = () => { throw new Error('lost accepted reply'); };
  const opened = vi.fn(); const scope = new AbortController();
  const first = render(<ApprovalsWorkspace session={session} scope={scope.signal} client={client} captureClient={capture} grantID={id(41)} onAccepted={opened}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Continue approved capture' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringContaining('same reviewed request'));
  const original = capture.calls[0].input;
  first.unmount(); capture.responder = () => acceptedResult();
  render(<ApprovalsWorkspace session={session} scope={scope.signal} client={client} captureClient={capture} grantID={id(41)} onAccepted={opened}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Continue approved capture' }));
  await waitFor(() => expect(opened).toHaveBeenCalledWith(id(8)));
  expect(capture.calls.map(c => c.name)).toEqual(['request_capture', 'request_capture']);
  expect(capture.calls.map(c => c.input)).toEqual([original, original]);
  expect(original).toMatchObject({ preview_id: id(43), continue_acquisition: true });
});

it('keeps another original OAuth client from resuming and explains the requesting client', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Approved', requested_by: principal('synthetic-developer') };
  client.detail.requested_by.client_id = 'mcp';
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByText(/original requesting client \(mcp\)/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Continue approved capture' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Resolve original request' })).toBeNull();
});

it('resolves an expired grant original outcome without attempting acquisition', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Expired', can_resolve: true };
  const capture = new SyntheticOperations(); capture.responder = () => resolvedAcceptedResult(); const opened = vi.fn();
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} captureClient={capture} grantID={id(41)} onAccepted={opened}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Resolve original request' }));
  await waitFor(() => expect(opened).toHaveBeenCalledWith(id(8)));
  expect(capture.calls.map(c => c.name)).toEqual(['resolve_capture_request']);
});

it('cancels resume on unmount and ignores a late accepted reply', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Approved', can_resume: true, can_resolve: true };
  const capture = new SyntheticOperations(); let complete!: (value: ReturnType<typeof acceptedResult>) => void;
  capture.responder = () => new Promise(resolve => { complete = resolve; });
  const opened = vi.fn();
  const page = render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} captureClient={capture} grantID={id(41)} onAccepted={opened}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Continue approved capture' }));
  await waitFor(() => expect(capture.calls).toHaveLength(1));
  page.unmount();
  expect(capture.calls[0].signal.aborted).toBe(true);
  complete(acceptedResult());
  await Promise.resolve();
  expect(opened).not.toHaveBeenCalled();
});
