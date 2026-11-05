import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ApprovalsWorkspace } from './ApprovalsWorkspace';
import { operations as approvalOperations } from './http';
import type { Data, Input, Operation, Operations, Output } from './http';
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
} satisfies Data<'list_reviews'>['approvals'][number];
type CollectionGrant = Extract<Data<'get_grant'>, { kind: 'adHocCapture' | 'policy' }>;
const grant: CollectionGrant = { ...row, can_resume: false, can_resolve: false, resume_requires_original_client: false, observation_limits: { max_session_seconds: 15, max_observed_bytes: 1 << 30, max_bytes_per_second: 16 << 20, max_concurrent_sessions: 1 },
  actions: [{ action_id: 'a1', kind: 'packetCapture', execution_mode: 'ongoing', before: '30s', after: '10s', filter: 'tcp[13] & 2 != 0', filter_digest: 'ef'.repeat(32), filter_instructions: 4, max_bytes: 16 << 20, ring_max_bytes: 16 << 20, ring_max_age: '50s', sensitive: ['rawBytePredicate'] }] };

class SyntheticApprovals implements Operations {
  calls: { name: Operation; input: unknown }[] = [];
  decision?: Output<'decide_review'>;
  detail: Data<'get_grant'> = grant;
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
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Approved', resume_requires_original_client: true, requested_by: principal('synthetic-developer') };
  client.detail.requested_by.client_id = 'mcp';
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByText(/original requesting client \(mcp\)/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Continue approved capture' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Find capture; otherwise close request' })).toBeNull();
});

it('resolves an expired grant original outcome without attempting acquisition', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Expired', can_resolve: true };
  const capture = new SyntheticOperations(); capture.responder = () => resolvedAcceptedResult(); const opened = vi.fn();
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} captureClient={capture} grantID={id(41)} onAccepted={opened}/>);
  fireEvent.click(await screen.findByRole('button', { name: 'Find capture; otherwise close request' }));
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

it.each(['Pending', 'Denied'] as const)('never offers destructive outcome lookup or client guidance for %s review', async phase => {
 const client = new SyntheticApprovals(); client.detail = { ...grant, phase, can_resolve: true, resume_requires_original_client: true };
 render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
 await screen.findByText('tcp[13] & 2 != 0');
 expect(screen.queryByRole('button', { name: 'Find capture; otherwise close request' })).toBeNull();
 expect(screen.queryByText(/original requesting client/)).toBeNull();
});
it('does not tell an independent approved-plan reviewer to continue the requester capture', async () => {
 const client = new SyntheticApprovals(); client.detail = { ...grant, phase: 'Approved', requested_by: principal('another-developer') };
 render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
 await screen.findByText('tcp[13] & 2 != 0');
 expect(screen.queryByText(/original requesting client/)).toBeNull();
});


function teamPolicyGrant(): CollectionGrant {
  const value: CollectionGrant = { ...structuredClone(grant), kind: 'policy', phase: 'Approved', revision: 2, capture_deadline_rule: 'policyAuthority',
    reasons: [{ action_id: 'a1', code: 'policyCollection' }],
    target: { cluster_id: id(1), namespace: 'payments', namespace_uid: 'namespace-uid', workload_kind: 'Deployment', workload_name: 'api', workload_uid: 'workload-uid' },
    policy: { uid: 'team-policy-uid', executor: principal('installation-policy-executor'), authority_issued_at: iso(-86_400_000), authority_not_after: iso(30*86_400_000), max_executions: 10, max_collected_bytes: 64 << 20, max_observed_bytes: 1 << 30, executions_used: 4, collected_bytes_used: 16 << 20, observed_bytes_used: 4000 },
    requested_by: principal('departed-requester'), not_after: iso(3_600_000), can_decide: false, can_revoke: true,
    decision: { decision: 'approved', decided_by: principal('independent-reviewer'), decided_at: iso(-30_000), reason: 'finite team collection', authentication_context: { acr: 'mfa', authenticated_at: iso(-40_000) } },
    can_resume: false, can_resolve: false, resume_requires_original_client: false,
  };
  delete value.capture_id; delete value.preview_id; delete value.preview_deadline; delete value.capture_window_seconds;
  return value;
}

it('shows original team policy scope and budgets to a current manager without offering review or personal capture', async () => {
  const client = new SyntheticApprovals(); client.detail = teamPolicyGrant();
  expect(validOutput_get_grant(result(client.detail))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)} newID={() => 'manager-revoke-key'}/>);
  expect(await screen.findByText('team-policy-uid')).toBeTruthy();
  expect(screen.getByText('installation-policy-executor')).toBeTruthy();
  expect(screen.getByText(/4 of 10 action starts/)).toBeTruthy();
  expect(screen.getByText(/recurring policy collection uses a separate finite approval and shared budgets/)).toBeTruthy();
  expect(screen.getByText(/16 MiB of 64 MiB output/)).toBeTruthy();
  expect(screen.getByText(/This approval grants no evidence access/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Continue approved capture' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Find capture; otherwise close request' })).toBeNull();
  expect(screen.queryByRole('link', { name: 'Sign in with step-up' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Revoke approval' }));
  await waitFor(() => expect(client.calls.some(call => call.name === 'revoke_grant')).toBe(true));
  expect(client.calls.find(call => call.name === 'revoke_grant')?.input).toEqual({ grant_id: id(41), expected_revision: 2, idempotency_key: 'manager-revoke-key' });
  expect(client.calls.some(call => call.name === 'decide_review')).toBe(false);
});

it('does not infer team revocation from requester provenance and rejects personal placeholders in policy DTOs', async () => {
  const client = new SyntheticApprovals(); client.detail = { ...teamPolicyGrant(), can_revoke: false };
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByText('team-policy-uid')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Revoke approval' })).toBeNull();
  for (const patch of [{ capture_id: id(42) }, { preview_id: id(43) }, { preview_deadline: iso(60_000) }, { can_resume: true }, { can_resolve: true }, { resume_requires_original_client: true }, { target: { ...client.detail.target, pod_name: 'invented' } }]) {
    expect(validOutput_get_grant(result({ ...client.detail, ...patch }))).toBe(false);
  }
});

it('shows profile parameters and endpoint without a fabricated recording ring', async () => {
  const client = new SyntheticApprovals();
  const profile: CollectionGrant = { ...grant, observation_limits: undefined, data_class: 'raw', reasons: [{ action_id: 'heap', code: 'liveProfile' }],
    actions: [{ action_id: 'heap', kind: 'profile', execution_mode: 'onTrigger', max_bytes: 16 << 20, sensitive: ['liveProfile'], profile: { runtime: 'go', type: 'heap', mode: 'snapshot', source: 'httpEndpoint', timeout: '5s', force_gc: true, source_ref: 'go-endpoint', source_name: 'go-pprof-loopback', address_mode: 'targetLoopback', port: 6060, path_policy: 'go-pprof/v1', endpoint_digest: 'ab'.repeat(32) } }] };
  client.detail = profile;
  expect(validOutput_get_grant(result(client.detail))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByText(/Go profile/)).toBeTruthy();
  expect(screen.getByText(/heap · snapshot/)).toBeTruthy();
  expect(screen.getByText(/forced GC enabled/)).toBeTruthy();
  expect(screen.getByText(/target Pod loopback, TCP port 6060/)).toBeTruthy();
  expect(screen.getByText('No pre-trigger history')).toBeTruthy();
  expect(screen.queryByText('Syscalls')).toBeNull();
  expect(screen.queryByText(/0 bytes/)).toBeNull();
  const mixed = structuredClone(profile); Object.assign(mixed.actions[0], { ring_max_bytes: 16 << 20 });
  expect(validOutput_get_grant(result(mixed))).toBe(false);
  const missing = structuredClone(profile); delete missing.actions[0].profile;
  expect(validOutput_get_grant(result(missing))).toBe(false);
});

it.each(['templateBinding', 'administratorProfile'] as const)('shows a recurring profile endpoint definition (%s)', async sourceKind => {
  const client = new SyntheticApprovals();
  const policy: CollectionGrant = { ...teamPolicyGrant(), data_class: 'raw', observation_limits: undefined,
    actions: [{ action_id: 'cpu', kind: 'profile', execution_mode: 'onTrigger', max_bytes: 16 << 20, sensitive: ['liveProfile'], profile: {
      runtime: 'go', type: 'cpu', mode: 'interval', source: 'httpEndpoint', duration: '10s', timeout: '15s', force_gc: false,
      source_ref: 'go-endpoint', source_name: 'go-pprof-loopback', address_mode: 'targetLoopback', path_policy: 'go-pprof/v1',
      source_kind: sourceKind, definition_digest: 'cd'.repeat(32),
      ...(sourceKind === 'templateBinding' ? { declared_port_name: 'pprof', minimum_port: 6000, maximum_port: 7000 } : { port: 6060 }),
    } }] };
  client.detail = policy;
  expect(validOutput_get_grant(result(policy))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByText(/cpu · interval/)).toBeTruthy();
  expect(screen.getByText(/forced GC disabled/)).toBeTruthy();
  expect(screen.getByText(/Every triggering Pod must match this reviewed endpoint definition/)).toBeTruthy();
  expect(screen.getByText('cd'.repeat(32))).toBeTruthy();
  if (sourceKind === 'templateBinding') {
    expect(screen.getByText(/named TCP port pprof, allowed range 6000–7000/)).toBeTruthy();
    expect(screen.getByText(/Pod template binding/)).toBeTruthy();
    expect(screen.queryByText(/TCP port 6060/)).toBeNull();
  } else {
    expect(screen.getByText(/TCP port 6060/)).toBeTruthy();
    expect(screen.getByText(/Administrator endpoint profile/)).toBeTruthy();
    expect(screen.queryByText(/named TCP port/)).toBeNull();
  }
  expect(screen.queryByText(/Pod api-a/)).toBeNull();
  expect(screen.queryByText(/Observation limits bound by this approval/)).toBeNull();
  expect(screen.queryByRole('button', { name: 'Continue approved capture' })).toBeNull();
  for (const patch of [{ endpoint_digest: 'ab'.repeat(32) }, { definition_digest: null }, { source_kind: 'unknown' }, { unknown: true },
    ...(sourceKind === 'templateBinding' ? [{ port: 6060 }, { declared_port_name: undefined }, { minimum_port: 0 }, { maximum_port: 65536 }] : [{ declared_port_name: 'pprof' }, { minimum_port: 6000 }, { port: undefined }])]) {
    const invalid = structuredClone(policy); Object.assign(invalid.actions[0].profile!, patch);
    expect(validOutput_get_grant(result(invalid))).toBe(false);
  }
});

it.each([40000, undefined])('shows only an explicitly reviewed observation event ceiling (%s)', async maximum => {
  const client = new SyntheticApprovals();
  client.detail = { ...grant, observation_limits: { ...grant.observation_limits!, ...(maximum === undefined ? {} : { max_observed_events: maximum }) } };
  expect(validOutput_get_grant(result(client.detail))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  const limits = await screen.findByText(/Observation limits bound by this approval/);
  if (maximum === undefined) expect(limits.textContent).not.toMatch(/eligible entry and exit probes/);
  else expect(limits.textContent).toContain('40000 eligible entry and exit probes in total');
});

it('shows cumulative policy argument event reservations independently of bytes', async () => {
 const client = new SyntheticApprovals(); client.detail = teamPolicyGrant();
 Object.assign(client.detail.policy!, {max_observed_events:6000,observed_events_used:2000});
 expect(validOutput_get_grant(result(client.detail))).toBe(true);
 render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
 expect(await screen.findByText(/2000 of 6000 eligible entry and exit probes/)).toBeTruthy();
});

function rawGrant(artifactCount = 2): Extract<Data<'get_grant'>, { kind: 'rawQuery' }> {
  const { target: _target, capture_id: _capture, preview_id: _preview, preview_deadline: _deadline, capture_deadline_rule: _rule, capture_window_seconds: _window, ...common } = row;
  return { ...common, kind: 'rawQuery', data_class: 'raw', reasons: [], raw_access: {
    case_id: id(2), reason: 'Inspect existing incident evidence', operations: ['download_artifact'], max_bytes: artifactCount * 512, max_operations: 10000, not_after: iso(3_600_000), artifact_count: artifactCount, bytes_used: 128, operations_used: 1,
    artifacts: Array.from({ length: artifactCount }, (_, n) => ({ artifact_id: id(100 + n), capture_id: id(42), action_id: 'calls', digest: 'ab'.repeat(32), execution_digest: 'cd'.repeat(32), native_type: 'syscallArguments', native_bytes: 512, expires_at: iso(3_600_000), target: { cluster_id: id(1), namespace_uid: 'namespace-' + n, workload_uid: 'workload-' + n, pod_uid: 'pod-' + n, namespace: 'payments', workload_name: 'api-' + n } })),
  } };
}
it('reviews whole-file raw access with every target and size and no collection controls', async () => {
  const client = new SyntheticApprovals(); client.detail = rawGrant();
  expect(validOutput_get_grant(result(client.detail))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByRole('heading', { name: 'Download existing raw evidence' })).toBeTruthy();
  expect(screen.getByText(/approval starts no collection/)).toBeTruthy();
  expect(screen.getAllByText('512 bytes')).toHaveLength(2);
  expect(screen.getByText(/api-0, payments/)).toBeTruthy();
  expect(screen.getByText(/api-1, payments/)).toBeTruthy();
  expect(screen.getByText(/10000 download operations/)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Return to evidence' })).toHaveProperty('href', expect.stringContaining('/cases/' + id(2)));
  expect(screen.queryByRole('button', { name: 'Continue approved capture' })).toBeNull();
  expect(screen.queryByText(/preview was valid/)).toBeNull();
});
it('reviews query-only and combined raw operations with explicit page charging', async () => {
  const client = new SyntheticApprovals(); const detail = rawGrant();
  detail.raw_access.operations = ['download_artifact', 'pcap_query']; client.detail = detail;
  expect(validOutput_get_grant(result(detail))).toBe(true);
  render(<ApprovalsWorkspace session={session} scope={new AbortController().signal} client={client} grantID={id(41)}/>);
  expect(await screen.findByRole('heading', { name: 'Inspect existing raw evidence' })).toBeTruthy();
  expect(screen.getByText(/Saved packet queries and whole-file downloads/)).toBeTruthy();
  expect(screen.getByText(/Each paid query page reserves 24 KiB/)).toBeTruthy();
  expect(screen.getByText(/10000 selected operations/)).toBeTruthy();
});
it('validates64 exact raw review artifacts and rejects collection fields or hidden selection truncation', () => {
  const raw = rawGrant(64);
  expect(validOutput_get_grant(result(raw))).toBe(true);
  expect(validOutput_get_grant(result({ ...raw, target: row.target }))).toBe(false);
  expect(validOutput_get_grant(result({ ...raw, actions: [] }))).toBe(false);
  expect(validOutput_get_grant(result({ ...raw, raw_access: { ...raw.raw_access, artifacts: [] } }))).toBe(false);
  expect(validOutput_get_grant(result(rawGrant(65)))).toBe(false);
  const { artifacts: _artifacts, ...summary } = raw.raw_access;
  expect(validOutput_list_reviews(result({ approvals: [{ ...raw, raw_access: summary }] }))).toBe(true);
  expect(validOutput_list_reviews(result({ approvals: [raw] }))).toBe(false);
});
it('keeps a64-artifact review with maximal escaped identifiers inside the256KiB get_grant budget', async () => {
  const raw = rawGrant(64);
  for (const a of raw.raw_access.artifacts) {
    a.action_id = '&'.repeat(63); a.native_type = '&'.repeat(64);
    a.native_bytes = 1099511627776;
    a.target = { cluster_id: id(1), namespace_uid: '&'.repeat(64), workload_uid: '&'.repeat(64), pod_uid: '&'.repeat(64), namespace: 'a'.repeat(63), workload_kind: 'StatefulSet', workload_name: 'a'.repeat(253), pod_name: 'a'.repeat(253) };
  }
  raw.raw_access.reason = '&'.repeat(512);
  raw.requested_by = { issuer: 'https://identity.invalid/' + '&'.repeat(2000), subject: '&'.repeat(256), client_id: '&'.repeat(256) };
  raw.decision = { decision: 'approved', decided_by: { ...raw.requested_by }, decided_at: iso(0), reason: '&'.repeat(512), authentication_context: { acr: '&'.repeat(128), authenticated_at: iso(0) } };
  const output = result(raw);
  expect(validOutput_get_grant(output)).toBe(true);
  // Go's encoding/json escapes HTML-sensitive identifiers; match that cost.
  const size = new TextEncoder().encode(JSON.stringify(output).replaceAll('&', '\\u0026')).length;
  expect(size).toBeGreaterThan(128 * 1024);
  expect(size).toBeLessThanOrEqual(256 * 1024);
  console.info('Raw access maximal escaped review bytes:', size);
  try {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(output).replaceAll('&', '\\u0026'), { headers: { 'Content-Type': 'application/json' } })));
    await expect(approvalOperations.call('get_grant', { grant_id: raw.grant_id }, 'csrf', new AbortController().signal)).resolves.toEqual(output);
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(' '.repeat(256 * 1024 + 1), { headers: { 'Content-Type': 'application/json' } })));
    await expect(approvalOperations.call('get_grant', { grant_id: raw.grant_id }, 'csrf', new AbortController().signal)).rejects.toThrow();
  } finally { vi.unstubAllGlobals(); }
  expect(validOutput_get_grant(result({ ...raw, raw_access: { ...raw.raw_access, max_operations: 10001 } }))).toBe(false);
});
