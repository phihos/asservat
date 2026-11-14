import { existsSync, readFileSync } from 'node:fs';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { SyntheticEvidence, caseResult, id, session } from './test-fixtures';
import { result } from '../capture/test-fixtures';
import { validOutput_get_grant } from '../generated/validate-approvals';
import { validOutput_syscall_query } from '../generated/validate-projection';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

// Synthetic evidence; real workspace, approval/projection clients and validators.
it('requires approval before querying the same saved arguments through the HTTP clients', async () => {
  const value = caseResult();
  if (value.status !== 'ok') throw Error('fixture');
  const artifact = value.data.artifacts[0];
  Object.assign(artifact, { kind: 'syscallTrace', native_format: 'asservat-syscall-arguments/v1', data_class: 'raw', verified_native_bytes: 8192,
    target: { cluster_id: id(1), namespace_uid: 'ns', workload_uid: 'workload', pod_uid: 'pod', namespace: 'payments', workload_name: 'api' } });
  const until = new Date(Date.now() + 3600000).toISOString();
  const grant = result({ grant_id: id(41), phase: 'Approved', revision: 2, kind: 'rawQuery', execution_digest: 'ab'.repeat(32), review_digest: 'cd'.repeat(32), data_class: 'raw', reasons: [],
    requested_by: { issuer: session.principal.issuer, subject: session.principal.subject_id, client_id: 'console' }, requested_at: new Date(Date.now() - 1000).toISOString(), review_until: until, lifetime_seconds: 3600, can_decide: false, can_revoke: true, approval_navigation_uri: 'https://asservat.example.invalid/approvals/' + id(41),
    raw_access: { case_id: id(2), reason: 'Inspect saved arguments', operations: ['syscall_query'], max_bytes: 49152, max_operations: 10000, not_after: until, artifact_count: 1, bytes_used: 0, operations_used: 0,
      artifacts: [{ artifact_id: artifact.artifact_id, capture_id: id(42), action_id: 'calls', digest: artifact.digest, execution_digest: 'cd'.repeat(32), native_type: 'syscallArguments', native_bytes: 8192, expires_at: until, target: artifact.target }] } });
  const example = (name: string) => JSON.parse(readFileSync(existsSync(new URL('../../../examples/implemented/' + name, import.meta.url)) ? new URL('../../../examples/implemented/' + name, import.meta.url) : new URL('../../../examples/' + name, import.meta.url), 'utf8'));
  const page = example('mcp-syscall-query-result.json');
  page.provenance = [{ artifactID: artifact.artifact_id, digest: artifact.digest }];
  const queryObservedAt = new Date();
  page.data.query_observed_at = queryObservedAt.toISOString();
  page.data.query_expires_at = new Date(queryObservedAt.getTime() + 60000).toISOString();
  expect(validOutput_get_grant(grant)).toBe(true);
  expect(validOutput_syscall_query(page)).toBe(true);
  const reply = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
  const fetch = vi.fn().mockResolvedValueOnce(reply(result({ grant_id: id(41), phase: 'Pending' }))).mockResolvedValueOnce(reply(grant)).mockResolvedValueOnce(reply(page));
  vi.stubGlobal('fetch', fetch);
  const client = new SyntheticEvidence(); client.responder = () => value;
  const controller = new Evidence(client), scope = new AbortController();
  try {
    render(<EvidenceWorkspace controller={controller} session={session} scope={scope.signal} caseID={id(2)}/>);
    const run = await screen.findByRole('button', { name: 'Run syscall query' });
    expect(run).toHaveProperty('disabled', true);
    expect(fetch).not.toHaveBeenCalled();
    const heading = screen.getByRole('heading', { name: 'Request saved syscall argument query approval' });
    const approval = within(heading.closest('section')!);
    fireEvent.change(approval.getByLabelText('Reason for raw access'), { target: { value: 'Inspect saved arguments' } });
    fireEvent.click(approval.getByRole('button', { name: 'Request query approval' }));
    await approval.findByRole('link', { name: 'Review query approval' });
    expect(run).toHaveProperty('disabled', true);
    fireEvent.click(approval.getByRole('button', { name: 'Check approval' }));
    await screen.findByText('Approval request: Approved.', { exact: false });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Run syscall query' })).toHaveProperty('disabled', false));
    fireEvent.click(screen.getByRole('button', { name: 'Run syscall query' }));
    expect(await screen.findByRole('table', { name: 'Saved syscall argument events' })).toBeTruthy();
    expect(screen.getByText('base64:c3ludGhldGlj')).toBeTruthy();
    expect(fetch.mock.calls.map(call => call[0])).toEqual(['/api/v1/operations/request_raw_access', '/api/v1/operations/get_grant', '/api/v1/operations/syscall_query']);
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toMatchObject({ artifact_digests: [artifact.digest], operations: ['syscall_query'], max_bytes: 49152 });
    expect(JSON.parse(fetch.mock.calls[2][1].body)).toMatchObject({ case_id: id(2), artifact_id: artifact.artifact_id, grant_id: id(41) });
    expect(client.calls.map(call => call.name)).toEqual(['get_case']);
    expect(fetch.mock.calls[2][1].headers['X-CSRF-Token']).toBe(session.csrf_token);
    act(() => scope.abort());
    expect(screen.queryByRole('table', { name: 'Saved syscall argument events' })).toBeNull();
  } finally { scope.abort(); controller.reset(); }
});
