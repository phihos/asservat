import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { AccessPreviewWorkspace } from './AccessPreviewWorkspace';
import type { PreviewClient, PreviewInput, PreviewOutput } from './preview-http';
import { validInput_preview_access_change, validOutput_preview_access_change } from '../generated/validate-access-preview';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free preview fixtures for unit tests only.
const spec = { effect: 'Deny', subjects: [{ kind: 'Group', issuer: 'https://identity.invalid', id: 'team-a' }], roles: ['evidence-reader'], scope: { clusterID: id(1), namespaceRef: { name: 'payments', uid: 'ns' } }, reason: 'Synthetic review' };
const changes = [{ action: 'create', kind: 'AccessBinding', spec }];
const cell = { cluster_id: id(1), namespace_uid: 'ns', workload_uid: '*', other_workloads: true };
const preview = {
  complete: false, message: 'Some targets could not be evaluated.', targets_evaluated: 2, deltas_total: 1, unavailable_total: 1, unmatched: [],
  deltas: [{ ...cell, subject: { kind: 'Group', issuer: 'https://identity.invalid', id: 'team-a' }, operation: 'read', before: 'Allow', after: 'Deny', after_unmet: 'ExplicitDeny' }],
  unavailable: [{ ...cell, workload_uid: 'wl', other_workloads: false, decision: 'Indeterminate', unmet: 'ClusterUnavailable' }],
};

class SyntheticPreview implements PreviewClient {
  calls: { input: PreviewInput; csrf: string }[] = [];
  async preview(input: PreviewInput, csrf: string): Promise<PreviewOutput> {
    this.calls.push({ input: structuredClone(input), csrf });
    return result(preview) as unknown as PreviewOutput;
  }
}

afterEach(cleanup);

it('fixtures match the canonical preview_access_change contract', () => {
  expect(validInput_preview_access_change({ changes })).toBe(true);
  expect(validInput_preview_access_change({ changes: [] })).toBe(false);
  expect(validInput_preview_access_change({ changes: [{ action: 'create', kind: 'PermissionSource', spec }] })).toBe(false);
  expect(validInput_preview_access_change({ changes: [{ action: 'delete', kind: 'PermissionSource', uid: 'source-uid' }] })).toBe(true);
  expect(validOutput_preview_access_change(result(preview))).toBe(true);
  expect(validOutput_preview_access_change(result({ ...preview, unavailable: [{ ...preview.unavailable[0], decision: 'Allow' }] }))).toBe(false);
});

it('previews only on request and shows decision changes and Indeterminate targets', async () => {
  const client = new SyntheticPreview();
  render(<AccessPreviewWorkspace session={session} scope={new AbortController().signal} client={client}/>);
  expect(client.calls).toHaveLength(0);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: JSON.stringify(changes) } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('Some targets could not be evaluated.')).toBeTruthy();
  expect(screen.getByText('team-a')).toBeTruthy();
  expect(screen.getByText('Deny (ExplicitDeny)')).toBeTruthy();
  expect(screen.getByText(/not enrolled in this installation/)).toBeTruthy();
  expect(client.calls).toEqual([{ input: { changes }, csrf: session.csrf_token }]);
});

it('refuses malformed changes locally without calling the server', () => {
  const client = new SyntheticPreview();
  render(<AccessPreviewWorkspace session={session} scope={new AbortController().signal} client={client}/>);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: '[{' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(screen.getByRole('alert').textContent).toMatch(/not valid JSON/);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: '[]' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(screen.getByRole('alert').textContent).toMatch(/1 to 16 changes/);
  expect(client.calls).toHaveLength(0);
});
