import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { RetentionPreviewWorkspace } from './RetentionPreviewWorkspace';
import type { RetentionPreviewClient, RetentionPreviewInput, RetentionPreviewOutput } from './preview-http';
import { validInput_preview_retention_change, validOutput_preview_retention_change } from '../generated/validate-retention-preview';
import { id, result, session } from '../capture/test-fixtures';

// Synthetic, content-free preview fixtures for unit tests only.
const spec = { scope: {}, purposeRef: 'diagnostics', defaults: { evidenceSeconds: 600, caseMetadataSeconds: 3600, auditMetadataSeconds: 3600 },
  maxima: { evidenceSeconds: 1800, caseMetadataSeconds: 86400, auditMetadataSeconds: 86400 }, rules: [], deletionBudgetSeconds: 300, legalExceptions: 'disabled' };
const changes = [{ action: 'update', uid: 'baseline', spec }, { action: 'delete', source_cluster_id: id(2), uid: 'local-policy' }];
const deletion = new Date(Date.now() + 1_800_000).toISOString();
const data = {
  complete: false, message: 'The policy source of some clusters is not current.', observed_at: new Date().toISOString(), artifacts_scanned: 12, scan_limited: false,
  affected_total: 9, read_closed_total: 2, deletion_due_total: 1, unknown_total: 3, earliest_expires_at: deletion, earliest_delete_by: deletion, baseline_changed: false,
  groups: [{ cluster_id: id(1), privacy_class: 'potentialPersonalData', evidence_type: 'context', scanned: 12, affected: 9, read_closed: 2, deletion_due: 1, unknown: 3, earliest_expires_at: deletion, earliest_delete_by: deletion }],
  groups_total: 1, incomplete_clusters: [{ cluster_id: id(2), reason: 'SourceUnavailable' }], incomplete_total: 1,
  not_evaluated: [{ action: 'delete', source_cluster_id: id(2), uid: 'local-policy', reason: 'UnknownObject' }],
};

class SyntheticPreview implements RetentionPreviewClient {
  calls: { input: RetentionPreviewInput; csrf: string }[] = [];
  async preview(input: RetentionPreviewInput, csrf: string): Promise<RetentionPreviewOutput> {
    this.calls.push({ input: structuredClone(input), csrf });
    return result(data) as unknown as RetentionPreviewOutput;
  }
}

afterEach(cleanup);

it('fixtures match the canonical preview_retention_change contract', () => {
  expect(validInput_preview_retention_change({ changes })).toBe(true);
  expect(validInput_preview_retention_change({ changes: [] })).toBe(false);
  expect(validInput_preview_retention_change({ changes: [{ action: 'create', uid: 'x', spec }] })).toBe(false);
  expect(validInput_preview_retention_change({ changes: [{ action: 'update', uid: 'x', spec: { ...spec, legalExceptions: 'always' } }] })).toBe(false);
  expect(validOutput_preview_retention_change(result(data))).toBe(true);
  expect(validOutput_preview_retention_change(result({ ...data, incomplete_clusters: [{ cluster_id: id(2), reason: 'Assumed' }] }))).toBe(false);
});

it('previews only on request and shows counts, earliest deletion, incomplete clusters and unevaluated changes', async () => {
  const client = new SyntheticPreview();
  render(<RetentionPreviewWorkspace session={session} scope={new AbortController().signal} client={client}/>);
  expect(client.calls).toHaveLength(0);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: JSON.stringify(changes) } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(await screen.findByText('The policy source of some clusters is not current.')).toBeTruthy();
  expect(screen.getByText(/9 would be shortened, 2 would become unreadable at once, 1 would be due for deletion at once, 3 unknown/)).toBeTruthy();
  expect(screen.getByText(/Earliest new access end/)).toBeTruthy();
  expect(screen.getByText('Incomplete clusters (1)')).toBeTruthy();
  expect(screen.getByText(/no accepted policy with this UID/)).toBeTruthy();
  expect(client.calls).toEqual([{ input: { changes }, csrf: session.csrf_token }]);
});

it('refuses malformed changes locally without calling the server', () => {
  const client = new SyntheticPreview();
  render(<RetentionPreviewWorkspace session={session} scope={new AbortController().signal} client={client}/>);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: '[{' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(screen.getByRole('alert').textContent).toMatch(/not valid JSON/);
  fireEvent.change(screen.getByLabelText(/Changes/), { target: { value: '[]' } });
  fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
  expect(screen.getByRole('alert').textContent).toMatch(/1 to 16 changes/);
  expect(client.calls).toHaveLength(0);
});
