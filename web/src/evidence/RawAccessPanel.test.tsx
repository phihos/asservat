import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RawAccessPanel } from './RawAccessPanel';
import type { Operations } from '../approvals/http';
import type { Artifact } from './http';
import { caseResult, session, id } from './test-fixtures';
import { result } from '../capture/test-fixtures';
import { validInput_request_raw_access, validOutput_request_raw_access } from '../generated/validate-approvals';

afterEach(cleanup);
function artifact(n: number, size?: number): Artifact {
  const c = caseResult(); if (c.status !== 'ok') throw new Error();
  return { ...c.data.artifacts[0], artifact_id: id(n), digest: n.toString(16).padStart(64, '0'), data_class: 'raw', verified_native_bytes: size, target: { cluster_id: id(1), namespace_uid: 'ns', workload_uid: 'workload', pod_uid: 'pod', namespace: 'payments', workload_name: 'api' } };
}

it('requests selected whole files with exact sizes and reuses an uncertain request unchanged', async () => {
  const call = vi.fn().mockRejectedValueOnce(new Error('unknown')).mockResolvedValueOnce(result({ grant_id: id(41), phase: 'Pending' }));
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={[artifact(3, 512), artifact(4, 1024), artifact(5)]} client={{ call } as Operations} newID={() => 'same-key'}/>);
  const boxes = screen.getAllByRole('checkbox');
  expect((boxes[2] as HTMLInputElement).disabled).toBe(true);
  fireEvent.click(boxes[0]); fireEvent.click(boxes[1]);
  expect(screen.getByLabelText('Total download byte budget')).toHaveProperty('value', '1536');
  expect(screen.getByText(/10000 download operations/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'Inspect incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await screen.findByRole('alert');
  const input = call.mock.calls[0][1];
  expect(input).toEqual({ case_id: id(2), artifact_digests: [artifact(3).digest, artifact(4).digest], operations: ['download_artifact'], reason: 'Inspect incident', max_bytes: 1536, expires_in_seconds: 3600, idempotency_key: 'same-key' });
  expect(validInput_request_raw_access(input)).toBe(true);
  expect(screen.getByRole('group')).toHaveProperty('disabled', true);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same approval request' }));
  expect(await screen.findByRole('link', { name: 'Review download approval' })).toHaveProperty('href', expect.stringContaining('/approvals/' + id(41)));
  expect(call.mock.calls[1][1]).toEqual(input);
  expect(screen.getByText(/starts no collection/)).toBeTruthy();
});

it('bounds selection to64 and refuses empty, duplicate or oversized selectors while retaining future operation contracts', () => {
  render(<RawAccessPanel session={session} scope={new AbortController().signal} caseID={id(2)} artifacts={Array.from({ length: 65 }, (_, n) => artifact(n + 3, 1))}/>);
  const boxes = screen.getAllByRole('checkbox');
  for (const b of boxes.slice(0, 64)) fireEvent.click(b);
  expect(boxes[64]).toHaveProperty('disabled', true);
  const input = { case_id: id(2), artifact_digests: Array.from({ length: 64 }, (_, n) => artifact(n + 3).digest), operations: ['download_artifact'], reason: 'incident', max_bytes: 64, expires_in_seconds: 3600, idempotency_key: 'key' };
  expect(validInput_request_raw_access(input)).toBe(true);
  for (const artifact_digests of [[], [...input.artifact_digests, artifact(80).digest], [artifact(3).digest, artifact(3).digest]]) expect(validInput_request_raw_access({ ...input, artifact_digests })).toBe(false);
  for (const operations of [[], ['download_artifact', 'download_artifact']]) expect(validInput_request_raw_access({ ...input, operations })).toBe(false);
  expect(validInput_request_raw_access({ ...input, operations: ['read_memory'] })).toBe(true);
  for (const phase of ['Expired', 'Revoked']) expect(validOutput_request_raw_access(result({ grant_id: id(41), phase }))).toBe(true);
});

it('cancels the request on session scope end without exposing a late approval', async () => {
  let resolve!: (value: unknown) => void;
  const call = vi.fn((..._args: unknown[]) => new Promise(r => { resolve = r; }));
  const scope = new AbortController();
  const view = render(<RawAccessPanel session={session} scope={scope.signal} caseID={id(2)} artifacts={[artifact(3, 0)]} client={{ call } as Operations}/>);
  fireEvent.click(screen.getByRole('checkbox'));
  expect(screen.getByLabelText('Total download byte budget')).toHaveProperty('value', '1');
  fireEvent.change(screen.getByLabelText('Reason for raw download'), { target: { value: 'incident' } });
  fireEvent.click(screen.getByRole('button', { name: 'Request download approval' }));
  await waitFor(() => expect(call).toHaveBeenCalledOnce());
  scope.abort(); resolve(result({ grant_id: id(41), phase: 'Pending' }));
  await waitFor(() => expect(call.mock.calls[0][3]).toHaveProperty('aborted', true));
  expect(screen.queryByRole('link', { name: 'Review download approval' })).toBeNull();
  view.unmount();
});
