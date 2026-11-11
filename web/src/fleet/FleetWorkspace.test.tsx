import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { FleetWorkspace } from './FleetWorkspace';
import { FleetFailure, type BootstrapReceipt, type FleetClient } from './http';
import { session } from '../live/test-fixtures';
import { returnPath } from '../routes';
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const reply = (): BootstrapReceipt => ({ bootstrapID: id(1), clusterID: id(2), peerID: id(3), issuerEpoch: id(4), deliveryProfile: 'regional-installer', credentialVersion: 1, notBefore: '2026-11-01T12:00:00Z', notAfter: '2026-11-01T12:05:00Z' });
const fill = () => {
  fireEvent.change(screen.getByLabelText('Cluster display name'), { target: { value: 'Workload cluster' } });
  fireEvent.change(screen.getByLabelText('Region'), { target: { value: 'eu-test' } });
  fireEvent.change(screen.getByLabelText('Delivery profile'), { target: { value: 'regional-installer' } });
};
afterEach(cleanup);
it('issues only on explicit submit and shows actual IDs and original UTC expiry', async () => {
  const issue = vi.fn<FleetClient['issue']>().mockResolvedValue(reply());
  render(<FleetWorkspace session={session} scope={new AbortController().signal} client={{ issue }} newID={() => id(8)}/>);
  expect(issue).not.toHaveBeenCalled(); fill(); expect(issue).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Issue bootstrap slot' }));
  await screen.findByRole('heading', { name: 'Bootstrap slot issued' });
  expect(issue).toHaveBeenCalledTimes(1); expect(issue.mock.calls[0].slice(0, 3)).toEqual([{ displayName: 'Workload cluster', region: 'eu-test', deliveryProfile: 'regional-installer' }, id(8), session.csrf_token]);
  expect(screen.getByText(id(1))).toBeTruthy(); expect(screen.getByText('2026-11-01T12:05:00.000Z')).toBeTruthy();
  expect(screen.getByText('This original slot has expired.')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Create another slot' })); expect(issue).toHaveBeenCalledTimes(1);
  expect(returnPath('/fleet')).toBe('/fleet'); expect(returnPath('/fleet/unknown')).toBe('/');
});
it('retries an uncertain request with the same key/body and refreshed same-user CSRF', async () => {
  const scope = new AbortController(), issue = vi.fn<FleetClient['issue']>().mockRejectedValueOnce(new FleetFailure(503)).mockResolvedValueOnce(reply());
  const view = render(<FleetWorkspace session={session} scope={scope.signal} client={{ issue }} newID={() => id(8)}/>); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Issue bootstrap slot' })); await screen.findByRole('button', { name: 'Retry same issuance' });
  expect((screen.getByLabelText('Region') as HTMLInputElement).disabled).toBe(true);
  view.rerender(<FleetWorkspace session={{ ...session, csrf_token: 'D'.repeat(43) }} scope={scope.signal} client={{ issue }} newID={() => id(9)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Retry same issuance' })); await screen.findByRole('heading', { name: 'Bootstrap slot issued' });
  expect(issue.mock.calls[1][0]).toEqual(issue.mock.calls[0][0]); expect(issue.mock.calls[1][1]).toBe(id(8)); expect(issue.mock.calls[1][2]).toBe('D'.repeat(43));
});
it('clears private-session views and aborts pending transport on identity loss or unmount', async () => {
  let finish!: (receipt: BootstrapReceipt) => void;
  const issue = vi.fn<FleetClient['issue']>().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const scope = new AbortController(), view = render(<FleetWorkspace session={session} scope={scope.signal} client={{ issue }}/>); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Issue bootstrap slot' })); expect(issue).toHaveBeenCalledTimes(1);
  act(() => scope.abort()); expect(issue.mock.calls[0][3].aborted).toBe(true);
  await act(async () => finish(reply())); expect(screen.queryByText(id(1))).toBeNull(); expect((screen.getByLabelText('Region') as HTMLInputElement).value).toBe('');
  const second = new AbortController(); view.rerender(<FleetWorkspace session={session} scope={second.signal} client={{ issue }}/>); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Issue bootstrap slot' })); view.unmount(); expect(issue.mock.calls[1][3].aborted).toBe(true);
  await act(async () => finish(reply()));
});
it('reports real operator refusal and does not replay or present a slot', async () => {
  const issue = vi.fn<FleetClient['issue']>().mockRejectedValue(new FleetFailure(403));
  render(<FleetWorkspace session={session} scope={new AbortController().signal} client={{ issue }}/>); fill();
  fireEvent.click(screen.getByRole('button', { name: 'Issue bootstrap slot' })); await screen.findByText('Current fleet operator access is required.');
  expect(screen.queryByRole('button', { name: 'Retry same issuance' })).toBeNull(); expect(screen.queryByRole('heading', { name: 'Bootstrap slot issued' })).toBeNull(); expect(issue).toHaveBeenCalledTimes(1);
  expect((screen.getByLabelText('Region') as HTMLInputElement).disabled).toBe(false);
});
