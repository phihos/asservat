import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SharePanel } from './SharePanel';
import { SharesWorkspace } from './SharesWorkspace';
import { Shares } from './shares';
import { operations, type Input, type Operation, type Operations, type Output } from './http';
import { validInput_create_share, validOutput_create_share, validOutput_list_shares, validOutput_revoke_share } from '../generated/validate-sharing';
import { id, result, session } from '../capture/test-fixtures';
import EvidenceWorkspace from '../evidence/EvidenceWorkspace';
import { Evidence } from '../evidence/evidence';
import { SyntheticEvidence, caseResult } from '../evidence/test-fixtures';

// Synthetic, content-free share fixtures for unit tests only.
const hour = 3_600_000;
const row = (n: number, phase: string) => ({ share_id: id(n), case_id: id(2), phase, expires_at: new Date(Date.now() + hour).toISOString() });
const failure = (code: string, message: string) => ({ ...result<'get_capture'>({}), status: 'error', data: { code, message, retryable: false } }) as unknown as Output<Operation>;
const artifact = { artifact_id: id(3), digest: 'ab'.repeat(32), expires_at: new Date(Date.now() + 48 * hour).toISOString() };

class SyntheticShares implements Operations {
  calls: { name: Operation; input: unknown; csrf: string }[] = [];
  owned = [row(10, 'Active'), row(11, 'Suspended')];
  fail?: () => unknown;
  async call<N extends Operation>(name: N, input: Input<N>, csrf: string): Promise<Output<N>> {
    this.calls.push({ name, input: structuredClone(input), csrf });
    if (this.fail) return this.fail() as Output<N>;
    if (name === 'create_share') return result({ share_id: id(10), phase: 'Active' }) as unknown as Output<N>;
    if (name === 'revoke_share') { this.owned = this.owned.map(r => r.share_id === (input as Input<'revoke_share'>).share_id ? { ...r, phase: 'Revoked' } : r); return result({ share_id: id(10), phase: 'Revoked', revision: 2 }) as unknown as Output<N>; }
    const view = (input as Input<'list_shares'>).view;
    if (view === 'owned' && this.owned.length === 0) return failure('NotAvailable', 'Sharing needs the evidence-owner role.') as Output<N>;
    return result({ shares: view === 'owned' ? this.owned : [row(20, 'Active')] }) as unknown as Output<N>;
  }
}

const controllers: (Shares | Evidence)[] = [];
afterEach(() => { cleanup(); for (const c of controllers) c.reset(); controllers.length = 0; vi.unstubAllGlobals(); });

it('fixtures match the canonical share contracts', () => {
  expect(validOutput_create_share(result({ share_id: id(10), phase: 'Active' }))).toBe(true);
  expect(validOutput_list_shares(result({ shares: [row(10, 'Suspended')] }))).toBe(true);
  expect(validOutput_revoke_share(result({ share_id: id(10), phase: 'Revoked', revision: 2 }))).toBe(true);
  expect(validOutput_revoke_share(failure('Conflict', 'x'))).toBe(true);
});

async function mountPanel(client = new SyntheticShares()) {
  let n = 30;
  const shares = new Shares(client, () => id(n++)); controllers.push(shares);
  render(<SharePanel session={session} scope={new AbortController().signal} caseID={id(2)} artifact={artifact} preview={<p>Preview body</p>} controller={shares}/>);
  // Closed, the panel renders only its summary.
  expect(screen.queryByText('Preview body')).toBeNull();
  open();
  await screen.findByText('Preview body');
  return { client, shares };
}
function open() {
  const details = screen.getByText('Share this artifact').closest('details')!;
  details.open = true; fireEvent(details, new Event('toggle'));
}
function fill(recipient: string, kind = 'User') {
  fireEvent.change(screen.getByLabelText('Recipient type'), { target: { value: kind } });
  fireEvent.change(screen.getByLabelText('Recipient ID'), { target: { value: recipient } });
  fireEvent.click(screen.getByRole('button', { name: 'Add recipient' }));
}

it('shares one artifact with stable IDs of the own issuer, previews the recipient view and copies the case link', async () => {
  const { client } = await mountPanel();
  expect(screen.getByText('Preview body')).toBeTruthy();
  expect(screen.getByText(/Native download, other evidence in this case/)).toBeTruthy();
  expect((screen.getByRole('button', { name: 'Share' }) as HTMLButtonElement).disabled).toBe(true);
  fill('user-7'); fill('team-9', 'Group'); fill('user-7');
  expect(within(screen.getByRole('list', { name: 'Recipients' })).getAllByRole('listitem')).toHaveLength(2);
  fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'incident review' } });
  const before = Date.now();
  fireEvent.click(screen.getByRole('button', { name: 'Share' }));
  expect(await screen.findByText(/Shared with 2 recipients until/)).toBeTruthy();
  const create = client.calls.find(c => c.name === 'create_share')!;
  expect(create.csrf).toBe(session.csrf_token);
  const input = create.input as Input<'create_share'>;
  expect(validInput_create_share(input)).toBe(true);
  expect({ ...input, expires_at: undefined }).toEqual({ case_id: id(2), artifacts: [{ artifactID: id(3), digest: 'ab'.repeat(32) }],
    recipients: [{ kind: 'User', issuer: session.principal.issuer, id: 'user-7' }, { kind: 'Group', issuer: session.principal.issuer, id: 'team-9' }],
    data_classes: ['metadata'], operations: ['get_case'], expires_at: undefined, reason: 'incident review', idempotency_key: id(30) });
  // Default expiry: 24 hours.
  expect(Math.abs(Date.parse(input.expires_at) - before - 24 * hour)).toBeLessThan(5_000);
  // A successful share clears the form; the next share is a new request.
  expect(screen.queryByRole('list', { name: 'Recipients' })).toBeNull();
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { clipboard: { writeText } });
  fireEvent.click(screen.getByRole('button', { name: 'Copy case link' }));
  expect(await screen.findByText('Link copied.')).toBeTruthy();
  expect(writeText).toHaveBeenCalledWith(window.location.origin + '/cases/' + id(2));
});

it('limits the share to the artifact access and at most seven days', async () => {
  await mountPanel();
  fireEvent.change(screen.getByLabelText('Share for (hours)'), { target: { value: '72' } });
  expect(screen.getByText(/the artifact's access ends first/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Share for (hours)'), { target: { value: '169' } });
  fill('user-7'); fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'r' } });
  expect((screen.getByRole('button', { name: 'Share' }) as HTMLButtonElement).disabled).toBe(true);
});

it('retries an uncertain share only with the identical request and shows definite refusals', async () => {
  const { client } = await mountPanel();
  client.fail = () => { throw new Error('connection reset'); };
  fill('user-7'); fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'r' } });
  fireEvent.click(screen.getByRole('button', { name: 'Share' }));
  const retry = await screen.findByRole('button', { name: 'Retry same share request' });
  fill('user-8');
  client.fail = () => failure('NotAvailable', 'Sharing needs the evidence-owner role on the workload and the evidence:share scope.');
  fireEvent.click(retry);
  await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/evidence-owner role/));
  const creates = client.calls.filter(c => c.name === 'create_share');
  expect(creates).toHaveLength(2);
  expect(creates[1].input).toEqual(creates[0].input);
  // The refusal is definite: the next attempt is a new request with a new key.
  expect(screen.getByRole('button', { name: 'Share' })).toBeTruthy();
});

it('lists received and owned shares and revokes an active one', async () => {
  const client = new SyntheticShares(); let n = 40;
  const shares = new Shares(client, () => id(n++)); controllers.push(shares);
  render(<SharesWorkspace session={session} scope={new AbortController().signal} controller={shares}/>);
  expect((await screen.findByRole('link', { name: 'Open shared case' })).getAttribute('href')).toBe('/cases/' + id(2));
  const owned = within(screen.getByRole('region', { name: 'Shared by me' }));
  expect(owned.getByText(/Suspended: you no longer hold the evidence-owner role/)).toBeTruthy();
  expect(owned.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1);
  fireEvent.click(owned.getByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(owned.queryAllByRole('button', { name: 'Revoke' })).toHaveLength(0));
  const revoke = client.calls.find(c => c.name === 'revoke_share')!;
  expect(revoke.input).toEqual({ share_id: id(10), expected_revision: 1, idempotency_key: id(40) });
  expect(revoke.csrf).toBe(session.csrf_token);
  expect(client.calls.filter(c => c.name === 'list_shares').map(c => c.input)).toEqual([{ view: 'received', limit: 100 }, { view: 'owned', limit: 100 }, { view: 'received', limit: 100 }, { view: 'owned', limit: 100 }]);
});

it('shows an owned-list refusal without hiding received shares', async () => {
  const client = new SyntheticShares(); client.owned = [];
  const shares = new Shares(client); controllers.push(shares);
  render(<SharesWorkspace session={session} scope={new AbortController().signal} controller={shares}/>);
  expect(await screen.findByText(/Sharing needs the evidence-owner role/)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Open shared case' })).toBeTruthy();
});

it('sends the identical idempotency header for share commands and none for listing', async () => {
  const fetcher = vi.fn().mockImplementation(async () => new Response(JSON.stringify(result({ shares: [] })), { headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetcher);
  await operations.call('list_shares', { view: 'owned' } as Input<'list_shares'>, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/list_shares');
  expect(fetcher.mock.calls[0][1].headers['Idempotency-Key']).toBeUndefined();
  fetcher.mockImplementation(async () => new Response(JSON.stringify(result({ share_id: id(10), phase: 'Revoked', revision: 2 })), { headers: { 'Content-Type': 'application/json' } }));
  await operations.call('revoke_share', { share_id: id(10), expected_revision: 1, idempotency_key: id(3) }, 'C'.repeat(43), new AbortController().signal);
  expect(fetcher.mock.calls[1][1]).toMatchObject({ method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': 'C'.repeat(43), 'Idempotency-Key': id(3) } });
});

it('offers neither download nor sharing on a case read through a share', async () => {
  const client = new SyntheticEvidence(); const value = caseResult(); if (value.status !== 'ok') throw new Error();
  value.data.case.access = 'shared'; client.responder = () => value;
  const controller = new Evidence(client); controllers.push(controller);
  render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  expect(await screen.findByText(/it does not include native download/)).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download' })).toBeNull();
  expect(screen.queryByText('Share this artifact')).toBeNull();
  await act(async () => undefined);
});

it('offers sharing on an ordinary case', async () => {
  const controller = new Evidence(new SyntheticEvidence()); controllers.push(controller);
  render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  expect(await screen.findByText('Share this artifact')).toBeTruthy();
  expect(screen.getAllByText('Access until')).toHaveLength(1);
  open();
  const preview = await screen.findByRole('region', { name: 'What recipients will see' });
  expect(within(preview).getByText('Pod status')).toBeTruthy();
  expect(within(preview).getByText('Access until')).toBeTruthy();
});
