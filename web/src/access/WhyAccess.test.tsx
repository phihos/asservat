import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { WhyAccess } from './WhyAccess';
import type { Client, Input, Output } from './http';
import { validInput_explain_access, validOutput_explain_access } from '../generated/validate-access';
import { id, result, session, target } from '../capture/test-fixtures';

// Synthetic, content-free explanation fixtures for unit tests only.
const deny = { decision: 'Deny', operation: 'capture', unmet: 'ExplicitDeny', required_roles: ['workload-maintainer'], message: 'A deny assignment that names you blocks this operation.', target: { cluster_id: id(1), namespace_uid: 'ns', workload_uid: 'deployment', pod_uid: 'pod' }, assignments: [{ effect: 'deny', assignment_id: id(9), role: 'workload-maintainer', subject_kind: 'Group', basis_kind: 'AccessBinding', basis_uid: 'binding-uid', revision: 'ab'.repeat(32) }], assignments_total: 1 };
const undisclosed = { decision: 'Deny', operation: 'capture', unmet: 'NoMatchingAllow', required_roles: ['workload-maintainer'], message: 'No current assignment of yours grants this operation.', assignments: [], assignments_total: 0 };

class SyntheticAccess implements Client {
  calls: { input: Input; csrf: string }[] = [];
  constructor(private reply: unknown) {}
  async explain(input: Input, csrf: string): Promise<Output> {
    this.calls.push({ input: structuredClone(input), csrf });
    return result(this.reply) as unknown as Output;
  }
}

afterEach(cleanup);

it('fixtures match the canonical explain_access contract', () => {
  expect(validOutput_explain_access(result(deny))).toBe(true);
  expect(validOutput_explain_access(result(undisclosed))).toBe(true);
  expect(validOutput_explain_access(result({ ...undisclosed, decision: 'Maybe' }))).toBe(false);
  expect(validInput_explain_access({ target_ref: target, operation: 'capture' })).toBe(true);
  expect(validInput_explain_access({ target_ref: target, operation: 'capture', principal: 'someone-else' })).toBe(false);
});

it('asks only when the user presses Why? and shows the deny that names them', async () => {
  const client = new SyntheticAccess(deny);
  render(<WhyAccess session={session} scope={new AbortController().signal} target={target} operation="capture" client={client}/>);
  expect(client.calls).toHaveLength(0);
  fireEvent.click(screen.getByRole('button', { name: 'Why?' }));
  expect(await screen.findByText('You do not have this access')).toBeTruthy();
  expect(screen.getByText(/A deny assignment that names you/)).toBeTruthy();
  expect(screen.getByText('binding-uid')).toBeTruthy();
  expect(client.calls).toEqual([{ input: { target_ref: target, operation: 'capture' }, csrf: session.csrf_token }]);
});

it('shows the uniform answer without assignments', async () => {
  render(<WhyAccess session={session} scope={new AbortController().signal} target={target} operation="capture" client={new SyntheticAccess(undisclosed)}/>);
  fireEvent.click(screen.getByRole('button', { name: 'Why?' }));
  expect(await screen.findByText(/Roles that allow this: workload-maintainer/)).toBeTruthy();
  expect(screen.queryByRole('listitem')).toBeNull();
});
