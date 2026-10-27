import type { Session } from '../auth/session';
import { OperationFailure, operationMessage } from '../capture/http';
import { operations, type Data, type Input, type Operation, type Operations, type Output, type Status } from './http';
import { operations as shareOperations, type Operations as ShareOperations } from '../sharing/http';

export type Entry = { name: string; status?: Status; message?: string; busy: boolean };
export type State = { entries: Entry[] };

// UI coordination is not authority: the server rechecks every operation. The
// looked-up names and their content-free status live only in this tab; there
// is no policy listing operation, so the user names the hub-held policy.
// One idempotency key per pending command is reused on retry and dropped on
// a definite result, so a retried uncertain activation is never a second one.
export class Policies {
  private state: State = { entries: [] };
  private listeners = new Set<() => void>();
  private identity?: string;
  private session?: Session;
  private scope?: AbortSignal;
  private keys = new Map<string, string>();
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private newID: () => string = () => crypto.randomUUID(), private shares: ShareOperations = shareOperations) {}

  private update(name: string, patch: Partial<Entry>) {
    this.state = { entries: this.state.entries.map(entry => entry.name === name ? { ...entry, ...patch } : entry) };
    for (const listener of this.listeners) listener();
  }

  attach(session: Session, scope: AbortSignal) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    return () => { if (this.scope === scope) { this.session = undefined; this.scope = undefined; } };
  }

  reset = () => {
    this.identity = undefined; this.session = undefined; this.scope = undefined; this.keys.clear();
    this.state = { entries: [] };
    for (const listener of this.listeners) listener();
  };

  private async run<N extends Operation>(name: string, operation: N, input: Input<N>): Promise<Data<N> | undefined> {
    const session = this.session, scope = this.scope;
    if (!session || !scope || scope.aborted) return;
    this.update(name, { busy: true, message: undefined });
    try {
      const result: Output<N> = await this.client.call(operation, input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This operation is still pending.');
      return result.data as Data<N>;
    } catch (error) {
      if (!scope.aborted) {
        // A canonical domain refusal is definite: the next command gets a new key.
        if (error instanceof OperationFailure && error.detail) this.keys.delete(operation + '\n' + name);
        this.update(name, { message: operationMessage(error) });
      }
      return;
    } finally { if (!scope.aborted) this.update(name, { busy: false }); }
  }

  lookup = async (name: string) => {
    name = name.trim();
    if (!/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(name) || name.length > 253) return;
    if (!this.state.entries.some(entry => entry.name === name)) {
      this.state = { entries: [...this.state.entries, { name, busy: false }] };
      for (const listener of this.listeners) listener();
    }
    await this.refresh(name);
  };

  refresh = async (name: string) => {
    const data = await this.run(name, 'get_policy_status', { policy_name: name });
    if (data) this.update(name, { status: data });
  };

  private async command(name: string, operation: 'activate_policy' | 'deactivate_policy') {
    const slot = operation + '\n' + name;
    const key = this.keys.get(slot) ?? this.newID();
    this.keys.set(slot, key);
    const data = await this.run(name, operation, { policy_name: name, idempotency_key: key });
    if (!data) return;
    this.keys.delete(slot);
    await this.refresh(name);
  }
  activate = (name: string) => this.command(name, 'activate_policy');

  // ADR-239: revoke every share of the acceptance's recurring sharing and
  // stop its future sharing (revoke_share with sharing_intent_id). The server
  // checks that the caller created or currently manages it.
  revokeSharing = async (name: string) => {
    const session = this.session, scope = this.scope;
    const acceptance = this.state.entries.find(entry => entry.name === name)?.status?.acceptance_id;
    if (!session || !scope || scope.aborted || !acceptance) return;
    const slot = 'revoke_share\n' + acceptance;
    const key = this.keys.get(slot) ?? this.newID();
    this.keys.set(slot, key);
    this.update(name, { busy: true, message: undefined });
    try {
      const reply = await this.shares.call('revoke_share', { sharing_intent_id: acceptance, expected_revision: 1, idempotency_key: key }, session.csrf_token, scope);
      if (scope.aborted) return;
      if (reply.status !== 'ok') throw new OperationFailure(503, reply.status === 'error' ? reply.data.code : 'Pending', reply.status === 'error' ? reply.data.message : 'This operation is still pending.');
      this.keys.delete(slot);
    } catch (error) {
      if (!scope.aborted) {
        if (error instanceof OperationFailure && error.detail) this.keys.delete(slot);
        this.update(name, { message: operationMessage(error) });
      }
      return;
    } finally { if (!scope.aborted) this.update(name, { busy: false }); }
    await this.refresh(name);
  };
  deactivate = (name: string) => this.command(name, 'deactivate_policy');
}
