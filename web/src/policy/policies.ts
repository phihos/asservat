import type { Session } from '../auth/session';
import { OperationFailure, operationMessage } from '../capture/http';
import { operations, type Data, type Input, type Operation, type Operations, type Output, type Status } from './http';
import { operations as shareOperations, type Operations as ShareOperations } from '../sharing/http';

// A policy is named by cluster, namespace and DebugPolicy name; key is their join.
export type Ref = { cluster: string; namespace: string; policy_name: string };
export type Entry = Ref & { key: string; status?: Status; message?: string; busy: boolean };
export type State = { entries: Entry[] };

const name = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const keyOf = (ref: Ref) => [ref.cluster, ref.namespace, ref.policy_name].join('/');

// UI coordination is not authority: the server rechecks every operation. The
// looked-up policies and their content-free status live only in this tab.
// One idempotency key per pending command is reused on retry and dropped on
// a definite result.
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

  private update(key: string, patch: Partial<Entry>) {
    this.state = { entries: this.state.entries.map(entry => entry.key === key ? { ...entry, ...patch } : entry) };
    for (const listener of this.listeners) listener();
  }
  private ref(key: string): Ref | undefined {
    const e = this.state.entries.find(entry => entry.key === key);
    return e && { cluster: e.cluster, namespace: e.namespace, policy_name: e.policy_name };
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

  private async run<N extends Operation>(key: string, operation: N, input: Input<N>): Promise<Data<N> | undefined> {
    const session = this.session, scope = this.scope;
    if (!session || !scope || scope.aborted) return;
    this.update(key, { busy: true, message: undefined });
    try {
      const result: Output<N> = await this.client.call(operation, input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status !== 'ok') throw new OperationFailure(503, result.status === 'error' ? result.data.code : 'Pending', result.status === 'error' ? result.data.message : 'This operation is still pending.');
      return result.data as Data<N>;
    } catch (error) {
      if (!scope.aborted) {
        // A canonical domain refusal is definite: the next command gets a new key.
        if (error instanceof OperationFailure && error.detail) this.keys.delete(operation + '\n' + key);
        this.update(key, { message: operationMessage(error) });
      }
      return;
    } finally { if (!scope.aborted) this.update(key, { busy: false }); }
  }

  lookup = async (input: Ref) => {
    const ref = { cluster: input.cluster.trim(), namespace: input.namespace.trim(), policy_name: input.policy_name.trim() };
    if (!name.test(ref.cluster) || ref.cluster.length > 63 || !name.test(ref.namespace) || ref.namespace.length > 63 || !/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(ref.policy_name) || ref.policy_name.length > 253) return;
    const key = keyOf(ref);
    if (!this.state.entries.some(entry => entry.key === key)) {
      this.state = { entries: [...this.state.entries, { ...ref, key, busy: false }] };
      for (const listener of this.listeners) listener();
    }
    await this.refresh(key);
  };

  refresh = async (key: string) => {
    const ref = this.ref(key);
    if (!ref) return;
    const data = await this.run(key, 'get_policy_status', ref);
    if (data) this.update(key, { status: data });
  };

  deactivate = async (key: string) => {
    const ref = this.ref(key);
    if (!ref) return;
    const slot = 'deactivate_policy\n' + key;
    const idempotency_key = this.keys.get(slot) ?? this.newID();
    this.keys.set(slot, idempotency_key);
    if (!await this.run(key, 'deactivate_policy', { ...ref, idempotency_key })) return;
    this.keys.delete(slot);
    await this.refresh(key);
  };

  // ADR-239: stop future sharing (stop_future_sharing) or revoke every share
  // of the acceptance's recurring sharing and stop it (revoke_share with
  // sharing_intent_id). The server checks that the caller created or
  // currently manages it.
  stopSharing = (key: string) => this.changeSharing(key, 'stop_future_sharing');
  revokeSharing = (key: string) => this.changeSharing(key, 'revoke_share');
  private changeSharing = async (key: string, operation: 'stop_future_sharing' | 'revoke_share') => {
    const session = this.session, scope = this.scope;
    const status = this.state.entries.find(entry => entry.key === key)?.status;
    const acceptance = status?.acceptance_id;
    if (!session || !scope || scope.aborted || !acceptance) return;
    const slot = operation + '\n' + acceptance;
    const idempotency_key = this.keys.get(slot) ?? this.newID();
    this.keys.set(slot, idempotency_key);
    this.update(key, { busy: true, message: undefined });
    try {
      const input = { sharing_intent_id: acceptance, expected_revision: operation === 'revoke_share' ? status?.sharing?.revision ?? 1 : 1, idempotency_key };
      const reply = await this.shares.call(operation, input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (reply.status !== 'ok') throw new OperationFailure(503, reply.status === 'error' ? reply.data.code : 'Pending', reply.status === 'error' ? reply.data.message : 'This operation is still pending.');
      this.keys.delete(slot);
    } catch (error) {
      if (!scope.aborted) {
        if (error instanceof OperationFailure && error.detail) this.keys.delete(slot);
        this.update(key, { message: operationMessage(error) });
      }
      return;
    } finally { if (!scope.aborted) this.update(key, { busy: false }); }
    await this.refresh(key);
  };
}
