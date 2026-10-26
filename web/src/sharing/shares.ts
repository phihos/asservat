import type { Session } from '../auth/session';
import { OperationFailure, operationMessage } from '../capture/http';
import { operations, type Data, type Input, type Operation, type Operations, type Output, type ShareRow } from './http';

export type Recipient = { kind: 'User' | 'Group'; id: string };
export type State = {
  busy: boolean;
  owned?: ShareRow[]; received?: ShareRow[];
  ownedMessage?: string; receivedMessage?: string;
  created?: { shareID: string; expiresAt: string; recipients: number };
  message?: string;
  // A create whose reply was lost: it may exist, and only the identical
  // request (same idempotency key) may be sent again.
  uncertain?: boolean;
};
export const maxRecipients = 8;
export const maxHours = 7 * 24;

// UI coordination only, never authority: the server checks ownership,
// recipients, expiry and current rights on every call. Recipients are the
// stable IDs of the signed-in user's own identity provider.
export class Shares {
  private state: State = { busy: false };
  private listeners = new Set<() => void>();
  private identity?: string;
  private session?: Session;
  private scope?: AbortSignal;
  private pending?: Input<'create_share'>;
  private revokeKeys = new Map<string, string>();
  readonly snapshot = () => this.state;
  readonly subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  constructor(private client: Operations = operations, private newID: () => string = () => crypto.randomUUID()) {}

  private publish(patch: Partial<State>) { this.state = { ...this.state, ...patch }; for (const listener of this.listeners) listener(); }

  attach(session: Session, scope: AbortSignal) {
    const identity = JSON.stringify([session.principal.issuer, session.principal.subject_id]);
    if (identity !== this.identity) this.reset();
    this.identity = identity; this.session = session; this.scope = scope;
    return () => { if (this.scope === scope) { this.session = undefined; this.scope = undefined; } };
  }

  reset = () => {
    this.identity = undefined; this.session = undefined; this.scope = undefined; this.pending = undefined; this.revokeKeys.clear();
    this.state = { busy: false };
    for (const listener of this.listeners) listener();
  };

  // Returns the data, or the user-visible message and whether the outcome is
  // definite (a canonical domain reply) rather than unknown.
  private async run<N extends Operation>(name: N, input: Input<N>): Promise<{ data?: Data<N>; message?: string; definite: boolean } | undefined> {
    const session = this.session, scope = this.scope;
    if (!session || !scope || scope.aborted) return;
    try {
      const result: Output<N> = await this.client.call(name, input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') return { data: result.data as Data<N>, definite: true };
      if (result.status === 'error') return { message: result.data.message, definite: true };
      return { message: 'The request is still pending. Retry the same request shortly.', definite: false };
    } catch (error) {
      if (scope.aborted) return;
      return { message: operationMessage(error), definite: error instanceof OperationFailure && !!error.detail };
    }
  }

  load = async () => {
    if (this.state.busy) return;
    this.publish({ busy: true });
    // The generated type marks the defaulted include_intents required; the
    // implemented subset (ADR-232) rejects it, so it is never sent.
    const received = await this.run('list_shares', { view: 'received', limit: 100 } as Input<'list_shares'>);
    const owned = await this.run('list_shares', { view: 'owned', limit: 100 } as Input<'list_shares'>);
    if (!received && !owned) { this.publish({ busy: false }); return; }
    this.publish({ busy: false, received: received?.data?.shares, receivedMessage: received?.message, owned: owned?.data?.shares, ownedMessage: owned?.message });
  };

  create = async (caseID: string, artifact: { artifact_id: string; digest: string }, recipients: Recipient[], hours: number, reason: string) => {
    if (this.state.busy || !this.session) return;
    const issuer = this.session.principal.issuer;
    this.pending ??= {
      case_id: caseID, artifacts: [{ artifactID: artifact.artifact_id, digest: artifact.digest }],
      recipients: recipients.map(r => ({ kind: r.kind, issuer, id: r.id })), data_classes: ['metadata'], operations: ['get_case'],
      expires_at: new Date(Date.now() + hours * 3_600_000).toISOString(), reason, idempotency_key: this.newID(),
    };
    const input = this.pending;
    this.publish({ busy: true, message: undefined, created: undefined });
    const reply = await this.run('create_share', input);
    // An aborted call may already have reached the server: stay uncertain.
    if (!reply) { this.publish({ busy: false, uncertain: true }); return; }
    if (reply.definite) this.pending = undefined;
    this.publish({ busy: false, uncertain: !reply.definite, message: reply.message,
      created: reply.data && { shareID: reply.data.share_id, expiresAt: input.expires_at, recipients: input.recipients.length } });
  };

  // Drops an uncertain request so the form can build a new one (new key).
  // The earlier request may still have created a share; /shares lists it.
  discardPending = () => {
    if (this.state.busy) return;
    this.pending = undefined;
    this.publish({ uncertain: false, message: undefined });
  };

  revoke = async (row: ShareRow) => {
    if (this.state.busy) return;
    const key = this.revokeKeys.get(row.share_id) ?? this.newID();
    this.revokeKeys.set(row.share_id, key);
    this.publish({ busy: true, message: undefined });
    // An Active share has revision 1; revocation makes it 2 (ADR-232).
    const reply = await this.run('revoke_share', { share_id: row.share_id, expected_revision: 1, idempotency_key: key });
    if (!reply) { this.publish({ busy: false }); return; }
    if (reply.definite) this.revokeKeys.delete(row.share_id);
    this.publish({ busy: false, message: reply.message });
    if (reply.data) await this.load();
  };
}
