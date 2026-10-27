import type { Session } from '../auth/session';
import { OperationFailure, operationMessage } from '../capture/http';
import { operations, type Data, type Input, type Operation, type Operations, type Output, type ShareRow } from './http';

export type Recipient = { kind: 'User' | 'Group'; id: string };
export type State = {
  busy: boolean;
  owned?: ShareRow[]; received?: ShareRow[];
  // ADR-238: the administrator's management-only pages (loaded on demand).
  administered?: ShareRow[]; administeredCursor?: string; administeredMessage?: string;
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
  private transferKeys = new Map<string, [string, string]>();
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
    this.identity = undefined; this.session = undefined; this.scope = undefined; this.pending = undefined; this.revokeKeys.clear(); this.transferKeys.clear();
    this.state = { busy: false };
    for (const listener of this.listeners) listener();
  };

  // Returns the data, or the user-visible message and whether the outcome is
  // definite (a canonical domain reply) rather than unknown.
  private async run<N extends Operation>(name: N, input: Input<N>): Promise<{ data?: Data<N>; next?: string; message?: string; definite: boolean } | undefined> {
    const session = this.session, scope = this.scope;
    if (!session || !scope || scope.aborted) return;
    try {
      const result: Output<N> = await this.client.call(name, input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') return { data: result.data as Data<N>, next: (result as { next_cursor?: string | null }).next_cursor ?? undefined, definite: true };
      if (result.status === 'error') return { message: result.data.message, definite: true };
      return { message: 'The request is still pending. Retry the same request shortly.', definite: false };
    } catch (error) {
      if (scope.aborted) return;
      return { message: operationMessage(error), definite: error instanceof OperationFailure && !!error.detail };
    }
  }

  // ADR-238: one management-only page of every share for installation
  // administrators; next appends the following page. The server refuses
  // everyone else.
  loadAdministration = async (next = false) => {
    if (this.state.busy) return;
    const cursor = next ? this.state.administeredCursor : undefined;
    if (next && !cursor) return;
    this.publish({ busy: true });
    const reply = await this.run('list_shares', { view: 'administration', limit: 50, ...(cursor ? { cursor } : {}) } as Input<'list_shares'>);
    if (!reply) { this.publish({ busy: false }); return; }
    const rows = reply.data?.shares;
    this.publish({ busy: false, administeredMessage: reply.message, administeredCursor: reply.next,
      administered: rows && (next ? [...(this.state.administered ?? []), ...rows] : rows) });
  };

  // After a change: the user's lists, and the administrator page if shown.
  private refresh = async () => {
    await this.load();
    if (this.state.administered) await this.loadAdministration();
  };

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

  // teams (ADR-238) optionally names which of the user's own owner teams
  // manage the share; empty keeps the default (all of them).
  create = async (caseID: string, artifact: { artifact_id: string; digest: string }, recipients: Recipient[], hours: number, reason: string, teams: string[] = []) => {
    if (this.state.busy || !this.session) return;
    const issuer = this.session.principal.issuer;
    this.pending ??= {
      case_id: caseID, artifacts: [{ artifactID: artifact.artifact_id, digest: artifact.digest }],
      recipients: recipients.map(r => ({ kind: r.kind, issuer, id: r.id })), data_classes: ['metadata'], operations: ['get_case'],
      expires_at: new Date(Date.now() + hours * 3_600_000).toISOString(), reason, idempotency_key: this.newID(),
      ...(teams.length ? { management: { mode: 'teams' as const, teams: teams.map(id => ({ kind: 'Group' as const, issuer, id })) } } : {}),
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

  revoke = async (row: Pick<ShareRow, 'share_id' | 'revision'>) => {
    if (this.state.busy) return;
    const key = this.revokeKeys.get(row.share_id) ?? this.newID();
    this.revokeKeys.set(row.share_id, key);
    this.publish({ busy: true, message: undefined });
    // The listed revision: 1, plus one per management transfer (ADR-238).
    const reply = await this.run('revoke_share', { share_id: row.share_id, expected_revision: row.revision ?? 1, idempotency_key: key });
    if (!reply) { this.publish({ busy: false }); return; }
    if (reply.definite) this.revokeKeys.delete(row.share_id);
    this.publish({ busy: false, message: reply.message ?? (reply.data ? 'Share revoked.' : undefined) });
    if (reply.data) await this.refresh();
  };

  // ADR-238: a current manager hands management to owner teams they belong
  // to. Recipients, creator and end date are unchanged; the server checks
  // every team.
  transfer = async (row: ShareRow, teams: string[]) => {
    if (this.state.busy || !this.session || teams.length === 0) return;
    const issuer = this.session.principal.issuer;
    const request = JSON.stringify([row.share_id, row.revision ?? 1, teams]);
    const known = this.transferKeys.get(row.share_id);
    const key = known && known[0] === request ? known[1] : this.newID();
    this.transferKeys.set(row.share_id, [request, key]);
    this.publish({ busy: true, message: undefined });
    const reply = await this.run('transfer_share', { share_id: row.share_id, expected_revision: row.revision ?? 1, idempotency_key: key,
      management: { mode: 'teams', teams: teams.map(id => ({ kind: 'Group' as const, issuer, id })) } } as Input<'transfer_share'>);
    if (!reply) { this.publish({ busy: false }); return; }
    if (reply.definite) this.transferKeys.delete(row.share_id);
    this.publish({ busy: false, message: reply.message ?? (reply.data ? 'Management transferred.' : undefined) });
    if (reply.data) await this.refresh();
  };
}
