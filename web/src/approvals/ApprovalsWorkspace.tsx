import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operationMessage } from '../capture/http';
import { operations as defaultOperations, type Grant, type Operations, type ReviewRow } from './http';

const date = (value: string) => new Date(value).toLocaleString();
const reasons: Record<string, string> = {
  rawBytePredicate: 'a raw byte comparison in the packet filter can test payload bytes',
  recordingApprovalRequired: 'this installation requires approval for every recording',
};
const phases: Record<string, string> = {
  Pending: 'Waiting for review', Approved: 'Approved', Denied: 'Denied', Revoked: 'Revoked', Expired: 'Expired', Exhausted: 'Exhausted',
};
const bytes = (n: number) => n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(n % (1 << 20) ? 1 : 0)} MiB` : `${n} bytes`;

function Rows({ rows, empty, label }: { rows?: ReviewRow[]; empty: string; label: string }) {
  if (!rows) return null;
  if (rows.length === 0) return <p>{empty}</p>;
  return <ul className="progress-actions" aria-label={label}>{rows.map(row => <li key={row.grant_id}>
    <span><a href={'/approvals/' + row.grant_id}>{row.target.workload_kind} {row.target.workload_name}</a> in {row.target.namespace} · {phases[row.phase] ?? row.phase} · requested by {row.requested_by.subject} {date(row.requested_at)}
      {row.phase === 'Pending' && <> · review until {date(row.review_until)}</>}</span>
  </li>)}</ul>;
}

function Detail({ grant, busy, onDecide, onRevoke }: { grant: Grant; busy: boolean; onDecide: (approve: boolean, reason: string) => void; onRevoke: () => void }) {
  const [reason, setReason] = useState('');
  return <>
    <section className="review-section" aria-labelledby="approval-plan">
      <h2 id="approval-plan">What would be recorded</h2>
      <p>{grant.target.workload_kind} <strong>{grant.target.workload_name}</strong>, Pod {grant.target.pod_name} in namespace {grant.target.namespace} (cluster <span className="identifier">{grant.target.cluster_id}</span>). Data class: {grant.data_class}.</p>
      <p>Needs approval because {grant.reasons.map(r => reasons[r.code] ?? r.code).join('; ')}.</p>
      <table>
        <thead><tr><th scope="col">Action</th><th scope="col">Mode</th><th scope="col">Window</th><th scope="col">Filter</th><th scope="col">Ring</th><th scope="col">Output limit</th></tr></thead>
        <tbody>{grant.actions.map(a => <tr key={a.action_id}>
          <td>{a.kind === 'packetCapture' ? 'Packets' : 'Syscalls'} <span className="identifier">{a.action_id}</span></td>
          <td>{a.execution_mode === 'ongoing' ? 'Records while armed' : 'On trigger'}</td>
          <td>{a.before} before, {a.after} after</td>
          <td>{a.filter ? <><code>{a.filter}</code>{a.filter_digest && <> ({a.filter_instructions} instructions, program <span className="identifier">{a.filter_digest.slice(0, 16)}</span>)</>}</> : 'none'}</td>
          <td>{bytes(a.ring_max_bytes)}, {a.ring_max_age}</td>
          <td>{bytes(a.max_bytes)}</td>
        </tr>)}</tbody>
      </table>
      {grant.observation_limits && <p>Observation limits bound by this approval: {grant.observation_limits.max_session_seconds} s per session, {bytes(grant.observation_limits.max_observed_bytes)} in total, {bytes(grant.observation_limits.max_bytes_per_second)} per second, {grant.observation_limits.max_concurrent_sessions} concurrent session.</p>}
      {grant.result_access && <p>Follow-up access for the requester only: {grant.result_access.operations.join(', ')} by clients {grant.result_access.client_ids.join(', ')}, at most {grant.result_access.max_artifacts} artifacts and {bytes(grant.result_access.max_bytes)} in total until {date(grant.result_access.not_after)} (used: {grant.result_access.artifacts_used} artifacts, {bytes(grant.result_access.bytes_used)}).</p>}
      <p className="field-help">Plan digest <span className="identifier">{grant.execution_digest}</span>. Requested by {grant.requested_by.subject} (client {grant.requested_by.client_id}) on {date(grant.requested_at)}; the preview was valid until {date(grant.preview_deadline)}. {grant.capture_deadline_rule === 'acceptanceWithinGrant' ? `After approval, submitting this plan starts a capture window of at most ${Math.round(grant.capture_window_seconds! / 60)} minutes, bounded by the approval expiry.` : 'This legacy plan must start before its preview deadline; create a new preview if it has expired.'} An approval lasts {Math.round(grant.lifetime_seconds / 60)} minutes and covers only this exact plan and requester.</p>
    </section>
    <section className="review-section" aria-labelledby="approval-state">
      <h2 id="approval-state">Decision</h2>
      <p role="status">{phases[grant.phase] ?? grant.phase}{grant.phase === 'Pending' && <> until {date(grant.review_until)}</>}
        {grant.decision && <> · {grant.decision.decision} by {grant.decision.decided_by.subject} on {date(grant.decision.decided_at)}: {grant.decision.reason}</>}
        {grant.not_after && grant.phase === 'Approved' && <> · valid until {date(grant.not_after)}</>}
        {grant.revoked_at && <> · revoked {date(grant.revoked_at)}</>}</p>
      {grant.can_decide && <>
        <label htmlFor="approval-reason">Reason (recorded with your decision)</label>
        <textarea id="approval-reason" rows={2} maxLength={512} value={reason} onChange={event => setReason(event.target.value)}/>
        <p className="field-help">Approving needs a recent step-up sign-in at your identity provider. You cannot decide a request you made yourself. Signing in returns to this plan; review it again before deciding.</p>
        <a className="button secondary" href={'/auth/step-up?return_to=' + encodeURIComponent('/approvals/' + grant.grant_id)}>Sign in with step-up</a>
        <Button className="button" isDisabled={busy || reason.trim() === ''} onPress={() => onDecide(true, reason.trim())}>Approve</Button>
        <Button className="button secondary" isDisabled={busy || reason.trim() === ''} onPress={() => onDecide(false, reason.trim())}>Deny</Button>
      </>}
      {grant.can_revoke && <Button className="button secondary" isDisabled={busy} onPress={onRevoke}>{grant.phase === 'Pending' ? 'Withdraw request' : 'Revoke approval'}</Button>}
    </section>
  </>;
}

// ADR-249: the approval inbox. Approvers see the pending requests of other
// people for workloads where they hold action-approver now; everyone sees
// their own requests. The detail page shows the exact reviewed plan.
export function ApprovalsWorkspace({ session, scope, grantID, client = defaultOperations, newID = () => crypto.randomUUID() }: { session: Session; scope: AbortSignal; grantID?: string; client?: Operations; newID?: () => string }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [pending, setPending] = useState<ReviewRow[]>();
  const [requested, setRequested] = useState<ReviewRow[]>();
  const [grant, setGrant] = useState<Grant>();
  // One key per intended decision, reused only for a retry of the same one.
  const keys = useRef(new Map<string, string>());
  const key = (intent: string) => { let k = keys.current.get(intent); if (!k) { k = newID(); keys.current.set(intent, k); } return k; };
  const load = useCallback(async () => {
    setBusy(true); setMessage(undefined);
    try {
      if (grantID) {
        const result = await client.call('get_grant', { grant_id: grantID }, session.csrf_token, scope);
        if (scope.aborted) return;
        if (result.status === 'ok') setGrant(result.data); else if (result.status === 'error') setMessage(result.data.message);
        return;
      }
      const [inbox, own] = await Promise.all([client.call('list_reviews', { view: 'pending' }, session.csrf_token, scope), client.call('list_reviews', { view: 'requested' }, session.csrf_token, scope)]);
      if (scope.aborted) return;
      if (inbox.status === 'ok') setPending(inbox.data.approvals); else if (inbox.status === 'error') setMessage(inbox.data.message);
      if (own.status === 'ok') setRequested(own.data.approvals); else if (own.status === 'error') setMessage(own.data.message);
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error));
    } finally { if (!scope.aborted) setBusy(false); }
  }, [client, grantID, scope, session.csrf_token]);
  useEffect(() => { heading.current?.focus(); void load(); }, [load]);
  const act = async (call: () => Promise<{ status: string; data: unknown }>) => {
    setBusy(true); setMessage(undefined);
    try {
      const result = await call();
      if (scope.aborted) return;
      if (result.status === 'error') { setMessage((result.data as { message: string }).message); return; }
      keys.current.clear();
      await load();
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error) + ' Retrying repeats the same decision.');
    } finally { if (!scope.aborted) setBusy(false); }
  };
  const decide = (approve: boolean, reason: string) => grant && void act(() => client.call('decide_review', { grant_id: grant.grant_id, decision: approve ? 'approve' : 'deny', reason, idempotency_key: key((approve ? 'approve:' : 'deny:') + reason) }, session.csrf_token, scope));
  const revoke = () => grant && void act(() => client.call('revoke_grant', { grant_id: grant.grant_id, expected_revision: grant.revision, idempotency_key: key('revoke:' + grant.revision) }, session.csrf_token, scope));
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>{grantID ? 'Approval request' : 'Approvals'}</h1>
      <p>Sensitive recordings, such as a packet filter that tests payload bytes, need an independent approver before anything is recorded. {grantID ? <a href="/approvals">All approvals</a> : <a href="/captures/new">Collect evidence</a>}</p>
    </div>
    {message && <p role="alert" className="notice">{message}</p>}
    {grantID ? grant && <Detail grant={grant} busy={busy} onDecide={decide} onRevoke={revoke}/> : <>
      <section className="review-section" aria-labelledby="to-review" aria-busy={busy}>
        <h2 id="to-review">Waiting for your review</h2>
        <Rows rows={pending} empty="No requests are waiting for you." label="Requests to review"/>
      </section>
      <section className="review-section" aria-labelledby="my-requests" aria-busy={busy}>
        <h2 id="my-requests">My requests</h2>
        <Rows rows={requested} empty="You have not requested an approval." label="My requests"/>
      </section>
    </>}
    <Button className="button secondary" isDisabled={busy} onPress={() => void load()}>Refresh</Button>
  </div>;
}
