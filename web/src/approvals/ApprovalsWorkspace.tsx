import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operations as captureOperations, type Operations as CaptureOperations } from '../capture/http';
import { approvalSubmissionKey } from '../capture/approval-intent';
import { operationMessage } from '../capture/http';
import { operations as defaultOperations, type Grant, type Operations, type ReviewRow } from './http';

const date = (value: string) => new Date(value).toLocaleString();
const reasons: Record<string, string> = {
  rawBytePredicate: 'a raw byte comparison in the packet filter can test payload bytes',
  logs: 'the selected log window may contain sensitive user data; saved-log queries and native downloads have separate bounded permissions',
  syscallArguments: 'the recording captures approved scalar values and bounded reads of user memory; arguments may contain sensitive user data',
  liveProfile: 'live profiling can affect the application and records raw user data',
  rawPackets: 'the recording keeps payload prefixes up to the approved per-transport caps',
  httpHeaders: 'the recording reads payload to project HTTP/1 method, status, Content-Type and Content-Length; bodies, URLs and credentials are discarded',
  recordingApprovalRequired: 'this installation requires approval for every recording',
  policyCollection: 'recurring policy collection uses a separate finite approval and shared budgets',
};
const accessOperation = (operation: string) => operation === 'get_logs' ? 'Saved log queries' : operation === 'pcap_query' ? 'Saved packet queries' : operation === 'syscall_query' ? 'Saved syscall argument queries' : operation === 'download_artifact' ? 'whole-file downloads' : operation;
const hasQueries = (operations: readonly string[]) => operations.includes('get_logs') || operations.includes('pcap_query') || operations.includes('syscall_query');
const queryDescription = (operations: readonly string[]) => { const kinds = [operations.includes('pcap_query') && 'packet', operations.includes('syscall_query') && 'syscall argument', operations.includes('get_logs') && 'log'].filter(Boolean); return 'Saved ' + (kinds.length > 1 ? kinds.slice(0, -1).join(', ') + ' and ' + kinds.at(-1) : kinds[0]) + ' queries'; };
const phases: Record<string, string> = {
  Pending: 'Waiting for review', Approved: 'Approved', Denied: 'Denied', Revoked: 'Revoked', Expired: 'Expired', Exhausted: 'Exhausted',
};
const bytes = (n: number) => n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(n % (1 << 20) ? 1 : 0)} MiB` : `${n} bytes`;

function Rows({ rows, empty, label }: { rows?: ReviewRow[]; empty: string; label: string }) {
  if (!rows) return null;
  if (rows.length === 0) return <p>{empty}</p>;
  return <ul className="progress-actions" aria-label={label}>{rows.map(row => <li key={row.grant_id}>
    <span><a href={'/approvals/' + row.grant_id}>{row.kind === 'rawQuery' ? `${hasQueries(row.raw_access.operations) ? 'Inspect' : 'Download'} ${row.raw_access.artifact_count} existing artifacts` : `${row.target.workload_kind} ${row.target.workload_name}`}</a>{row.kind !== 'rawQuery' && <> in {row.target.namespace}</>} · {phases[row.phase] ?? row.phase} · requested by {row.requested_by.subject} {date(row.requested_at)}
      {row.phase === 'Pending' && <> · review until {date(row.review_until)}</>}</span>
  </li>)}</ul>;
}

function Detail({ grant, busy, onDecide, onRevoke, onResume, onResolve }: { grant: Grant; busy: boolean; onDecide: (approve: boolean, reason: string) => void; onRevoke: () => void; onResume: () => void; onResolve: () => void }) {
  const [reason, setReason] = useState('');
  const policy = grant.kind === 'policy' ? grant.policy : undefined;
  return <>
    {grant.kind === 'rawQuery' ? <section className="review-section" aria-labelledby="approval-plan">
      <h2 id="approval-plan">{hasQueries(grant.raw_access.operations) ? 'Inspect existing raw evidence' : 'Download existing raw evidence'}</h2>
      <p>{hasQueries(grant.raw_access.operations) ? grant.raw_access.operations.includes('download_artifact') ? `${queryDescription(grant.raw_access.operations)} and whole-file downloads of the selected existing artifacts.` : `${queryDescription(grant.raw_access.operations)} over the selected existing artifacts.` : 'Whole-file download of the selected existing artifacts.'} This approval starts no collection.</p>
      <p>Requested by {grant.requested_by.subject} (client {grant.requested_by.client_id}). Reason: {grant.raw_access.reason}</p>
      <table><thead><tr><th>Artifact</th><th>Target</th><th>Verified native size</th><th>Access until</th></tr></thead><tbody>{grant.raw_access.artifacts.map(a => <tr key={a.artifact_id}><td>{a.native_type} <span className="identifier">{a.artifact_id}</span><br/>Capture {a.capture_id}, action {a.action_id}<details><summary>Exact versions</summary>Copy {a.digest}<br/>Execution {a.execution_digest}</details></td><td>{a.target.workload_kind} {a.target.workload_name ?? a.target.workload_uid}, {a.target.namespace ?? a.target.namespace_uid}; Pod {a.target.pod_name ?? a.target.pod_uid}<br/>Cluster {a.target.cluster_id}<details><summary>Target identities</summary>Namespace {a.target.namespace_uid}<br/>Workload {a.target.workload_uid}<br/>Pod {a.target.pod_uid}</details></td><td>{new Intl.NumberFormat().format(a.native_bytes)} bytes</td><td>{date(a.expires_at)}</td></tr>)}</tbody></table>
      <p>At most {new Intl.NumberFormat().format(grant.raw_access.max_bytes)} bytes and {grant.raw_access.max_operations} {hasQueries(grant.raw_access.operations) ? 'selected operations' : 'download operations'} until {date(grant.raw_access.not_after)}. Used: {grant.raw_access.bytes_used} bytes and {grant.raw_access.operations_used} operations. Retransmissions consume this shared budget.</p>
      {hasQueries(grant.raw_access.operations) && <p>Each paid query page reserves 24 KiB and one operation, including a reply lost in transit. Queries and downloads share the reviewed pool; a query permits at most two paid pages. A query-only pool need not cover the whole native size.</p>}
      <p>Downloaded copies are outside Asservat's automatic deletion. Current permissions and retention still apply.</p>
      <a href={'/cases/' + grant.raw_access.case_id}>Return to evidence</a>
    </section> : <section className="review-section" aria-labelledby="approval-plan">
      <h2 id="approval-plan">What would be recorded</h2>
      <p>{grant.target.workload_kind} <strong>{grant.target.workload_name}</strong>{grant.kind === 'adHocCapture' && <>, Pod {grant.target.pod_name}</>} in namespace {grant.target.namespace} (cluster <span className="identifier">{grant.target.cluster_id}</span>). Data class: {grant.data_class}.</p>
      <p>Needs approval because {grant.reasons.map(r => reasons[r.code] ?? r.code).join('; ')}.</p>
      <table>
        <thead><tr><th scope="col">Action</th><th scope="col">Mode</th><th scope="col">Window</th><th scope="col">Filter</th><th scope="col">Ring</th><th scope="col">Output limit</th></tr></thead>
        <tbody>{grant.actions.map(a => <tr key={a.action_id}>
          <td>{a.kind === 'profile' ? 'Go profile' : a.kind === 'packetCapture' ? 'Packets' : 'Syscalls'} <span className="identifier">{a.action_id}</span></td>
          <td>{a.execution_mode === 'ongoing' ? 'Records while armed' : 'On trigger'}</td>
          <td>{a.profile ? <>{a.profile.type} · {a.profile.mode}{a.profile.duration && <> for {a.profile.duration}</>}<br/>Timeout {a.profile.timeout}; forced GC {a.profile.force_gc ? 'enabled' : 'disabled'}</> : <>{a.before} before, {a.after} after</>}</td>
          <td>{a.filter ? <><code>{a.filter}</code>{a.filter_digest && <> ({a.filter_instructions} instructions, program <span className="identifier">{a.filter_digest.slice(0, 16)}</span>)</>}</> : a.profile ? 'Not applicable' : 'none'}</td>
          <td>{a.profile ? 'No pre-trigger history' : <>{bytes(a.ring_max_bytes ?? 0)}, {a.ring_max_age}</>}</td>
          <td>{bytes(a.max_bytes)}</td>
        </tr>)}</tbody>
      </table>
      {grant.actions.filter(a => a.profile).map(a => {
        const profile = a.profile!;
        return <div key={'endpoint-' + a.action_id}>
          <p>Profile endpoint {profile.source_name} ({profile.source_ref}): {profile.address_mode === 'targetLoopback' ? 'target Pod loopback' : 'target Pod IP'}, {profile.definition_digest && profile.source_kind === 'templateBinding' ? <>named TCP port {profile.declared_port_name}, allowed range {profile.minimum_port}–{profile.maximum_port}</> : <>TCP port {profile.port}</>}, {profile.path_policy}. {profile.definition_digest ? 'Every triggering Pod must match this reviewed endpoint definition.' : 'The reviewed endpoint must match at execution.'}</p>
          {profile.definition_digest && <details><summary>Reviewed endpoint definition</summary><p>{profile.source_kind === 'templateBinding' ? 'Pod template binding' : 'Administrator endpoint profile'} · <span className="identifier">{profile.definition_digest}</span></p></details>}
        </div>;
      })}
      {grant.observation_limits && <p>Observation limits bound by this approval: {grant.observation_limits.max_session_seconds} s per session, {bytes(grant.observation_limits.max_observed_bytes)} in total, {bytes(grant.observation_limits.max_bytes_per_second)} per second, {grant.observation_limits.max_concurrent_sessions} concurrent session.{grant.observation_limits.max_observed_events !== undefined && <> {grant.observation_limits.max_observed_events} eligible entry and exit probes in total.</>}</p>}
      {grant.result_access && <p>Follow-up access for the requester only: {grant.result_access.operations.map(accessOperation).join(', ')} by clients {grant.result_access.client_ids.join(', ')}, at most {grant.result_access.max_artifacts} artifacts and {bytes(grant.result_access.max_bytes)} in total until {date(grant.result_access.not_after)} (used: {grant.result_access.artifacts_used} artifacts, {bytes(grant.result_access.bytes_used)}).</p>}
      {grant.result_access && hasQueries(grant.result_access.operations) && <p>Each paid query page reserves 24 KiB and one operation from that same follow-up pool. Downloaded bytes and query pages share its limit.</p>}
      {policy ? <>
        <p>Team policy <span className="identifier">{policy.uid}</span> runs as <span className="identifier">{policy.executor.subject}</span> under the reviewed team authority from {date(policy.authority_issued_at)} until {date(policy.authority_not_after)}.</p>
        <p>Grant reservations: {policy.executions_used} of {policy.max_executions} action starts; {bytes(policy.collected_bytes_used)} of {bytes(policy.max_collected_bytes)} output; {bytes(policy.observed_bytes_used)} of {bytes(policy.max_observed_bytes)} sensitive observation.{!!policy.max_observed_events && <> {policy.observed_events_used ?? 0} of {policy.max_observed_events} eligible entry and exit probes.</>} Reservations include uncertain work and are not refunded by replacing an approval. Team, workload and admission limits can further restrict collection.</p>
        <p className="field-help">Plan digest <span className="identifier">{grant.execution_digest}</span>. Requested by {grant.requested_by.subject} on {date(grant.requested_at)}. This approval expires {date(grant.not_after!)} from its original request; requester credentials do not renew team execution. Current team authority and permissions still apply.</p>
        <p>This approval grants no evidence access. Inspect or download gathered user data through your current evidence permissions.</p>
      </> : <p className="field-help">Plan digest <span className="identifier">{grant.execution_digest}</span>. Requested by {grant.requested_by.subject} (client {grant.requested_by.client_id}) on {date(grant.requested_at)}; the preview was valid until {date(grant.preview_deadline!)}. {grant.capture_deadline_rule === 'acceptanceWithinGrant' ? `After approval, submitting this plan starts a capture window of at most ${Math.round(grant.capture_window_seconds! / 60)} minutes, bounded by the approval expiry.` : 'This legacy plan must start before its preview deadline; create a new preview if it has expired.'} An approval lasts {Math.round(grant.lifetime_seconds / 60)} minutes and covers only this exact plan and requester.</p>}
    </section>}
    <section className="review-section" aria-labelledby="approval-state">
      <h2 id="approval-state">Decision</h2>
      <p role="status">{phases[grant.phase] ?? grant.phase}{grant.phase === 'Pending' && <> until {date(grant.review_until)}</>}
        {grant.decision && <> · {grant.decision.decision} by {grant.decision.decided_by.subject} on {date(grant.decision.decided_at)}: {grant.decision.reason}</>}
        {grant.not_after && (grant.kind === 'policy' || grant.phase === 'Approved') && <> · valid until {date(grant.not_after)}</>}
        {grant.revoked_at && <> · revoked {date(grant.revoked_at)}</>}</p>
      {grant.can_decide && <>
        <label htmlFor="approval-reason">Reason (recorded with your decision)</label>
        <textarea id="approval-reason" rows={2} maxLength={512} value={reason} onChange={event => setReason(event.target.value)}/>
        <p className="field-help">Approving needs a recent step-up sign-in at your identity provider. You cannot decide a request you made yourself. Signing in returns to this plan; review it again before deciding.</p>
        <a className="button secondary" href={'/auth/step-up?return_to=' + encodeURIComponent('/approvals/' + grant.grant_id)}>Sign in with step-up</a>
        <Button className="button" isDisabled={busy || reason.trim() === ''} onPress={() => onDecide(true, reason.trim())}>Approve</Button>
        <Button className="button secondary" isDisabled={busy || reason.trim() === ''} onPress={() => onDecide(false, reason.trim())}>Deny</Button>
      </>}
      {grant.can_resume && <div className="actions"><Button className="button" isDisabled={busy} onPress={onResume}>Continue approved capture</Button><p>Uses the exact reviewed preview and original requester client. It can continue the original accepted acquisition; it cannot create another capture.</p></div>}
      {grant.can_resolve && grant.phase !== 'Pending' && grant.phase !== 'Denied' && <div className="actions"><Button className="button secondary" isDisabled={busy} onPress={onResolve}>Find capture; otherwise close request</Button><p>Opens the original capture if it was accepted. Otherwise it closes this reviewed request so it cannot start a capture.</p></div>}
      {grant.resume_requires_original_client && grant.phase === 'Approved' && <p>Collection must continue through the original requesting client ({grant.requested_by.client_id}) with its current permissions. This page does not transfer its approval to another client.</p>}
      {grant.can_revoke && <Button className="button secondary" isDisabled={busy} onPress={onRevoke}>{grant.phase === 'Pending' ? 'Withdraw request' : 'Revoke approval'}</Button>}
    </section>
  </>;
}

// ADR-249: the approval inbox. Approvers see the pending requests of other
// people for workloads where they hold action-approver now; everyone sees
// their own requests. The detail page shows the exact reviewed plan.
export function ApprovalsWorkspace({ session, scope, grantID, client = defaultOperations, captureClient = captureOperations, newID = () => crypto.randomUUID(), onAccepted = captureID => window.location.assign('/captures/' + captureID) }: { session: Session; scope: AbortSignal; grantID?: string; client?: Operations; captureClient?: CaptureOperations; newID?: () => string; onAccepted?: (captureID: string) => void }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const command = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => command.current?.abort(), [scope]);
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
  const continueRequest = async (resolve: boolean) => {
    const original = grant;
    if (!original || original.kind !== 'adHocCapture' || !original.preview_id || busy || scope.aborted || (resolve ? !original.can_resolve : !original.can_resume)) return;
    command.current?.abort();
    const request = new AbortController(); command.current = request;
    const abort = () => request.abort(); scope.addEventListener('abort', abort, { once: true });
    const input = { preview_id: original.preview_id, idempotency_key: approvalSubmissionKey(original.preview_id) };
    setBusy(true); setMessage(undefined);
    try {
      if (resolve) {
        const result = await captureClient.call('resolve_capture_request', input, session.csrf_token, request.signal);
        if (request.signal.aborted || scope.aborted || command.current !== request) return;
        if (result.status === 'ok') {
          if (result.data.state === 'accepted') onAccepted(result.data.capture_id);
          else {
            setGrant({ ...original, can_resume: false, can_resolve: false });
            setMessage('The original request is closed. Prepare a new review before collecting.');
          }
        } else setMessage(result.status === 'error' ? result.data.message : 'The original result is not confirmed. Resolve this same request again.');
      } else {
        const result = await captureClient.call('request_capture', { ...input, continue_acquisition: true }, session.csrf_token, request.signal);
        if (request.signal.aborted || scope.aborted || command.current !== request) return;
        if (result.status === 'ok') onAccepted(result.data.capture_id);
        else setMessage(result.status === 'error' ? result.data.message : 'The original result is not confirmed. Retry this same approved request.');
      }
    } catch (error) {
      if (!request.signal.aborted && !scope.aborted) setMessage(operationMessage(error) + ' Retrying uses this same reviewed request. You can resolve its original outcome before making another request.');
    } finally {
      scope.removeEventListener('abort', abort);
      if (!request.signal.aborted && !scope.aborted && command.current === request) setBusy(false);
    }
  };
  const decide = (approve: boolean, reason: string) => grant && void act(() => client.call('decide_review', { grant_id: grant.grant_id, decision: approve ? 'approve' : 'deny', reason, idempotency_key: key((approve ? 'approve:' : 'deny:') + reason) }, session.csrf_token, scope));
  const revoke = () => grant && void act(() => client.call('revoke_grant', { grant_id: grant.grant_id, expected_revision: grant.revision, idempotency_key: key('revoke:' + grant.revision) }, session.csrf_token, scope));
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>{grantID ? 'Approval request' : 'Approvals'}</h1>
      <p>Sensitive recordings, such as a packet filter that tests payload bytes, need an independent approver before anything is recorded. {grantID ? <a href="/approvals">All approvals</a> : <a href="/captures/new">Collect evidence</a>}</p>
    </div>
    {message && <p role="alert" className="notice">{message}</p>}
    {grantID ? grant && <Detail grant={grant} busy={busy} onDecide={decide} onRevoke={revoke} onResume={() => void continueRequest(false)} onResolve={() => void continueRequest(true)}/> : <>
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
