import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Entry, Policies } from './policies';

const states: Record<string, string> = {
  active: 'Active', deactivated: 'Deactivated', suspended: 'Suspended in Kubernetes', changed: 'Changed since activation',
  expired: 'Expired', deleted: 'Deleted in Kubernetes',
};
const reasons: Record<string, string> = {
  cooldown: 'cooldown or workload budget', budget: 'execution limit reached', coalesced: 'restarts between two polls',
  capacity: 'collection capacity', authority: 'access no longer sufficient', unavailable: 'target or service unavailable',
  overlong: 'log records longer than the record limit, not evaluated',
};

const metrics: Record<string, string> = {
  cpuCores: 'CPU usage (cores)', cpuQuotaRatio: 'CPU usage / CPU limit', memoryBytes: 'memory working set (bytes)', memoryLimitRatio: 'memory working set / memory limit',
};
const operators: Record<string, string> = { gt: '>', gte: '≥', lt: '<', lte: '≤' };

type Status = NonNullable<Entry['status']>;

const sharingStates: Record<string, string> = {
  active: 'sharing', limitReached: 'capture limit reached', expired: 'ended', revoked: 'revoked',
  stopped: 'future sharing stopped; existing shares stay until they expire or are revoked',
  policyChanged: 'stopped: the DebugPolicy changed; activate the new revision to share again',
};

// ADR-239: repeated collections will be shared; existing shares stay until
// they expire or are revoked.
function sharing(s: NonNullable<Status['sharing']>): string {
  const n = s.recipients === 1 ? '1 recipient' : `${s.recipients} recipients`;
  return `Repeated collections will be shared with ${n} until ${new Date(s.not_after).toLocaleString()}: ${s.shared_captures} of ${s.max_captures} captures shared (${sharingStates[s.state] ?? s.state})`;
}

// The current DebugPolicy's detector (ADR-228/230/231/241), configuration only.
function detector(d: NonNullable<Status['detector']>): string {
  if (d.kind === 'alert') return 'Firing Alertmanager alerts naming a pod of the workload';
  if (d.kind === 'log') {
    const field = d.json_field ? ' in a JSON field' : '';
    return `Container log records matching a ${d.match === 'regexp' ? 'regular expression' : 'text'}${field} within ${d.window_seconds ?? 0} s (Kubernetes log API)`;
  }
  if (d.kind === 'resource') {
    return `${metrics[d.metric ?? ''] ?? d.metric ?? ''} ${operators[d.operator ?? ''] ?? d.operator ?? ''} ${d.threshold ?? ''}, samples at most ${d.sample_interval_seconds ?? 0} s old (Kubernetes metrics API)`;
  }
  if (d.kind === 'probe') {
    const n = d.minimum_failures ?? 1;
    return `${d.probe_type ?? ''} probe failures: ${n} ${n === 1 ? 'failure' : 'failures'} within ${d.window_seconds ?? 0} s (Kubernetes Events)`;
  }
  const codes = d.exit_codes?.length ? `, exit codes ${d.exit_codes.join(', ')}` : '';
  return `Container restarts: ${(d.reasons ?? []).join(', ')}${codes}`;
}

function occurrence(o: Status['recent'][number]): string {
  if (o.detector === 'alert' && o.failed_at) return `alert started at ${new Date(o.failed_at).toLocaleString()}`;
  if (o.detector === 'log' && o.failed_at) return `matching log record at ${new Date(o.failed_at).toLocaleString()}`;
  if (o.detector === 'resource' && o.failed_at) return `resource condition met at ${new Date(o.failed_at).toLocaleString()}`;
  return o.detector === 'probe' && o.failed_at ? `probe failure at ${new Date(o.failed_at).toLocaleString()}` : `restart ${o.restarts ?? ''}`;
}

function PolicyGrantControls({ entry, controller }: { entry: Entry; controller: Policies }) {
  const s = entry.status!;
  const [executions, setExecutions] = useState(Math.min(s.max_executions, 10));
  const [output, setOutput] = useState(Math.min(s.max_collected_bytes, 8 << 20));
  const [observed, setObserved] = useState(s.max_observed_bytes);
  const [days, setDays] = useState('');
  const [seconds, setSeconds] = useState(10);
  const [rate, setRate] = useState(16 << 20);
  const [concurrent, setConcurrent] = useState(1);
  const [grantID, setGrantID] = useState('');
  return <section aria-label={'Policy approval for ' + entry.name}>
    <h3>Policy approval</h3>
    {s.attached_grant_id ? <p>Attached policy grant: <a href={'/approvals/' + s.attached_grant_id}>{s.attached_grant_id}</a>. Current authority, budgets and recorder readiness still apply.</p> : <p>No policy grant is attached.</p>}
    <p>A different human approver reviews this workload, configuration and finite limits. Approval gives no personal evidence access.</p>
    <form onSubmit={event => { event.preventDefault(); void controller.requestGrant(entry.name, {
      limits: { max_executions: executions, max_collected_bytes: output, max_observed_bytes: observed },
      ...(days ? { lifetime_seconds: Number(days) * 86400 } : {}),
      ...(observed > 0 ? { observation_limits: { max_session_seconds: seconds, max_observed_bytes: observed, max_bytes_per_second: rate, max_concurrent_sessions: concurrent } } : {}),
    }); }}>
      <fieldset disabled={entry.busy || entry.requestPending}>
        <legend>Approval limits</legend>
        <label>Maximum executions<input type="number" required min={1} max={s.max_executions} step={1} value={executions} onChange={e => setExecutions(Number(e.target.value))}/></label>
        <label>Maximum output (bytes)<input type="number" required min={1} max={s.max_collected_bytes} step={1} value={output} onChange={e => setOutput(Number(e.target.value))}/></label>
        <label>Maximum observed input (bytes)<input type="number" required min={0} max={s.max_observed_bytes} step={1} value={observed} onChange={e => setObserved(Number(e.target.value))}/></label>
        <label>Approval period (days, optional)<input type="number" min={1} max={365} step={1} value={days} onChange={e => setDays(e.target.value)}/></label>
        <p>Leave the period empty to use the installation default. The original policy expiry still applies.</p>
        {observed > 0 && <>
          <label>Maximum session (seconds)<input type="number" required min={1} max={3600} step={1} value={seconds} onChange={e => setSeconds(Number(e.target.value))}/></label>
          <label>Maximum input rate (bytes/second)<input type="number" required min={1} max={1 << 30} step={1} value={rate} onChange={e => setRate(Number(e.target.value))}/></label>
          <label>Maximum concurrent sessions<input type="number" required min={1} max={1000} step={1} value={concurrent} onChange={e => setConcurrent(Number(e.target.value))}/></label>
        </>}
      </fieldset>
      {entry.requestPending && <p>Retry keeps the original request and selected limits.</p>}
      <Button type="submit" className="button secondary" isDisabled={entry.busy}>{entry.requestPending ? 'Retry approval request' : 'Request policy approval'}</Button>
    </form>
    {entry.grant && <p>Approval request recorded. <a href={entry.grant.approval_navigation_uri}>View policy approval</a>.</p>}
    <form onSubmit={event => { event.preventDefault(); void controller.attachGrant(entry.name, grantID.trim()); }}>
      <label>Approved policy grant ID<input disabled={entry.busy || !!entry.attachmentPending} required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" value={grantID} onChange={e => setGrantID(e.target.value)} autoComplete="off" spellCheck={false}/></label>
      <p>A current team manager can attach the reviewed grant. This keeps the original policy expiry and shared spend.</p>
      <Button type="submit" className="button secondary" isDisabled={entry.busy}>{entry.attachmentPending ? 'Retry attachment' : 'Attach approved grant'}</Button>
    </form>
  </section>;
}

function PolicyEntry({ entry, controller }: { entry: Entry; controller: Policies }) {
  const s = entry.status;
  const active = s?.state === 'active';
  return <article className="diagnostic" aria-busy={entry.busy} aria-labelledby={'policy-' + entry.name}>
    <h2 id={'policy-' + entry.name}>{entry.name}</h2>
    {s ? <>
      <p role="status">{states[s.state] ?? s.state}</p>
      <dl className="facts">
        {s.detector && <><dt>Trigger</dt><dd>{detector(s.detector)}</dd></>}
        <dt>Shared policy executions</dt><dd>{s.executions_spent} of {s.max_executions} used</dd>
        <dt>Shared output reservations</dt><dd>{s.collected_bytes_spent.toLocaleString()} of {s.max_collected_bytes.toLocaleString()} bytes reserved</dd>
        <dt>Shared observation charges</dt><dd>{s.observed_bytes_spent.toLocaleString()} of {s.max_observed_bytes.toLocaleString()} bytes charged before filtering</dd>
        <dt>Expires</dt><dd>{new Date(s.expires_at).toLocaleString()}</dd>
        <dt>Watched pods</dt><dd>{s.watched_pods}</dd>
        <dt>Occurrences</dt><dd>{s.occurrences}, {s.captured} captured</dd>
        {s.sharing && <><dt>Sharing</dt><dd>{sharing(s.sharing)}</dd></>}
        {s.suppressions.length > 0 && <><dt>Suppressed</dt><dd>{s.suppressions.map(x => `${x.count} × ${reasons[x.reason] ?? x.reason}`).join('; ')}</dd></>}
      </dl>
      <p>These policy budgets are shared across captures and grants. Reservations and uncertain spend stay charged; they are not measurements of gathered user data. Grant and workload limits may further restrict collection.</p>
      {s.collection_kind === 'packetCapture' && s.state === 'active' && <PolicyGrantControls entry={entry} controller={controller}/>}
      {s.recent.length > 0 && <ul className="progress-actions" aria-label="Recent occurrences">{s.recent.map(o => <li key={o.occurrence_id}>
        <span>{new Date(o.created_at).toLocaleString()} ({occurrence(o)})</span>
        <span>{o.capture_id ? <a href={'/captures/' + o.capture_id}>View capture</a> : o.outcome}</span>
      </li>)}</ul>}
      {s.state === 'deactivated' && <p>Existing captures and evidence are kept. This revision cannot be activated again; change the DebugPolicy to activate a new revision.</p>}
    </> : !entry.busy && !entry.message && <p role="status">No status yet.</p>}
    {entry.message && <p role="alert" className="notice">{entry.message}</p>}
    {entry.review && <div role="alert" className="notice"><p>{entry.review}</p>
      <Button className="button" isDisabled={entry.busy} onPress={() => void controller.activateSharing(entry.name)}>Activate and share</Button></div>}
    <div className="actions">
      {!active && s?.state !== 'deactivated' && <Button className="button" isDisabled={entry.busy} onPress={() => void controller.activate(entry.name)}>Activate</Button>}
      {s && s.state !== 'deactivated' && <Button className={active ? 'button' : 'button secondary'} isDisabled={entry.busy} onPress={() => void controller.deactivate(entry.name)}>Deactivate</Button>}
      {s?.sharing && s.sharing.state !== 'revoked' && s.sharing.state !== 'stopped' && <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.stopSharing(entry.name)}>Stop future sharing</Button>}
      {s?.sharing && s.sharing.state !== 'revoked' && <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.revokeSharing(entry.name)}>Revoke all shares</Button>}
      <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.refresh(entry.name)}>Check status</Button>
    </div>
  </article>;
}

// Hub-held restart-, probe-, alert-, log- and resource-trigger DebugPolicies (ADR-228/229/230/231/241). Activation, status and
// deactivation are the shared browser/MCP operations; nothing is decided here.
export function PolicyWorkspace({ session, scope, controller }: { session: Session; scope: AbortSignal; controller: Policies }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [name, setName] = useState('');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => controller.attach(session, scope), [controller, session, scope]);
  useEffect(() => { heading.current?.focus(); }, []);
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Automatic policies</h1>
      <p>Activate a hub-held restart, probe-failure, alert, log or resource policy for your team, check what it captured and stop it.
 A permission administrator can also stop a policy by suspending it in Kubernetes. <a href="/captures/new">Collect evidence manually</a>.</p>
    </div>
    <form onSubmit={event => { event.preventDefault(); void controller.lookup(name); }}>
      <label>Policy name<input name="policy" value={name} required maxLength={253} pattern="[a-z0-9]([\-a-z0-9.]*[a-z0-9])?" onChange={event => setName(event.target.value)} autoComplete="off" spellCheck={false}/></label>
      <p className="field-help">Use the DebugPolicy name in the hub control namespace.</p>
      <Button type="submit" className="button secondary">Show policy</Button>
    </form>
    {state.entries.map(entry => <PolicyEntry key={entry.name} entry={entry} controller={controller}/>)}
  </div>;
}
