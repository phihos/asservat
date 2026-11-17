import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Entry, Policies } from './policies';

const states: Record<string, string> = {
  active: 'Active', deactivated: 'Deactivated', suspended: 'Suspended in Kubernetes',
  renewalDue: 'Active, renewal due: an approver can renew it in the approvals inbox', expired: 'Expired', deleted: 'Deleted in Kubernetes',
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
  policyChanged: 'stopped: the DebugPolicy changed; its new revision shares again once accepted',
};

// ADR-239: repeated collections will be shared; existing shares stay until
// they expire or are revoked.
function sharing(s: NonNullable<Status['sharing']>): string {
  const n = s.recipients === 1 ? '1 recipient' : `${s.recipients} recipients`;
  const of = s.max_captures === undefined ? '' : ` of ${s.max_captures}`;
  return `Repeated collections will be shared with ${n} until ${new Date(s.not_after).toLocaleString()}: ${s.shared_captures}${of} captures shared (${sharingStates[s.state] ?? s.state})`;
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

// Legacy policy approval request and attachment (request_policy_grant,
// activate_policy with grant_id); they remain until hub-side acceptance
// (specs/policy-automation.md) opens and attaches the review itself.
function PolicyGrantControls({ entry, controller }: { entry: Entry; controller: Policies }) {
  const s = entry.status!;
  const finite = s.collection_kind === 'profile' || s.collection_kind === 'logs';
  const [executions, setExecutions] = useState(10);
  const [output, setOutput] = useState(finite ? s.max_collected_bytes ?? 1 : Math.min(s.max_collected_bytes ?? 8 << 20, 8 << 20));
  const [observed, setObserved] = useState(0);
  const [days, setDays] = useState('');
  const [seconds, setSeconds] = useState(10);
  const [rate, setRate] = useState(16 << 20);
  const [concurrent, setConcurrent] = useState(1);
  const [grantID, setGrantID] = useState('');
  return <section aria-label={'Policy approval for ' + entry.policy_name}>
    <h3>Policy approval</h3>
    <p>A different human approver reviews this workload, configuration and finite limits. Approval gives no personal evidence access.</p>
    <form onSubmit={event => { event.preventDefault(); void controller.requestGrant(entry.key, {
      limits: { max_executions: executions, max_collected_bytes: output, max_observed_bytes: finite ? 0 : observed },
      ...(days ? { lifetime_seconds: Number(days) * 86400 } : {}),
      ...(!finite && observed > 0 ? { observation_limits: { max_session_seconds: seconds, max_observed_bytes: observed, max_bytes_per_second: rate, max_concurrent_sessions: concurrent } } : {}),
    }); }}>
      <fieldset disabled={entry.busy || entry.requestPending}>
        <legend>Approval limits</legend>
        <label>Action starts<input type="number" required min={1} step={1} value={executions} onChange={e => setExecutions(Number(e.target.value))}/></label>
        <label>Maximum output (bytes)<input type="number" required min={1} step={1} value={output} onChange={e => setOutput(Number(e.target.value))}/></label>
        {!finite && <label>Maximum observed input (bytes)<input type="number" required min={0} step={1} value={observed} onChange={e => setObserved(Number(e.target.value))}/></label>}
        <label>Approval period (days, optional)<input type="number" min={1} step={1} value={days} onChange={e => setDays(e.target.value)}/></label>
        <p>Leave the period empty to use the installation default. The original policy expiry still applies.</p>
        {!finite && observed > 0 && <>
          <label>Maximum session (seconds)<input type="number" required min={1} step={1} value={seconds} onChange={e => setSeconds(Number(e.target.value))}/></label>
          <label>Maximum input rate (bytes/second)<input type="number" required min={1} step={1} value={rate} onChange={e => setRate(Number(e.target.value))}/></label>
          <label>Maximum concurrent sessions<input type="number" required min={1} step={1} value={concurrent} onChange={e => setConcurrent(Number(e.target.value))}/></label>
        </>}
      </fieldset>
      {entry.requestPending && <p>Retry keeps the original request and selected limits.</p>}
      <Button type="submit" className="button secondary" isDisabled={entry.busy}>{entry.requestPending ? 'Retry approval request' : 'Request policy approval'}</Button>
    </form>
    {entry.grant && <p>Approval request recorded. <a href={entry.grant.approval_navigation_uri}>View policy approval</a>.</p>}
    <form onSubmit={event => { event.preventDefault(); void controller.attachGrant(entry.key, grantID.trim()); }}>
      <label>Approved policy grant ID<input disabled={entry.busy || !!entry.attachmentPending} required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" value={grantID} onChange={e => setGrantID(e.target.value)} autoComplete="off" spellCheck={false}/></label>
      <p>A current team manager can attach the reviewed grant. This keeps the original policy expiry and shared spend.</p>
      <Button type="submit" className="button secondary" isDisabled={entry.busy}>{entry.attachmentPending ? 'Retry attachment' : 'Attach approved grant'}</Button>
    </form>
  </section>;
}

function PolicyEntry({ entry, controller }: { entry: Entry; controller: Policies }) {
  const s = entry.status;
  const live = s?.state === 'active' || s?.state === 'renewalDue';
  return <article className="diagnostic" aria-busy={entry.busy} aria-labelledby={'policy-' + entry.key}>
    <h2 id={'policy-' + entry.key}>{entry.policy_name}</h2>
    <p>{entry.cluster} / {entry.namespace}</p>
    {s ? <>
      <p role="status">{states[s.state] ?? s.state}{s.renewal_due && s.state !== 'renewalDue' ? '; renewal due' : ''}</p>
      <dl className="facts">
        {s.collection_kind === 'profile' && <><dt>Collection</dt><dd>Go endpoint profile</dd></>}
        {s.collection_kind === 'logs' && <><dt>Collection</dt><dd>Finite whole-Pod logs</dd></>}
        {s.detector && <><dt>Trigger</dt><dd>{detector(s.detector)}</dd></>}
        {s.executions_spent !== undefined && <><dt>Policy executions</dt><dd>{s.executions_spent}</dd></>}
        {s.collected_bytes_spent !== undefined && <><dt>Output reserved</dt><dd>{s.collected_bytes_spent.toLocaleString()}{s.max_collected_bytes !== undefined ? ` of ${s.max_collected_bytes.toLocaleString()}` : ''} bytes</dd></>}
        {s.expires_at && <><dt>Expires</dt><dd>{new Date(s.expires_at).toLocaleString()}</dd></>}
        <dt>Watched pods</dt><dd>{s.watched_pods}</dd>
        <dt>Occurrences</dt><dd>{s.occurrences}, {s.captured} captured</dd>
        {s.sharing && <><dt>Sharing</dt><dd>{sharing(s.sharing)}</dd></>}
        {s.suppressions.length > 0 && <><dt>Suppressed</dt><dd>{s.suppressions.map(x => `${x.count} × ${reasons[x.reason] ?? x.reason}`).join('; ')}</dd></>}
      </dl>
      {s.attached_grant_id && <p><a href={'/approvals/' + s.attached_grant_id}>View policy approval</a></p>}
      {s.collection_kind !== 'podStatus' && live && <PolicyGrantControls entry={entry} controller={controller}/>}
      {s.recent.length > 0 && <ul className="progress-actions" aria-label="Recent occurrences">{s.recent.map(o => <li key={o.occurrence_id}>
        <span>{new Date(o.created_at).toLocaleString()} ({occurrence(o)})</span>
        <span>{o.capture_id ? <a href={'/captures/' + o.capture_id}>View capture</a> : o.outcome}</span>
      </li>)}</ul>}
      {s.state === 'deactivated' && <p>Existing captures and evidence are kept. This revision cannot be activated again; change the DebugPolicy to activate a new revision.</p>}
    </> : !entry.busy && !entry.message && <p role="status">No status yet.</p>}
    {entry.message && <p role="alert" className="notice">{entry.message}</p>}
    {entry.review && <div role="alert" className="notice"><p>{entry.review}</p>
      <Button className="button" isDisabled={entry.busy} onPress={() => void controller.activateSharing(entry.key)}>Activate and share</Button></div>}
    <div className="actions">
      {!live && s?.state !== 'deactivated' && <Button className="button" isDisabled={entry.busy} onPress={() => void controller.activate(entry.key)}>Activate</Button>}
      {live && <Button className="button" isDisabled={entry.busy} onPress={() => void controller.deactivate(entry.key)}>Deactivate</Button>}
      {s?.sharing && s.sharing.state !== 'revoked' && s.sharing.state !== 'stopped' && <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.stopSharing(entry.key)}>Stop future sharing</Button>}
      {s?.sharing && s.sharing.state !== 'revoked' && <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.revokeSharing(entry.key)}>Revoke all shares</Button>}
      <Button className="button secondary" isDisabled={entry.busy} onPress={() => void controller.refresh(entry.key)}>Check status</Button>
    </div>
  </article>;
}

// Hub-held DebugPolicies (ADR-228/229/230/231/241). Activation, status and
// deactivation are the shared browser/MCP operations. Activation and the
// policy approval request remain until hub-side acceptance replaces them.
export function PolicyWorkspace({ session, scope, controller }: { session: Session; scope: AbortSignal; controller: Policies }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [ref, setRef] = useState({ cluster: 'local', namespace: '', policy_name: '' });
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => controller.attach(session, scope), [controller, session, scope]);
  useEffect(() => { heading.current?.focus(); }, []);
  const field = (label: string, key: keyof typeof ref, pattern: string, maxLength: number) =>
    <label>{label}<input name={key} value={ref[key]} required maxLength={maxLength} pattern={pattern} onChange={event => setRef({ ...ref, [key]: event.target.value })} autoComplete="off" spellCheck={false}/></label>;
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Automatic policies</h1>
      <p>Activate a hub-held restart, probe-failure, alert, log or resource policy for your team, check what it captured and stop it.
 A permission administrator can also stop a policy by suspending it in Kubernetes. <a href="/captures/new">Collect evidence manually</a>.</p>
    </div>
    <form onSubmit={event => { event.preventDefault(); void controller.lookup(ref); }}>
      {field('Cluster', 'cluster', '[a-z0-9]([\\-a-z0-9]*[a-z0-9])?', 63)}
      {field('Namespace', 'namespace', '[a-z0-9]([\\-a-z0-9]*[a-z0-9])?', 63)}
      {field('Policy name', 'policy_name', '[a-z0-9]([\\-a-z0-9.]*[a-z0-9])?', 253)}
      <p className="field-help">Use "local" for the hub's own cluster.</p>
      <Button type="submit" className="button secondary">Show policy</Button>
    </form>
    {state.entries.map(entry => <PolicyEntry key={entry.key} entry={entry} controller={controller}/>)}
  </div>;
}
