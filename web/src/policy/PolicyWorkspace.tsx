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
};

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

// The current DebugPolicy's detector (ADR-228/230/231), configuration only.
function detector(d: NonNullable<Status['detector']>): string {
  if (d.kind === 'alert') return 'Firing Alertmanager alerts naming a pod of the workload';
  if (d.kind === 'probe') {
    const n = d.minimum_failures ?? 1;
    return `${d.probe_type ?? ''} probe failures: ${n} ${n === 1 ? 'failure' : 'failures'} within ${d.window_seconds ?? 0} s (Kubernetes Events)`;
  }
  const codes = d.exit_codes?.length ? `, exit codes ${d.exit_codes.join(', ')}` : '';
  return `Container restarts: ${(d.reasons ?? []).join(', ')}${codes}`;
}

function occurrence(o: Status['recent'][number]): string {
  if (o.detector === 'alert' && o.failed_at) return `alert started at ${new Date(o.failed_at).toLocaleString()}`;
  return o.detector === 'probe' && o.failed_at ? `probe failure at ${new Date(o.failed_at).toLocaleString()}` : `restart ${o.restarts ?? ''}`;
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
        <dt>Executions</dt><dd>{s.executions_spent} of {s.max_executions} used</dd>
        <dt>Expires</dt><dd>{new Date(s.expires_at).toLocaleString()}</dd>
        <dt>Watched pods</dt><dd>{s.watched_pods}</dd>
        <dt>Occurrences</dt><dd>{s.occurrences}, {s.captured} captured</dd>
        {s.sharing && <><dt>Sharing</dt><dd>{sharing(s.sharing)}</dd></>}
        {s.suppressions.length > 0 && <><dt>Suppressed</dt><dd>{s.suppressions.map(x => `${x.count} × ${reasons[x.reason] ?? x.reason}`).join('; ')}</dd></>}
      </dl>
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

// Hub-held restart-, probe- and alert-trigger DebugPolicies (ADR-228/229/230/231). Activation, status and
// deactivation are the shared browser/MCP operations; nothing is decided here.
export function PolicyWorkspace({ session, scope, controller }: { session: Session; scope: AbortSignal; controller: Policies }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [name, setName] = useState('');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => controller.attach(session, scope), [controller, session, scope]);
  useEffect(() => { heading.current?.focus(); }, []);
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Automatic policies</h1>
      <p>Activate a hub-held restart, probe-failure or alert policy for your team, check what it captured and stop it. A permission administrator can also stop a policy by suspending it in Kubernetes. <a href="/captures/new">Collect evidence manually</a>.</p>
    </div>
    <form onSubmit={event => { event.preventDefault(); void controller.lookup(name); }}>
      <label>Policy name<input name="policy" value={name} required maxLength={253} pattern="[a-z0-9]([\-a-z0-9.]*[a-z0-9])?" onChange={event => setName(event.target.value)} autoComplete="off" spellCheck={false}/></label>
      <p className="field-help">Use the DebugPolicy name in the hub control namespace.</p>
      <Button type="submit" className="button secondary">Show policy</Button>
    </form>
    {state.entries.map(entry => <PolicyEntry key={entry.name} entry={entry} controller={controller}/>)}
  </div>;
}
