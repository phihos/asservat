import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ContextProjection, SyscallSelection } from './projection';

export function SyscallProjectionView({ controller, session, scope, caseID, artifactID, version }: { controller: ContextProjection; session: Session; scope: AbortSignal; caseID: string; artifactID: string; version: string }) {
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, caseID, artifactID, version);
  const state = attached ? snapshot : { phase: 'idle' as const };
  const [view, setView] = useState<SyscallSelection['view']>('summary');
  const [limit, setLimit] = useState('100');
  const [names, setNames] = useState('');
  const [errorsOnly, setErrorsOnly] = useState(false);
  useEffect(() => controller.attach(session, scope, caseID, artifactID, version), [controller, session, scope, caseID, artifactID, version]);
  const busy = !attached || state.phase === 'loading' || state.phase === 'pending';
  const coverage = state.syscallSummary?.coverage ?? state.syscallEvents?.coverage;
  const inspect = () => controller.inspectSyscalls({ view, limit: Number(limit), names: view === 'events' && names.trim() ? names.split(',').map(name => name.trim()) : [], errorsOnly: view === 'events' && errorsOnly });
  return <section className="syscall-projection" aria-label="Saved syscall views" aria-busy={state.phase === 'loading'}>
    <h3>Saved syscall views</h3>
    <p>Inspect recorded syscall names, outcomes, timing and source identities. Arguments, paths, buffers and pointers are omitted.</p>
    <label>Syscall view <select value={view} disabled={busy} onChange={event => { controller.close(); setView(event.target.value as SyscallSelection['view']); setNames(''); setErrorsOnly(false); }}><option value="summary">Summary</option><option value="events">Events</option></select></label>
    <label>Rows per page <input type="number" min={1} max={100} value={limit} disabled={busy} onChange={event => { controller.close(); setLimit(event.target.value); }}/></label>
    {view === 'events' && <>
      <label>Syscall names, separated by commas <input value={names} maxLength={8320} disabled={busy} onChange={event => { controller.close(); setNames(event.target.value); }}/></label>
      <p className="field-help">Leave empty for all recorded names. Up to 64 names, each at most 64 characters. Filters affect this display only.</p>
      <label className="filter-checkbox"><input type="checkbox" checked={errorsOnly} disabled={busy} onChange={event => { controller.close(); setErrorsOnly(event.target.checked); }}/> Errors only</label>
    </>}
    {state.phase === 'loading' && <p role="status">Checking access and preparing the saved syscall view…</p>}
    {state.phase === 'pending' && <><p role="status">The saved syscall view is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check result</Button></>}
    {state.phase === 'result' && <>
      {coverage && <>
        <p className="notice">These counts describe only the saved file. Acquisition coverage, dropped events and truncation are unknown.</p>
        <dl className="facts"><dt>Recorded events</dt><dd>{coverage.record_count?.toLocaleString() ?? 'Unavailable'}</dd><dt>Unmatched events</dt><dd>{coverage.unmatched_events.toLocaleString()}</dd><dt>Unfinished events</dt><dd>{coverage.unfinished_events?.toLocaleString() ?? 'Unavailable'}</dd><dt>Unknown outcomes</dt><dd>{coverage.unknown_events?.toLocaleString() ?? 'Unavailable'}</dd></dl>
      </>}
      {state.syscallSummary && <>
        {state.syscallSummary.rows.length === 0 && <p>No events are recorded in this file.</p>}
        <table className="profile-summary" aria-label="Syscall counts"><thead><tr><th>Syscall</th><th>Count</th><th>Errors</th><th>Paired calls</th><th>Total paired duration (ns)</th></tr></thead><tbody>{state.syscallSummary.rows.map(row => <tr key={row.syscall}><td>{row.syscall}</td><td>{row.count.toLocaleString()}</td><td>{row.errors.toLocaleString()}</td><td>{row.paired_count.toLocaleString()}</td><td>{row.total_duration_ns.toLocaleString()}</td></tr>)}</tbody></table>
      </>}
      {state.syscallEvents && <>
        {state.syscallEvents.events.length === 0 && <p>No recorded events match these display filters.</p>}
        <table className="profile-summary" aria-label="Recorded syscall events"><thead><tr><th>Timestamp and syscall</th><th>Outcome and duration</th><th>Source identity</th></tr></thead><tbody>{state.syscallEvents.events.map((event, index) => <tr key={index}><td><time dateTime={event.timestamp}>{event.timestamp}</time><br/>{event.syscall} · {event.abi}</td><td>{event.outcome}{event.errno ? ` · ${event.errno}` : ''}<br/>{event.duration_ns === undefined ? 'Duration unavailable' : `${event.duration_ns.toLocaleString()} ns`}</td><td>Process: {event.identity.process_ref}<br/>Thread: {event.identity.thread_ref}<br/>Pod: {event.identity.pod_uid}</td></tr>)}</tbody></table>
      </>}
      {state.warnings?.map((warning, index) => <p className="field-help" key={index}>{warning}</p>)}
      {state.nextCursor && <Button className="button secondary" onPress={() => void controller.nextSyscallPage()}>Next page</Button>}
    </>}
    {state.phase === 'expired' && <p role="status">This view has expired. Inspect again to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved syscall view is unavailable or your access could not be checked.</p>}
    {!['loading', 'pending'].includes(state.phase) && <Button className="button secondary" isDisabled={!attached} onPress={() => void inspect()}>{state.phase === 'idle' ? 'Inspect saved syscalls' : 'Inspect again'}</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close view</Button>}
  </section>;
}
