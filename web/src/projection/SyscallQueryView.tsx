import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { SyscallQuery, type SyscallQuerySource } from './syscall-query';

type Props = { controller: SyscallQuery; session: Session; scope: AbortSignal; caseID: string; artifactID: string; version: string; grantID?: string };
export function SyscallQueryView(props: Props) {
  return <SavedSyscallQuery key={JSON.stringify([props.caseID, props.artifactID, props.version, props.grantID])} {...props}/>;
}
function SavedSyscallQuery({ controller, session, scope, caseID, artifactID, version, grantID }: Props) {
  const source: SyscallQuerySource = { caseID, artifactID, version, ...(grantID ? { grantID } : {}) };
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, source);
  const state = attached ? snapshot : { phase: 'idle' as const };
  useEffect(() => controller.attach(session, scope, source), [controller, session, scope, caseID, artifactID, version, grantID]);
  const [names, setNames] = useState(''); const [errorsOnly, setErrorsOnly] = useState(false); const [limit, setLimit] = useState('100');
  const locked = ['loading', 'pending', 'uncertain'].includes(state.phase);
  const changed = () => controller.close();
  const result = state.result;
  return <section aria-label="Saved syscall argument query" aria-busy={state.phase === 'loading'}>
    <h3>Query saved syscall arguments</h3>
    <p>Read only the arguments already recorded in this saved artifact. No new tracing, user-memory read or pointer dereference occurs. Values may contain user data; query approval does not grant native download access.</p>
    {!grantID && <p role="status">Obtain syscall-query approval for this client before running.</p>}
    <form onSubmit={event => { event.preventDefault(); const selected = names.split(',').map(name => name.trim()).filter(Boolean); void controller.run({ limit: Number(limit), errors_only: errorsOnly, ...(selected.length ? { syscall_names: selected } : {}) }); }}>
      <fieldset disabled={locked}><legend>Recorded syscall selection</legend>
        <label>Syscall names, separated by commas<input value={names} maxLength={4159} onChange={event => { changed(); setNames(event.target.value); }}/></label>
        <p className="field-help">Leave empty for all recorded names. Up to 64 names of at most 64 characters. Argument contents cannot be used as filters.</p>
        <label><input type="checkbox" checked={errorsOnly} onChange={event => { changed(); setErrorsOnly(event.target.checked); }}/>Errors only</label>
        <label>Events per page<input type="number" min="1" max="100" required value={limit} onChange={event => { changed(); setLimit(event.target.value); }}/></label>
      </fieldset>
      <Button type="submit" className="button secondary" isDisabled={!attached || !grantID || locked}>Run syscall query</Button>
    </form>
    {state.phase === 'loading' && <p role="status">Checking access and reading the saved syscall arguments…</p>}
    {state.phase === 'pending' && <><p role="status">The original syscall query is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check syscall query</Button></>}
    {state.phase === 'uncertain' && <><p role="alert">The response was not received. The query may already be charged. Retry its same frozen request to recover the original query.</p><Button className="button secondary" onPress={() => void controller.retryBegin()}>Retry same syscall query</Button></>}
    {state.phase === 'approval-required' && <p role="alert">Current syscall-query approval is required. Use the artifact's raw-access review controls.</p>}
    {state.phase === 'unavailable' && <p role="alert">The syscall query is unavailable. Check your current access, selected names, approval and remaining allowance.</p>}
    {state.phase === 'expired' && <p role="status">This syscall query view has expired. Run explicitly to request a fresh view.</p>}
    {state.phase === 'result' && result && <>
      <p>These events describe the saved file. Acquisition coverage and dropped events remain unknown; recorded faults and truncation are not repaired by this query.</p>
      <dl className="facts"><dt>Recorded events</dt><dd>{result.coverage.record_count?.toLocaleString() ?? 'Unavailable'}</dd><dt>Unmatched events</dt><dd>{result.coverage.unmatched_events.toLocaleString()}</dd><dt>Unfinished events</dt><dd>{result.coverage.unfinished_events?.toLocaleString() ?? 'Unavailable'}</dd></dl>
      {result.events.length ? <table className="profile-summary" aria-label="Saved syscall argument events"><thead><tr><th>Recorded event</th><th>Source identity</th><th>Recorded arguments</th></tr></thead><tbody>{result.events.map((event, index) => <tr key={index}>
        <td><time dateTime={event.timestamp}>{event.timestamp}</time><br/>{event.syscall} · {event.abi}<br/>{event.outcome}{event.errno ? ` · ${event.errno}` : ''}<br/>{event.duration_ns === undefined ? 'Duration unavailable' : `${event.duration_ns.toLocaleString()} ns`}</td>
        <td>Process: {event.identity.process_ref}<br/>Thread: {event.identity.thread_ref}<br/>Pod: {event.identity.pod_uid}</td>
        <td>{event.arguments.length ? <dl>{event.arguments.map(argument => <div key={argument.name}><dt>{argument.name}</dt><dd><code>{argument.value}</code>{argument.value === 'unavailable:fault' ? ' — recorded read failed' : argument.value === 'base64:' ? ' — recorded empty bytes' : ''}{argument.truncated ? ' — truncated at acquisition' : ''}</dd></div>)}</dl> : 'No arguments recorded for this event'}</td>
      </tr>)}</tbody></table> : <p>No recorded events match this selection.</p>}
      {state.nextCursor && <><p>More recorded events match. The next page starts a separate query and may consume another bounded allowance.</p><Button className="button secondary" onPress={() => void controller.nextPage()}>Next syscall page</Button></>}
      {state.warnings?.map((warning, index) => <p key={index}>{warning}</p>)}
    </>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close syscall query</Button>}
  </section>;
}
