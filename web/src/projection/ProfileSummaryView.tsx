import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ContextProjection } from './projection';

type ProfileSummaryProps = { controller: ContextProjection; session: Session; scope: AbortSignal; caseID: string; artifactID: string; version: string; requestedType?: string };

export function ProfileSummaryView(props: ProfileSummaryProps) {
  // An edit belongs to this immutable source. Metadata rerenders preserve it;
  // selecting another source starts with that source's editable suggestion.
  return <SourceProfileSummary key={JSON.stringify([props.caseID, props.artifactID, props.version])} {...props}/>;
}

function SourceProfileSummary({ controller, session, scope, caseID, artifactID, version, requestedType }: ProfileSummaryProps) {
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, caseID, artifactID, version);
  const state = attached ? snapshot : { phase: 'idle' as const };
  const [sampleType, setSampleType] = useState(() => requestedType === 'heap' ? 'inuse_space' : 'cpu');
  const [topN, setTopN] = useState('20');
  useEffect(() => controller.attach(session, scope, caseID, artifactID, version), [controller, session, scope, caseID, artifactID, version]);
  const busy = !attached || state.phase === 'loading' || state.phase === 'pending';
  const summary = state.summary;
  return <section aria-label="Saved profile summary" aria-busy={state.phase === 'loading'}>
    <h3>Saved profile summary</h3>
    <p>Inspect aggregate function costs from the saved pprof profile. Labels, paths and raw samples are excluded. Function names may contain user data.</p>
    <label>Sample type <input value={sampleType} maxLength={64} disabled={busy} onChange={event => setSampleType(event.target.value)}/></label>
    <label>Number of functions <input type="number" min={1} max={100} value={topN} disabled={busy} onChange={event => setTopN(event.target.value)}/></label>
    {state.phase === 'loading' && <p role="status">Checking access and preparing the saved summary…</p>}
    {state.phase === 'pending' && <><p role="status">The saved summary is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check result</Button></>}
    {state.phase === 'result' && summary && <>
      <dl className="facts"><dt>Sample type</dt><dd>{summary.sample_type}</dd><dt>Unit</dt><dd>{summary.unit}</dd><dt>Total</dt><dd>{summary.total.toLocaleString()}</dd><dt>Duration</dt><dd>{summary.duration_seconds === null ? 'Unavailable' : `${summary.duration_seconds} seconds`}</dd><dt>Symbols</dt><dd>{summary.symbol_status}</dd></dl>
      <table className="profile-summary" aria-label="Profile function costs"><thead><tr><th>Function</th><th>Flat</th><th>Cumulative</th><th>Flat percentage</th></tr></thead><tbody>{summary.top.map((row, index) => <tr key={index}><td>{row.function ?? 'Unresolved'}</td><td>{row.flat.toLocaleString()}</td><td>{row.cumulative.toLocaleString()}</td><td>{row.fraction === null ? 'Unavailable' : `${(row.fraction * 100).toFixed(2)}%`}</td></tr>)}</tbody></table>
      {state.warnings?.map((warning, index) => <p key={index} className="field-help">{warning}</p>)}
    </>}
    {state.phase === 'expired' && <p role="status">This view has expired. Inspect again to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved summary is unavailable or your access could not be checked.</p>}
    {!['loading', 'pending'].includes(state.phase) && <Button className="button secondary" isDisabled={!attached || !sampleType || !Number.isInteger(Number(topN)) || Number(topN) < 1 || Number(topN) > 100} onPress={() => void controller.inspect({ sample_type: sampleType, top_n: Number(topN) })}>{state.phase === 'idle' ? 'Inspect saved profile' : 'Inspect again'}</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close view</Button>}
  </section>;
}
