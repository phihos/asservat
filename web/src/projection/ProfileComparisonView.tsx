import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ContextProjection, ProfileSource, ComparisonSelection } from './projection';

export type ProfileBaseline = { caseID?: string; artifactID: string; version: string; label: string };

export function ProfileComparisonView({ controller, session, scope, caseID, artifactID, version, baselines }: { controller: ContextProjection; session: Session; scope: AbortSignal; caseID: string; artifactID: string; version: string; baselines: ProfileBaseline[] }) {
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [baselineID, setBaselineID] = useState('');
  const selected = baselines.find(source => source.artifactID === baselineID);
  const incident: ProfileSource = { caseID, artifactID, version };
  const baseline: ProfileSource | undefined = selected && { caseID: selected.caseID ?? caseID, artifactID: selected.artifactID, version: selected.version };
  const attached = !!baseline && controller.isComparisonAttachedTo(session, scope, incident, baseline);
  const state = attached ? snapshot : { phase: 'idle' as const };
  const [sampleType, setSampleType] = useState('cpu');
  const [normalization, setNormalization] = useState<ComparisonSelection['normalization']>('perSecond');
  const [topN, setTopN] = useState('20');
  useEffect(() => {
    if (!selected) { controller.close(); return; }
    return controller.attachComparison(session, scope, { caseID, artifactID, version }, { caseID: selected.caseID ?? caseID, artifactID: selected.artifactID, version: selected.version });
  }, [controller, session, scope, caseID, artifactID, version, selected?.caseID, selected?.artifactID, selected?.version]);
  const busy = state.phase === 'loading' || state.phase === 'pending';
  const comparison = state.comparison;
  return <section aria-label="Saved profile comparison" aria-busy={state.phase === 'loading'}>
    <h3>Compare saved profiles</h3>
    <p>Choose a baseline from the visible saved profiles. Compare cumulative function costs for one sample type; collection and sampling differences can affect the result.</p>
    <label>Baseline profile <select value={selected?.artifactID ?? ''} onChange={event => { controller.close(); setBaselineID(event.target.value); }}>
      <option value="">Choose a baseline</option>
      {baselines.map(source => <option key={source.artifactID} value={source.artifactID}>{source.label}{source.artifactID === artifactID ? ' (this profile)' : ''}</option>)}
    </select></label>
    <label>Comparison sample type <input value={sampleType} maxLength={64} disabled={busy} onChange={event => setSampleType(event.target.value)}/></label>
    <label>Normalization <select value={normalization} disabled={busy} onChange={event => setNormalization(event.target.value as ComparisonSelection['normalization'])}><option value="perSecond">Per second</option><option value="none">Raw totals</option></select></label>
    <label>Number of comparison functions <input type="number" min={1} max={100} value={topN} disabled={busy} onChange={event => setTopN(event.target.value)}/></label>
    {state.phase === 'loading' && <p role="status">Checking both profiles and preparing the comparison…</p>}
    {state.phase === 'pending' && <><p role="status">The saved comparison is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check comparison result</Button></>}
    {state.phase === 'result' && comparison && <>
      <p>{comparison.sample_type} · {comparison.unit}{comparison.normalization === 'perSecond' ? ' per second' : ' · raw totals'} · cumulative function costs</p>
      <table className="profile-summary" aria-label="Profile acquisition details"><thead><tr><th>Detail</th><th>Baseline</th><th>Incident</th></tr></thead><tbody>
        <tr><th>Profile type</th><td>{comparison.baseline.profile_type}</td><td>{comparison.incident.profile_type}</td></tr>
        <tr><th>Collection mode</th><td>{comparison.baseline.mode}</td><td>{comparison.incident.mode}</td></tr>
        <tr><th>Forced garbage collection</th><td>{comparison.baseline.force_gc ? 'Yes' : 'No'}</td><td>{comparison.incident.force_gc ? 'Yes' : 'No'}</td></tr>
        <tr><th>Duration</th><td>{comparison.baseline.duration_seconds === null ? 'Unavailable' : `${comparison.baseline.duration_seconds} seconds`}</td><td>{comparison.incident.duration_seconds === null ? 'Unavailable' : `${comparison.incident.duration_seconds} seconds`}</td></tr>
        <tr><th>Sampling period</th><td>{comparison.baseline.period ? `${comparison.baseline.period.value} ${comparison.baseline.period.unit} (${comparison.baseline.period.type})` : 'Unavailable'}</td><td>{comparison.incident.period ? `${comparison.incident.period.value} ${comparison.incident.period.unit} (${comparison.incident.period.type})` : 'Unavailable'}</td></tr>
        <tr><th>Native sample total</th><td>{comparison.baseline.total.toLocaleString()}</td><td>{comparison.incident.total.toLocaleString()}</td></tr>
        <tr><th>Symbols</th><td>{comparison.baseline.symbol_status}</td><td>{comparison.incident.symbol_status}</td></tr>
      </tbody></table>
      <p>Build: {comparison.build_status}. Sampling: {comparison.sampling_status}. Collection settings: {comparison.acquisition_status}.</p>
      <table className="profile-summary" aria-label="Profile comparison function costs"><thead><tr><th>Function</th><th>Baseline</th><th>Incident</th><th>Change</th></tr></thead><tbody>{comparison.rows.map((row, index) => <tr key={index}><td>{row.function ?? 'Unresolved'}</td><td>{row.baseline.toLocaleString()}</td><td>{row.incident.toLocaleString()}</td><td>{row.delta.toLocaleString()}</td></tr>)}</tbody></table>
      {comparison.limitations.map((limitation, index) => <p key={index} className="field-help">{limitation}</p>)}
      {state.warnings?.map((warning, index) => <p key={index} className="field-help">{warning}</p>)}
    </>}
    {state.phase === 'incompatible' && <p role="status">These profiles cannot be compared for the selected sample type and normalization.</p>}
    {state.phase === 'expired' && <p role="status">This comparison has expired. Compare again to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved comparison is unavailable. Check access to both profiles or select fewer functions.</p>}
    {!busy && <Button className="button secondary" isDisabled={!attached || !sampleType || !Number.isInteger(Number(topN)) || Number(topN) < 1 || Number(topN) > 100} onPress={() => void controller.inspectComparison({ sample_type: sampleType, normalization, top_n: Number(topN) })}>Compare profiles</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close comparison</Button>}
  </section>;
}
