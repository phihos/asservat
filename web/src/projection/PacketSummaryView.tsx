import { useEffect, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ContextProjection } from './projection';

type Props = { controller: ContextProjection; session: Session; scope: AbortSignal; caseID: string; artifactID: string; version: string };

export function PacketSummaryView(props: Props) {
  return <SavedPacketSummary key={JSON.stringify([props.caseID, props.artifactID, props.version])} {...props}/>;
}
function SavedPacketSummary({ controller, session, scope, caseID, artifactID, version }: Props) {
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, caseID, artifactID, version);
  const state = attached ? snapshot : { phase: 'idle' as const };
  useEffect(() => controller.attach(session, scope, caseID, artifactID, version), [controller, session, scope, caseID, artifactID, version]);
  const summary = state.packetSummary;
  return <section aria-label="Saved packet summary" aria-busy={state.phase === 'loading'}>
    <h3>Saved packet summary</h3>
    <p>Inspect the saved network headers. Numeric endpoints may contain user data. This view excludes payload, names and comments.</p>
    {state.phase === 'loading' && <p role="status">Checking access and preparing the saved packet summary…</p>}
    {state.phase === 'pending' && <><p role="status">The saved packet summary is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check result</Button></>}
    {state.phase === 'result' && summary && <>
      <dl className="facts"><dt>Saved packet records</dt><dd>{summary.packets.toLocaleString()}</dd><dt>{summary.drop_reporting === 'snapshotOutputLimit' ? 'Snapshot output-limit exclusions' : 'Reported capture exclusions'}</dt><dd>{summary.drops === null ? 'Unknown' : summary.drops.toLocaleString()}</dd><dt>Directional conversations</dt><dd>{summary.conversations_total.toLocaleString()}</dd></dl>
      <p>Counts describe saved records, not unique network datagrams. Acquisition coverage is unknown; reported exclusions are not measured network loss.</p>
      {summary.drop_reporting === 'captureExclusions' && <p>Capture exclusions can include filtering, unsupported packets, output limits and source-reported loss.</p>}
      {summary.drop_reporting === 'snapshotOutputLimit' && <p>This counter reports records excluded by the snapshot output limit; it does not measure all capture loss.</p>}
      {summary.drop_reporting === 'unavailable' && <p>The saved file does not provide a complete reported exclusion counter.</p>}
      {summary.conversations_truncated && <p>Showing the top {summary.conversations.length.toLocaleString()} of {summary.conversations_total.toLocaleString()} directional conversations from the complete saved-file scan.</p>}
      <table className="profile-summary" aria-label="Saved packet conversations"><thead><tr><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Protocol</th><th scope="col">Saved records</th></tr></thead><tbody>{summary.conversations.map((row, index) => <tr key={index}><td>{row.source}</td><td>{row.destination}</td><td>{row.protocol}</td><td>{row.packets.toLocaleString()}</td></tr>)}</tbody></table>
      {summary.packets === 0 && <p>No packet records were retained in this saved file.</p>}
      {state.warnings?.map((warning, index) => <p key={index} className="field-help">{warning}</p>)}
    </>}
    {state.phase === 'expired' && <p role="status">This view has expired. Inspect again to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved packet summary is unavailable or your access could not be checked.</p>}
    {!['loading', 'pending'].includes(state.phase) && <Button className="button secondary" isDisabled={!attached} onPress={() => void controller.inspect()}>{state.phase === 'idle' ? 'Inspect saved packets' : 'Inspect again'}</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close view</Button>}
  </section>;
}
