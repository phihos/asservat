import { useEffect, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { TargetDiscovery } from './target-discovery';

export function TargetDiscoveryView({ controller, session, scope, captureID }: { controller: TargetDiscovery; session: Session; scope: AbortSignal; captureID: string }) {
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, captureID);
  const state = attached ? snapshot : { phase: 'idle' as const };
  useEffect(() => controller.attach(session, scope, captureID), [controller, session, scope, captureID]);
  return <section aria-label="Saved process snapshot" aria-busy={state.phase === 'loading'}>
    <h3>Saved process snapshot</h3>
    <p>Read the recorded processes from this capture. This does not inspect the running workload again.</p>
    {state.phase === 'loading' && <p role="status">Checking access and preparing the saved snapshot…</p>}
    {state.phase === 'pending' && <><p role="status">The saved snapshot is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check result</Button></>}
    {state.page && <>
      <p>Snapshot interval: <time dateTime={state.page.summary.started_at}>{state.page.summary.started_at}</time> to <time dateTime={state.page.summary.ended_at}>{state.page.summary.ended_at}</time>.</p>
      <p>{state.page.summary.coverage.covered_pods} of {state.page.summary.coverage.requested_pods} selected Pods covered. {state.page.summary.coverage.process_inventory_complete ? 'The recorded process inventory is complete.' : 'The recorded process inventory is incomplete.'} This one-Pod observation does not describe every replica.</p>
      <p>Runtime and build identities are unknown. Network traffic and socket ownership are not included in this view.</p>
      {(state.page.processes ?? []).length === 0 && <p>No processes were observed in this saved snapshot.</p>}
      <table aria-label="Recorded processes"><thead><tr><th>Process</th><th>Executable</th><th>Resident memory</th><th>Parent reference</th></tr></thead><tbody>{state.page.processes?.map(row => <tr key={row.process_ref}><td>{row.display_pid}<br/><span className="identifier">{row.process_ref}</span></td><td>{row.executable_path ?? 'Executable path unavailable'}</td><td>{row.rss_bytes === undefined ? 'Unavailable' : `${row.rss_bytes.toLocaleString()} bytes`}</td><td>{row.parent_ref ?? 'Unavailable'}</td></tr>)}</tbody></table>
      {state.page.gaps.length > 0 && <p className="notice">Coverage notes: {state.page.gaps.join(', ')}</p>}
      {state.warnings?.map((warning, index) => <p className="field-help" key={index}>{warning}</p>)}
      {state.nextCursor && <Button className="button secondary" onPress={() => void controller.nextPage()}>Next page</Button>}
    </>}
    {state.phase === 'uncertain' && <p role="alert">The read outcome is unknown. Reading again explicitly may consume another query allowance; it does not collect another snapshot.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved process view is unavailable or current access could not be checked. You can use the native download in the evidence page.</p>}
    {state.phase === 'expired' && <p role="status">This view has expired. Read the saved snapshot again for a fresh view.</p>}
    {!['loading', 'pending'].includes(state.phase) && <Button className="button secondary" isDisabled={!attached} onPress={() => void controller.inspect()}>{state.phase === 'idle' ? 'Inspect saved processes' : 'Read saved snapshot again'}</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close view</Button>}
  </section>;
}
