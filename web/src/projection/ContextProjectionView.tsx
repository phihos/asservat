import { useEffect, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ContextProjection } from './projection';

// Installed composition must explicitly supply this view after query support is
// qualified. It is not registered in the existing evidence page by default.
export function ContextProjectionView({ controller, session, scope, caseID, artifactID }: { controller: ContextProjection; session: Session; scope: AbortSignal; caseID: string; artifactID: string }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => controller.attach(session, scope, caseID, artifactID), [controller, session, scope, caseID, artifactID]);
  return <section aria-label="Saved pod status" aria-busy={state.phase === 'loading'}>
    <h3>Saved pod status</h3>
    {state.phase === 'loading' && <p role="status">Checking access and preparing the saved status…</p>}
    {state.phase === 'pending' && <><p role="status">The saved status is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check result</Button></>}
    {state.phase === 'result' && <pre aria-label="Approved pod status">{state.excerpt!.lines.join('\n')}</pre>}
    {state.phase === 'expired' && <p role="status">This view has expired. Inspect again to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The saved status is unavailable or your access could not be checked.</p>}
    {!['loading', 'pending'].includes(state.phase) && <Button className="button secondary" onPress={() => void controller.inspect()}>{state.phase === 'idle' ? 'Inspect saved status' : 'Inspect again'}</Button>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close view</Button>}
  </section>;
}
