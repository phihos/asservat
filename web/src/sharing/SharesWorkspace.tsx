import { useEffect, useRef, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Shares } from './shares';

const date = (value: string) => new Date(value).toLocaleString();
const phases: Record<string, string> = {
  Active: 'Active', Expired: 'Expired', Revoked: 'Revoked',
  Suspended: 'Suspended: you no longer hold the evidence-owner role for this workload',
};

// Concrete evidence shares (ADR-232): the ones you created and the ones you
// can read now. Listing and revocation are the shared browser/MCP operations.
export function SharesWorkspace({ session, scope, controller }: { session: Session; scope: AbortSignal; controller: Shares }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    const detach = controller.attach(session, scope);
    void controller.load();
    return detach;
  }, [controller, session, scope]);
  useEffect(() => { heading.current?.focus(); }, []);
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Shared evidence</h1>
      <p>Evidence shared with you, and the shares you created. Share an artifact from its case page. <a href="/captures/new">Collect evidence</a>.</p>
    </div>
    {state.message && <p role="alert" className="notice">{state.message}</p>}
    <section className="review-section" aria-labelledby="shared-with-me" aria-busy={state.busy}>
      <h2 id="shared-with-me">Shared with me</h2>
      {state.receivedMessage && <p className="notice">{state.receivedMessage}</p>}
      {state.received?.length === 0 && <p>Nothing is shared with you right now.</p>}
      {!!state.received?.length && <ul className="progress-actions">{state.received.map(row => <li key={row.share_id}>
        <a href={'/cases/' + row.case_id}>Open shared case</a><span>Until {date(row.expires_at)}</span>
      </li>)}</ul>}
    </section>
    <section className="review-section" aria-labelledby="shared-by-me" aria-busy={state.busy}>
      <h2 id="shared-by-me">Shared by me</h2>
      {state.ownedMessage && <p className="notice">{state.ownedMessage}</p>}
      {state.owned?.length === 0 && <p>You have not shared evidence.</p>}
      {!!state.owned?.length && <ul className="progress-actions">{state.owned.map(row => <li key={row.share_id}>
        <span><a href={'/cases/' + row.case_id}>Case</a> · {phases[row.phase] ?? row.phase} · until {date(row.expires_at)}</span>
        {row.phase === 'Active' && <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.revoke(row)}>Revoke</Button>}
      </li>)}</ul>}
    </section>
    <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.load()}>Refresh shares</Button>
  </div>;
}
