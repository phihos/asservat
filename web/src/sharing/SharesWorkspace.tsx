import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { ShareRow } from './http';
import { TeamsEditor } from './SharePanel';
import type { Shares } from './shares';

const date = (value: string) => new Date(value).toLocaleString();
const phases: Record<string, string> = {
  Active: 'Active', Expired: 'Expired', Revoked: 'Revoked',
  Suspended: 'Suspended: no managing team holds the evidence-owner role for this workload any longer',
};
const subject = (s: { kind: string; id: string }) => (s.kind === 'Group' ? 'team ' : '') + s.id;

// ADR-238: hand management to owner teams the user belongs to.
function Transfer({ row, controller, busy, administrator }: { row: ShareRow; controller: Shares; busy: boolean; administrator?: boolean }) {
  const [teams, setTeams] = useState<string[]>([]);
  return <details className="retention-edit">
    <summary>{administrator ? 'Assign managing teams' : 'Transfer management'}</summary>
    <p className="field-help">The named owner teams replace the current managers. Recipients, creator and end date stay the same, and managing grants no access to the evidence. {administrator
      ? 'Name owner teams that currently hold evidence-owner for this artifact.'
      : 'You can name owner teams you belong to; assigning other owner teams requires an installation administrator.'}</p>
    <TeamsEditor teams={teams} onChange={setTeams} label="New managing team ID"/>
    <Button className="button secondary" isDisabled={busy || teams.length === 0} onPress={() => void controller.transfer(row, teams).then(() => setTeams([]))}>Transfer</Button>
  </details>;
}

// ADR-238: installation administrators see every share management-only
// (IDs, phase, expiry, creator, managers; never recipients or evidence),
// revoke it, or assign current owner teams (also to recover a Suspended
// share). The server refuses everyone else.
function Administration({ controller, rows, cursor, message, busy }: { controller: Shares; rows?: ShareRow[]; cursor?: string; message?: string; busy: boolean }) {
  return <details className="retention-edit" aria-busy={busy}>
    <summary>All shares (installation administrators)</summary>
    <p className="field-help">For installation administrators only. Revoking stops every recipient's access at their next read; assigning managing teams can recover a suspended share. Neither gives you access to the evidence.</p>
    <Button className="button secondary" isDisabled={busy} onPress={() => void controller.loadAdministration()}>Load all shares</Button>
    {message && <p className="notice">{message}</p>}
    {rows?.length === 0 && <p>There are no shares.</p>}
    {!!rows?.length && <ul className="progress-actions" aria-label="All shares">{rows.map(row => <li key={row.share_id}>
      <span><span className="identifier">{row.share_id}</span> · case <span className="identifier">{row.case_id}</span> · {phases[row.phase] ?? row.phase} · until {date(row.expires_at)}
        {row.created_by && <> · Created by {row.created_by.id}</>}
        {!!row.managed_by?.length && <> · Managed by {row.managed_by.map(subject).join(', ')}</>}
      </span>
      {(row.phase === 'Active' || row.phase === 'Suspended') && <Button className="button secondary" isDisabled={busy} onPress={() => void controller.revoke(row)}>Revoke {row.share_id}</Button>}
      {(row.phase === 'Active' || row.phase === 'Suspended') && <Transfer row={row} controller={controller} busy={busy} administrator/>}
    </li>)}</ul>}
    {cursor && <Button className="button secondary" isDisabled={busy} onPress={() => void controller.loadAdministration(true)}>More shares</Button>}
  </details>;
}

// Concrete evidence shares (ADR-232): the ones you created or manage and the
// ones you can read now. Listing, revocation and transfer are the shared
// browser/MCP operations.
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
      <p>Evidence shared with you, and the shares you created or manage. Share an artifact from its case page. <a href="/captures/new">Collect evidence</a>.</p>
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
      <h2 id="shared-by-me">Shared by me or my teams</h2>
      {state.ownedMessage && <p className="notice">{state.ownedMessage}</p>}
      {state.owned?.length === 0 && <p>You have not shared evidence.</p>}
      {!!state.owned?.length && <ul className="progress-actions">{state.owned.map(row => <li key={row.share_id}>
        <span><a href={'/cases/' + row.case_id}>Case</a> · {phases[row.phase] ?? row.phase} · until {date(row.expires_at)}
          {row.created_by && <> · Created by {row.created_by.id}</>}
          {!!row.managed_by?.length && <> · Managed by {row.managed_by.map(subject).join(', ')}</>}
        </span>
        {row.phase === 'Active' && <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.revoke(row)}>Revoke</Button>}
        {row.phase === 'Active' && <Transfer row={row} controller={controller} busy={state.busy}/>}
      </li>)}</ul>}
    </section>
    <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.load()}>Refresh shares</Button>
    <Administration controller={controller} rows={state.administered} cursor={state.administeredCursor} message={state.administeredMessage} busy={state.busy}/>
  </div>;
}
