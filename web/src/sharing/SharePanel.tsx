import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { Shares, type Recipient } from './shares';

const date = (value: number | string) => new Date(value).toLocaleString();

// The case link is the same for everyone; opening it checks the reader's own
// current rights or share. Copying it shares nothing by itself.
export function CaseLink({ caseID }: { caseID: string }) {
  const link = window.location.origin + '/cases/' + caseID;
  const [copied, setCopied] = useState<string>();
  const copy = async () => {
    try { await navigator.clipboard.writeText(link); setCopied('Link copied.'); } catch { setCopied('Copy the link from the field.'); }
  };
  return <div className="field">
    <label>Case link<input readOnly value={link} onFocus={event => event.target.select()}/></label>
    <div className="actions"><Button className="button secondary" onPress={() => void copy()}>Copy case link</Button></div>
    {copied && <p role="status" className="field-help">{copied}</p>}
  </div>;
}

// Recipient entry shared by the case Share panel and the capture request's
// "Share results with…" section (ADR-235): user and group names of the
// signed-in user's identity provider. No <form>, so it can sit inside
// another form; Enter in the name field adds the recipient.
export function RecipientsEditor({ recipients, onChange }: { recipients: Recipient[]; onChange: (next: Recipient[]) => void }) {
  const [kind, setKind] = useState<Recipient['kind']>('User');
  const [id, setID] = useState('');
  const add = () => {
    const value = id.trim();
    if (!value || recipients.some(r => r.kind === kind && r.id === value)) return;
    onChange([...recipients, { kind, id: value }]); setID('');
  };
  return <>
    <div className="form-row">
      <label>Recipient type<select value={kind} onChange={event => setKind(event.target.value as Recipient['kind'])}><option value="User">User</option><option value="Group">Group</option></select></label>
      <label>Group name or user ID<input value={id} autoComplete="off" spellCheck={false} onChange={event => setID(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); add(); } }}/></label>
    </div>
    <Button className="button secondary" isDisabled={!id.trim()} onPress={add}>Add recipient</Button>
    {recipients.length > 0 && <ul className="progress-actions" aria-label="Recipients">{recipients.map(r => <li key={r.kind + '\n' + r.id}>
      <span className="identifier">{r.kind}: {r.id}</span>
      <Button className="button secondary" onPress={() => onChange(recipients.filter(x => x !== r))}>Remove {r.id}</Button>
    </li>)}</ul>}
  </>;
}

// Owner teams that manage a share (ADR-238): group names of the signed-in
// user's identity provider. The server accepts only teams the
// user belongs to that hold evidence-owner for the artifact.
export function TeamsEditor({ teams, onChange, label }: { teams: string[]; onChange: (next: string[]) => void; label: string }) {
  const [id, setID] = useState('');
  const add = () => {
    const value = id.trim();
    if (!value || teams.includes(value)) return;
    onChange([...teams, value]); setID('');
  };
  return <>
    <label>{label}<input value={id} autoComplete="off" spellCheck={false} onChange={event => setID(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); add(); } }}/></label>
    <Button className="button secondary" isDisabled={!id.trim()} onPress={add}>Add team</Button>
    {teams.length > 0 && <ul className="progress-actions" aria-label={label}>{teams.map(team => <li key={team}>
      <span className="identifier">Group: {team}</span>
      <Button className="button secondary" onPress={() => onChange(teams.filter(x => x !== team))}>Remove {team}</Button>
    </li>)}</ul>}
  </>;
}

// Share one artifact (ADR-232). The preview is the recipient's actual view of
// this artifact; the server decides eligibility, recipients and expiry.
export function SharePanel({ session, scope, caseID, artifact, preview, controller: injected }: { session: Session; scope: AbortSignal; caseID: string; artifact: { artifact_id: string; digest: string; expires_at: string }; preview: ReactNode; controller?: Shares }) {
  const [controller] = useState(() => injected ?? new Shares());
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => controller.attach(session, scope), [controller, session, scope]);
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [hours, setHours] = useState(Number.NaN);
  const [reason, setReason] = useState('');
  const [teams, setTeams] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  // No hours: the share lasts until the artifact's access ends (ADR-335 D7).
  const validHours = Number.isNaN(hours) || Number.isInteger(hours) && hours >= 1;
  const requested = validHours && !Number.isNaN(hours) ? Date.now() + hours * 3_600_000 : Infinity;
  const ends = Math.min(requested, Date.parse(artifact.expires_at));
  const share = async () => {
    await controller.create(caseID, artifact, recipients, Number.isNaN(hours) ? undefined : hours, reason.trim(), teams);
    if (controller.snapshot().created) { setRecipients([]); setReason(''); setTeams([]); }
  };
  const ready = recipients.length > 0 && validHours && !state.busy;
  // The form and preview render only while open, so the page shows one copy
  // of the artifact details and nothing is requested until the user shares.
  return <details className="retention-edit" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Share this artifact</summary>
    {open && <>
    <p>Recipients can read and download this artifact in this case until the share ends. Name groups as in your identity provider ({session.principal.issuer}); name users by their stable subject ID, not a display name or e-mail.</p>
    {/* While a request is uncertain the retry must match what the form shows. */}
    <fieldset disabled={state.uncertain}>
    <RecipientsEditor recipients={recipients} onChange={setRecipients}/>
    <div className="form-row">
      <label>Share for (hours, optional)<input type="number" min={1} step={1} value={Number.isNaN(hours) ? '' : hours} onChange={event => setHours(event.target.valueAsNumber)}/></label>
      <label>Reason (optional)<input value={reason} onChange={event => setReason(event.target.value)}/></label>
    </div>
    <details>
      <summary>Managed by (optional)</summary>
      <p className="field-help">By default every owner team you belong to manages this share: its members can see and revoke it, even after you leave. To narrow that, name some of your owner teams here; naming an owner team you do not belong to requires an installation administrator. Managing grants no access to the evidence.</p>
      <TeamsEditor teams={teams} onChange={setTeams} label="Managing team name"/>
    </details>
    </fieldset>
    <p className="field-help">Without a duration the share lasts until the artifact's access ends; it never outlasts it.</p>
    <section className="review-section" aria-label="What recipients will see">
      <h3>What recipients will see</h3>
      {preview}
      <dl className="facts"><dt>Their access ends</dt><dd>{date(ends)}{ends < requested ? " (the artifact's access ends first)" : ''}</dd>
        <dt>Not included</dt><dd>Other evidence in this case, further sharing, workload access and new collections</dd></dl>
    </section>
    {state.message && <p role="alert" className="notice">{state.message}</p>}
    {state.created && <p role="status">Shared with {state.created.recipients} recipient{state.created.recipients === 1 ? '' : 's'} until {date(Math.min(state.created.expiresAt ? Date.parse(state.created.expiresAt) : Infinity, Date.parse(artifact.expires_at)))}. Send them the case link.</p>}
    <div className="actions">
      <Button className="button" isDisabled={state.uncertain ? state.busy : !ready} onPress={() => void share()}>{state.uncertain ? 'Retry same share request' : 'Share'}</Button>
      {state.uncertain && <Button className="button secondary" isDisabled={state.busy} onPress={controller.discardPending}>Discard and start over</Button>}
    </div>
    {state.uncertain && <p className="field-help">The share may already exist. Retrying sends the identical request and cannot create a second share. After discarding, check Your shares before sharing again.</p>}
    <CaseLink caseID={caseID}/>
    <p><a href="/shares">Your shares</a></p>
    </>}
  </details>;
}
