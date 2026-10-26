import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { maxHours, maxRecipients, Shares, type Recipient } from './shares';

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
// "Share results with…" section (ADR-235): stable User/Group IDs of the
// signed-in user's issuer, at most eight. No <form>, so it can sit inside
// another form; Enter in the ID field adds the recipient.
export function RecipientsEditor({ recipients, onChange }: { recipients: Recipient[]; onChange: (next: Recipient[]) => void }) {
  const [kind, setKind] = useState<Recipient['kind']>('User');
  const [id, setID] = useState('');
  const add = () => {
    const value = id.trim();
    if (!value || value.length > 256 || recipients.length >= maxRecipients || recipients.some(r => r.kind === kind && r.id === value)) return;
    onChange([...recipients, { kind, id: value }]); setID('');
  };
  return <>
    <div className="form-row">
      <label>Recipient type<select value={kind} onChange={event => setKind(event.target.value as Recipient['kind'])}><option value="User">User</option><option value="Group">Group</option></select></label>
      <label>Recipient ID<input value={id} maxLength={256} autoComplete="off" spellCheck={false} onChange={event => setID(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); add(); } }}/></label>
    </div>
    <Button className="button secondary" isDisabled={!id.trim() || recipients.length >= maxRecipients} onPress={add}>Add recipient</Button>
    {recipients.length > 0 && <ul className="progress-actions" aria-label="Recipients">{recipients.map(r => <li key={r.kind + '\n' + r.id}>
      <span className="identifier">{r.kind}: {r.id}</span>
      <Button className="button secondary" onPress={() => onChange(recipients.filter(x => x !== r))}>Remove {r.id}</Button>
    </li>)}</ul>}
    <p className="field-help">{recipients.length} of {maxRecipients} recipients.</p>
  </>;
}

// Share one artifact (ADR-232). The preview is the recipient's actual view of
// this artifact; the server decides eligibility, recipients and expiry.
export function SharePanel({ session, scope, caseID, artifact, preview, controller: injected }: { session: Session; scope: AbortSignal; caseID: string; artifact: { artifact_id: string; digest: string; expires_at: string }; preview: ReactNode; controller?: Shares }) {
  const [controller] = useState(() => injected ?? new Shares());
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => controller.attach(session, scope), [controller, session, scope]);
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [hours, setHours] = useState(24);
  const [reason, setReason] = useState('');
  const [open, setOpen] = useState(false);
  const validHours = Number.isInteger(hours) && hours >= 1 && hours <= maxHours;
  const requested = Date.now() + (validHours ? hours : 24) * 3_600_000;
  const ends = Math.min(requested, Date.parse(artifact.expires_at));
  const share = async () => {
    await controller.create(caseID, artifact, recipients, hours, reason.trim());
    if (controller.snapshot().created) { setRecipients([]); setReason(''); }
  };
  const ready = recipients.length > 0 && validHours && reason.trim().length > 0 && !state.busy;
  // The form and preview render only while open, so the page shows one copy
  // of the artifact details and nothing is requested until the user shares.
  return <details className="retention-edit" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Share this artifact</summary>
    {open && <>
    <p>Recipients can read this artifact in this case until the share ends. Use the stable user or group IDs of your identity provider ({session.principal.issuer}), not display names.</p>
    {/* While a request is uncertain the retry must match what the form shows. */}
    <fieldset disabled={state.uncertain}>
    <RecipientsEditor recipients={recipients} onChange={setRecipients}/>
    <div className="form-row">
      <label>Share for (hours)<input type="number" min={1} max={maxHours} step={1} value={Number.isNaN(hours) ? '' : hours} onChange={event => setHours(event.target.valueAsNumber)}/></label>
      <label>Reason<input value={reason} maxLength={512} onChange={event => setReason(event.target.value)}/></label>
    </div>
    </fieldset>
    <p className="field-help">At most seven days. The share never outlasts the artifact's access.</p>
    <section className="review-section" aria-label="What recipients will see">
      <h3>What recipients will see</h3>
      {preview}
      <dl className="facts"><dt>Their access ends</dt><dd>{date(ends)}{ends < requested ? " (the artifact's access ends first)" : ''}</dd>
        <dt>Not included</dt><dd>Other evidence in this case, further sharing, workload access and new collections</dd></dl>
    </section>
    {state.message && <p role="alert" className="notice">{state.message}</p>}
    {state.created && <p role="status">Shared with {state.created.recipients} recipient{state.created.recipients === 1 ? '' : 's'} until {date(Math.min(Date.parse(state.created.expiresAt), Date.parse(artifact.expires_at)))}. Send them the case link.</p>}
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
