import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { fleetClient, FleetFailure, validBootstrapInput, type BootstrapInput, type BootstrapReceipt, type FleetClient } from './http';

type Attempt = { input: BootstrapInput; key: string };
const empty: BootstrapInput = { displayName: '', region: '', deliveryProfile: '' };
const utc = (value: string) => new Date(value).toISOString();
export function FleetWorkspace({ session, scope, client = fleetClient, newID = () => crypto.randomUUID() }: {
  session: Session; scope: AbortSignal; client?: FleetClient; newID?: () => string;
}) {
  const heading = useRef<HTMLHeadingElement>(null), busyRef = useRef(false);
  const owner = useRef<{ scope: AbortSignal; child: AbortController } | undefined>(undefined);
  const [input, setInput] = useState(empty), [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Attempt>(), [result, setResult] = useState<BootstrapReceipt>(), [message, setMessage] = useState<string>();
  useLayoutEffect(() => {
    const mine = { scope, child: new AbortController() }; owner.current = mine;
    const reset = () => { busyRef.current = false; setBusy(false); setInput(empty); setPending(undefined); setResult(undefined); setMessage(undefined); };
    const clear = () => { mine.child.abort(); reset(); };
    reset();
    heading.current?.focus();
    if (scope.aborted) clear(); else scope.addEventListener('abort', clear, { once: true });
    return () => { scope.removeEventListener('abort', clear); mine.child.abort(); if (owner.current === mine) owner.current = undefined; };
  }, [scope]);
  const issue = async (attempt: Attempt) => {
    const mine = owner.current;
    if (!mine || mine.scope !== scope || mine.child.signal.aborted || busyRef.current) return;
    busyRef.current = true; setBusy(true); setPending(attempt); setMessage(undefined); setResult(undefined);
    const current = () => owner.current === mine && !mine.child.signal.aborted;
    try {
      const value = await client.issue(attempt.input, attempt.key, session.csrf_token, mine.child.signal);
      if (current()) { setResult(value); setPending(undefined); }
    } catch (error) {
      if (current()) {
        if (error instanceof FleetFailure && [400, 401, 403].includes(error.status)) {
          setPending(undefined);
          setMessage(error.status === 400 ? 'The request was refused. Check the cluster details and configured delivery profile.' : 'Current fleet operator access is required.');
        } else setMessage(error instanceof FleetFailure && error.status === 429 ? 'Issuance is busy or its capacity ceiling was reached. Retry this same request.' : 'Issuance could not be confirmed. Retry this same request to resolve the original submission.');
      }
    } finally { if (current()) { busyRef.current = false; setBusy(false); } }
  };
  const locked = busy || !!pending || !!result;
  return <>
    <h1 ref={heading} tabIndex={-1}>Enroll a cluster</h1>
    <p>Issue a single-use bootstrap slot for a cluster. Retrieve the bootstrap record through your configured operator channel and enroll before the slot expires.</p>
    <form className="review-section" onSubmit={event => { event.preventDefault(); if (!locked && validBootstrapInput(input)) void issue({ input: { ...input }, key: newID() }); }}>
      {([['displayName', 'Cluster display name', 128], ['region', 'Region', 64], ['deliveryProfile', 'Delivery profile', 64]] as const).map(([field, label, length]) => <label key={field}>{label}<input value={input[field]} maxLength={length * 2} disabled={locked} required onChange={event => { setInput({ ...input, [field]: event.target.value }); setMessage(undefined); }}/></label>)}
      <Button type="submit" className="button" isDisabled={locked || !validBootstrapInput(input)}>Issue bootstrap slot</Button>
    </form>
    {busy && <p role="status">Issuing bootstrap slot…</p>}
    {message && <p role="alert">{message}</p>}
    {pending && !busy && <Button className="button" onPress={() => void issue(pending)}>Retry same issuance</Button>}
    {result && <section className="review-section" aria-labelledby="fleet-receipt"><h2 id="fleet-receipt">Bootstrap slot issued</h2>
      <p>{Date.now() >= Date.parse(result.notAfter) ? 'This original slot has expired.' : 'Use this slot before its original expiry. Issuance does not confirm cluster enrollment.'}</p>
      <dl>{Object.entries({ 'Bootstrap ID': result.bootstrapID, 'Cluster ID': result.clusterID, 'Peer ID': result.peerID, 'Issuer epoch': result.issuerEpoch, 'Delivery profile': result.deliveryProfile, 'Credential version': result.credentialVersion, 'Valid from (UTC)': utc(result.notBefore), 'Expires at (UTC)': utc(result.notAfter) }).map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="identifier">{value}</dd></div>)}</dl>
      <Button className="button secondary" onPress={() => { setResult(undefined); setMessage(undefined); }}>Create another slot</Button>
    </section>}
  </>;
}
