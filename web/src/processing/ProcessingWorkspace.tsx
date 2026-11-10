import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { processingArtifactIDFromPath } from '../routes';
import { ProcessingDiscovery } from './ProcessingDiscovery';
import type { ProcessingDiscoveryClient } from './discovery-http';
import { processingClient, ProcessingFailure, uuid, type ProcessingClient, type Inventory, type Change, type Receipt, type Rule } from './http';

const when = (value: string) => new Date(value).toLocaleString();
function describe(rule: Rule) {
  const scope = rule.scope;
  return scope.kind === 'artifact' ? `Artifact ${scope.location.artifactID}` : `Workload ${scope.workloadUID} in namespace ${scope.namespaceUID}, cluster ${scope.clusterID}, acquired from ${when(scope.acquiredFrom)} until ${when(scope.acquiredUntil)}`;
}
export function ProcessingWorkspace({ session, scope, client = processingClient, discoveryClient, newID = () => crypto.randomUUID(), artifactID = processingArtifactIDFromPath(window.location.pathname) ?? '' }: {
  session: Session; scope: AbortSignal; client?: ProcessingClient; discoveryClient?: ProcessingDiscoveryClient; newID?: () => string; artifactID?: string;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  const artifactField = useRef<HTMLInputElement>(null);
  const inFlight = useRef(false);
  const activeScope = useRef(scope);
  const current = () => activeScope.current === scope && !scope.aborted;
  const [artifact, setArtifact] = useState(artifactID);
  const [busy, setBusy] = useState(false);
  const [inventory, setInventory] = useState<Inventory>();
  const [message, setMessage] = useState<string>();
  const [receipt, setReceipt] = useState<Receipt>();
  const [pending, setPending] = useState<{ input: Change; key: string }>();
  useLayoutEffect(() => {
    // Clear the previous principal's view before paint. Same-user session/CSRF
    // refreshes retain this scope and therefore retain an uncertain request.
    activeScope.current = scope;
    inFlight.current = false; setBusy(false);
    setInventory(undefined); setReceipt(undefined); setPending(undefined); setMessage(undefined); setArtifact(artifactID);
    heading.current?.focus();
    const clear = () => {
      if (activeScope.current !== scope) return;
      inFlight.current = false; setBusy(false);
      setInventory(undefined); setReceipt(undefined); setPending(undefined); setMessage(undefined); setArtifact('');
    };
    if (scope.aborted) clear();
    else scope.addEventListener('abort', clear, { once: true });
    return () => scope.removeEventListener('abort', clear);
  }, [scope]);
  const load = async (after?: string) => {
    if (inFlight.current || !current()) return;
    inFlight.current = true; setBusy(true); setMessage(undefined); setInventory(undefined);
    try {
      const value = await client.read(scope, after);
      if (current()) setInventory(value);
    } catch (error) {
      if (current()) setMessage(error instanceof ProcessingFailure && [401, 403].includes(error.status)
        ? 'Current privacy operator access is required.' : 'Processing rules are unavailable. Refresh to check current access and state.');
    } finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const change = async (attempt: { input: Change; key: string }) => {
    if (inFlight.current || !current()) return;
    inFlight.current = true; setBusy(true); setReceipt(undefined); setMessage(undefined); setPending(attempt);
    try {
      const value = await client.change(attempt.input, attempt.key, session.csrf_token, scope);
      if (current()) { setReceipt(value); setPending(undefined); setInventory(undefined); }
    } catch (error) {
      if (current()) {
        if (error instanceof ProcessingFailure && [400, 401, 403, 409].includes(error.status)) {
          setPending(undefined); setInventory(undefined);
          setMessage(error.status === 409 ? 'The rule or request changed. Refresh processing rules and review the current revision before another change.' : 'The change was refused. Check current privacy operator access and refresh the rules.');
        } else setMessage('The change may have been accepted. Retry this same change to resolve its original request.');
      }
    } finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const start = (input: Change) => { if (!pending && !busy) void change({ input, key: newID() }); };
  const selectArtifact = (id: string) => {
    if (!current() || busy || pending || !uuid.test(id)) return;
    setArtifact(id);
    setReceipt(undefined);
    artifactField.current?.focus();
  };
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Processing restrictions</h1>
      <p>For configured privacy operators. Restrict processing of saved evidence or explicitly release an existing restriction. Ordinary evidence access does not grant these actions.</p>
      <p>Restrictions persist until an explicit release. An administrative deadline does not release a restriction. External downloaded copies remain outside Asservat's control.</p>
    </div>
    <ProcessingDiscovery session={session} scope={scope} client={discoveryClient} disabled={busy || !!pending} onSelect={selectArtifact}/>
    <section className="review-section" aria-labelledby="processing-inventory"><h2 id="processing-inventory">Restriction inventory</h2>
      <p>Load existing restrictions, including when ordinary evidence access is blocked. Each page contains at most 50 rules.</p>
      <Button className="button secondary" isDisabled={busy || !!pending} onPress={() => void load()}>Refresh processing rules</Button>
      {inventory && <>
        <p>{inventory.initialized ? 'Processing is initialized.' : 'Processing has not been initialized.'} Observed {when(inventory.observedAt)}.</p>
        {!inventory.initialized && <Button className="button" isDisabled={busy || !!pending} onPress={() => start({ action: 'initialize_processing' })}>Initialize processing</Button>}
        {inventory.rules.length === 0 && <p>No processing rules on this page.</p>}
        {inventory.rules.map(rule => <section className="review-section" key={rule.id} aria-label={`Processing rule ${rule.id}`}>
          <h3 className="identifier">{describe(rule)}</h3><p>State: {rule.state}. Revision {rule.revision}.</p>
          <p>Administrative coverage until {when(rule.administrationUntil)}. Retained rule history until {when(rule.retireBy)}.</p>
          {rule.state === 'restricted' && <Button className="button" isDisabled={busy || !!pending} onPress={() => start({ action: 'release_processing', ruleID: rule.id, expectedRevision: rule.revision, scope: rule.scope })}>Release restriction</Button>}
        </section>)}
        {inventory.nextCursor && <Button className="button secondary" isDisabled={busy || !!pending} onPress={() => void load(inventory.nextCursor)}>Next rules</Button>}
      </>}
    </section>
    <section className="review-section" aria-labelledby="processing-selected"><h2 id="processing-selected">Selected evidence</h2>
      <label htmlFor="processing-artifact">Artifact ID</label>
      <input ref={artifactField} id="processing-artifact" value={artifact} maxLength={36} disabled={busy || !!pending} onChange={event => { setArtifact(event.target.value); setReceipt(undefined); }}/>
      <p>A restriction covers this artifact and evidence derived from it.</p>
      <Button className="button" isDisabled={busy || !!pending || !uuid.test(artifact)} onPress={() => start({ action: 'restrict_processing', artifactID: artifact, ruleID: newID(), expectedRevision: 0 })}>Restrict processing</Button>
    </section>
    {busy && <p role="status">Checking processing state…</p>}
    {receipt && <p role="status">{receipt.state === 'initialized' ? 'Processing initialized.' : receipt.state === 'restricted' ? 'Processing restricted.' : 'Restriction released.'} Refresh processing rules to read the current inventory.</p>}
    {message && <p role="alert" className="notice">{message}</p>}
    {pending && !busy && <Button className="button" onPress={() => void change(pending)}>Retry same change</Button>}
  </div>;
}
