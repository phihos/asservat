import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { OperationFailure } from '../capture/http';
import { processingDiscoveryClient, validDiscoveryQuery, type DiscoveryPage, type DiscoveryQuery, type ProcessingDiscoveryClient } from './discovery-http';

const initial = {
  mode: 'case', caseID: '', clusterID: '', namespaceUID: '', workloadUID: '', from: '', until: '', purposeRef: '',
};
const pageSize = 12;
const maximumInterval = 3660 * 24 * 60 * 60 * 1000;
const when = (value: string) => new Date(value).toLocaleString(undefined, { timeZone: 'UTC', timeZoneName: 'short' });

function buildQuery(criteria: typeof initial): unknown {
  const common = { limit: pageSize, ...(criteria.purposeRef ? { purpose_ref: criteria.purposeRef } : {}) };
  if (criteria.mode === 'case') return { ...common, case_id: criteria.caseID };

  // The form labels the acquisition times as UTC. An explicit zone keeps the
  // same interval when browsers in different time zones review a request.
  const from = Date.parse(criteria.from + 'Z');
  const until = Date.parse(criteria.until + 'Z');
  if (!Number.isFinite(from) || !Number.isFinite(until) || until <= from || until - from > maximumInterval) return undefined;
  return {
    ...common, cluster_id: criteria.clusterID, namespace_uid: criteria.namespaceUID, workload_uid: criteria.workloadUID,
    acquired_from: new Date(from).toISOString(), acquired_until: new Date(until).toISOString(),
  };
}

export function ProcessingDiscovery({ session, scope, onSelect, disabled, client = processingDiscoveryClient }: {
  session: Session; scope: AbortSignal; onSelect: (artifactID: string) => void; disabled: boolean; client?: ProcessingDiscoveryClient;
}) {
  const inFlight = useRef<object | undefined>(undefined);
  const [criteria, setCriteria] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [result, setResult] = useState<{ query: DiscoveryQuery; page: DiscoveryPage }>();
  useLayoutEffect(() => {
    const clear = () => {
      inFlight.current = undefined;
      setCriteria(initial);
      setBusy(false);
      setResult(undefined);
      setMessage(undefined);
    };
    clear();
    scope.addEventListener('abort', clear, { once: true });
    return () => {
      inFlight.current = undefined;
      scope.removeEventListener('abort', clear);
    };
  }, [scope]);

  const edit = (field: keyof typeof initial, value: string) => {
    setCriteria(previous => ({ ...previous, [field]: value }));
    setResult(undefined);
    setMessage(undefined);
  };
  const search = async (input: unknown) => {
    if (disabled || scope.aborted || inFlight.current) return;
    setMessage(undefined);
    setResult(undefined);
    if (!validDiscoveryQuery(input)) {
      setMessage(criteria.mode === 'case' ? 'Enter a valid case ID and optional purpose reference.' : 'Enter a valid cluster ID, namespace and workload UIDs, and a UTC acquisition interval with a later end.');
      return;
    }
    const request = {};
    inFlight.current = request;
    const current = () => inFlight.current === request && !scope.aborted;
    setBusy(true);
    try {
      const reply = await client.search(input, session.csrf_token, scope);
      if (!current()) return;
      if (reply.status === 'ok') setResult({ query: input, page: reply.data });
      else setMessage('Evidence search is unavailable. Check your privacy operator access and try again.');
    } catch (error) {
      if (current()) setMessage(error instanceof OperationFailure && [401, 403].includes(error.status)
        ? 'Current privacy operator access is required.' : 'Evidence search is unavailable. Try again.');
    } finally {
      if (current()) {
        inFlight.current = undefined;
        setBusy(false);
      }
    }
  };
  const nextPage = () => {
    if (!result?.page.next) return;
    void search({ ...result.query, after: result.page.next });
  };

  return <section className="review-section" aria-labelledby="processing-discovery">
    <h2 id="processing-discovery">Find evidence</h2>
    <p>Search uses retained catalog metadata. Results show the lineage recorded at publication.</p>
    <form onSubmit={event => { event.preventDefault(); void search(buildQuery(criteria)); }}>
      <fieldset disabled={busy || disabled}>
        <legend>Search filters</legend>
        <label htmlFor="processing-search-mode">Search by</label>
        <select id="processing-search-mode" value={criteria.mode} onChange={event => edit('mode', event.target.value)}>
          <option value="case">Case ID</option>
          <option value="workload">Workload and acquisition time</option>
        </select>
        {criteria.mode === 'case' ? <>
          <label htmlFor="processing-search-case">Case ID</label>
          <input id="processing-search-case" value={criteria.caseID} maxLength={36} required onChange={event => edit('caseID', event.target.value)}/>
        </> : <>
          <label htmlFor="processing-search-cluster">Cluster ID</label>
          <input id="processing-search-cluster" value={criteria.clusterID} maxLength={36} required onChange={event => edit('clusterID', event.target.value)}/>
          <label htmlFor="processing-search-namespace">Namespace UID</label>
          <input id="processing-search-namespace" value={criteria.namespaceUID} maxLength={64} required onChange={event => edit('namespaceUID', event.target.value)}/>
          <label htmlFor="processing-search-workload">Workload UID</label>
          <input id="processing-search-workload" value={criteria.workloadUID} maxLength={64} required onChange={event => edit('workloadUID', event.target.value)}/>
          <label htmlFor="processing-search-from">Acquired from (UTC)</label>
          <input id="processing-search-from" type="datetime-local" step="1" value={criteria.from} required onChange={event => edit('from', event.target.value)}/>
          <label htmlFor="processing-search-until">Acquired until (UTC)</label>
          <input id="processing-search-until" type="datetime-local" step="1" value={criteria.until} required onChange={event => edit('until', event.target.value)}/>
        </>}
        <label htmlFor="processing-search-purpose">Purpose reference (optional)</label>
        <input id="processing-search-purpose" value={criteria.purposeRef} maxLength={128} onChange={event => edit('purposeRef', event.target.value)}/>
        <Button className="button" type="submit" isDisabled={busy || disabled}>Search evidence</Button>
      </fieldset>
    </form>
    {busy && <p role="status">Searching evidence metadata…</p>}
    {message && <p role="alert" className="notice">{message}</p>}
    {result && <section className="review-section" aria-labelledby="processing-candidates">
      <h3 id="processing-candidates">Evidence candidates</h3>
      {result.page.candidates.length === 0 && <p>No matching candidates on this page.</p>}
      {result.page.candidates.map(candidate => <article className="diagnostic" key={candidate.artifact_id} aria-label={`Evidence candidate ${candidate.artifact_id}`}>
        <h4 className="identifier">Artifact {candidate.artifact_id}</h4>
        <p>{candidate.native_type === 'podStatus' ? 'Pod status' : candidate.native_type} · {candidate.data_class} · {candidate.purpose_ref}</p>
        <dl className="facts">
          <dt>Case ID</dt><dd>{candidate.case_id}</dd>
          <dt>Capture ID</dt><dd>{candidate.capture_id}</dd>
          <dt>Cluster ID</dt><dd>{candidate.cluster_id}</dd>
          <dt>Namespace UID</dt><dd>{candidate.namespace_uid}</dd>
          <dt>Workload UID</dt><dd>{candidate.workload_uid}</dd>
          <dt>Acquisition anchor</dt><dd>{when(candidate.anchor_at)}</dd>
          <dt>Recorded access deadline</dt><dd>{when(candidate.expires_at)}</dd>
          <dt>Recorded deletion deadline</dt><dd>{when(candidate.delete_by)}</dd>
          <dt>Storage status</dt><dd>{candidate.custody_state === 'deleting' ? 'Deletion in progress' : 'Stored'}</dd>
        </dl>
        {candidate.parents.length > 0 ? <>
          <p>Recorded direct parents</p>
          <ul>{candidate.parents.map(id => <li className="identifier" key={id}>{id}</li>)}</ul>
        </> : <p>Original capture</p>}
        <Button className="button secondary" isDisabled={disabled} onPress={() => onSelect(candidate.artifact_id)}>Select artifact for restriction</Button>
      </article>)}
      {result.page.next && <Button className="button secondary" isDisabled={disabled} onPress={nextPage}>Next evidence page</Button>}
    </section>}
  </section>;
}
