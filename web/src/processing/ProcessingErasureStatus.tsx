import { useLayoutEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { OperationFailure } from '../capture/http';
import { processingErasureClient, type ErasureStatus, type ProcessingErasureClient } from './erasure-http';
import { uuid } from './http';

const when = (value: string) => new Date(value).toLocaleString();
const deletionLabels = { pending: 'Deletion pending', overdue: 'Deletion overdue', deleted: 'Managed deletion verified' };

export function ProcessingErasureStatus({ session, scope, acceptedRequestID, disabled, client = processingErasureClient }: {
  session: Session;
  scope: AbortSignal;
  acceptedRequestID?: string;
  disabled: boolean;
  client?: ProcessingErasureClient;
}) {
  const inFlight = useRef<object | undefined>(undefined);
  const [requestID, setRequestID] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ErasureStatus>();
  const [message, setMessage] = useState<string>();
  useLayoutEffect(() => {
    const clear = () => {
      inFlight.current = undefined;
      setRequestID('');
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
  useLayoutEffect(() => {
    if (!acceptedRequestID || scope.aborted) return;
    inFlight.current = undefined;
    setRequestID(acceptedRequestID);
    setBusy(false);
    setResult(undefined);
    setMessage(undefined);
  }, [scope, acceptedRequestID]);

  const read = async () => {
    if (disabled || scope.aborted || inFlight.current || !uuid.test(requestID)) return;
    const request = {};
    inFlight.current = request;
    const current = () => inFlight.current === request && !scope.aborted;
    setBusy(true);
    setResult(undefined);
    setMessage(undefined);
    try {
      const reply = await client.read(requestID, session.csrf_token, scope);
      if (!current()) return;
      if (reply.status === 'ok' && reply.data.request_id === requestID) setResult(reply.data);
      else setMessage('Erasure status is unavailable for this request ID.');
    } catch (error) {
      if (current()) setMessage(error instanceof OperationFailure && [401, 403].includes(error.status)
        ? 'Current privacy operator access is required.' : 'Erasure status is unavailable for this request ID.');
    } finally {
      if (current()) {
        inFlight.current = undefined;
        setBusy(false);
      }
    }
  };

  return <section className="review-section" aria-labelledby="processing-erasure-status">
    <h2 id="processing-erasure-status">Early erasure status</h2>
    <form onSubmit={event => { event.preventDefault(); void read(); }}>
      <label htmlFor="processing-erasure-request-id">Erasure request ID</label>
      <input id="processing-erasure-request-id" value={requestID} maxLength={36} required disabled={disabled || busy} onChange={event => {
        setRequestID(event.target.value); setResult(undefined); setMessage(undefined);
      }}/>
      <Button className="button secondary" type="submit" isDisabled={disabled || busy || !uuid.test(requestID)}>Check erasure status</Button>
    </form>
    {busy && <p role="status">Checking erasure status…</p>}
    {message && <p role="alert" className="notice">{message}</p>}
    {result && <>
      <p role="status">{deletionLabels[result.deletion_state]}.</p>
      <dl className="facts">
        <dt>Artifact ID</dt><dd className="identifier">{result.artifact_id}</dd>
        <dt>Accepted at</dt><dd>{when(result.accepted_at)}</dd>
        <dt>Access cutoff</dt><dd>{when(result.access_until)}</dd>
        <dt>Hard deletion deadline at acceptance</dt><dd>{when(result.delete_by)}</dd>
        {result.effective_delete_by !== result.delete_by && <><dt>Current hard deletion deadline</dt><dd>{when(result.effective_delete_by)}</dd></>}
        <dt>Request audit</dt><dd>{result.audit_state === 'acknowledged' ? 'Acknowledged' : 'Pending'}</dd>
        {result.deleted_at && <><dt>Verified deletion time</dt><dd>{when(result.deleted_at)}</dd></>}
      </dl>
    </>}
  </section>;
}
