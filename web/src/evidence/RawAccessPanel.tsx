import { useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operations, type Operations, type Input, type Data } from '../approvals/http';
import { operationMessage } from '../capture/http';
import type { Artifact } from './http';

const maximumBytes = 1099511627776;
const count = (value: number) => new Intl.NumberFormat().format(value);

// This form retains only metadata and one immutable request after submission.
// An uncertain reply is retried with the same identity, selection and key.
export function RawAccessPanel({ session, scope, caseID, artifacts, prefilledArtifactID, client = operations, newID = () => crypto.randomUUID() }: { session: Session; scope: AbortSignal; caseID: string; artifacts: Artifact[]; prefilledArtifactID?: string; client?: Operations; newID?: () => string }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [maxBytes, setMaxBytes] = useState(1);
  const [seconds, setSeconds] = useState(3600);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [reply, setReply] = useState<Data<'request_raw_access'>>();
  const request = useRef<Input<'request_raw_access'> | undefined>(undefined);
  const active = useRef<AbortController | undefined>(undefined);
  const heading = useRef<HTMLHeadingElement>(null);
  const appliedPrefill = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!prefilledArtifactID || appliedPrefill.current === prefilledArtifactID || request.current) return;
    const artifact = artifacts.find(a => a.artifact_id === prefilledArtifactID);
    if (!artifact) return;
    appliedPrefill.current = prefilledArtifactID;
    if (artifact.verified_native_bytes !== undefined && artifact.target && Date.parse(artifact.expires_at) > Date.now()) {
      setSelected([artifact.artifact_id]); setMaxBytes(Math.max(1, artifact.verified_native_bytes));
    }
    heading.current?.focus();
  }, [prefilledArtifactID, artifacts]);
  useEffect(() => () => active.current?.abort(), [scope]);
  const raw = artifacts.filter(a => a.data_class === 'raw');
  if (raw.length === 0) return null;
  const eligible = (a: Artifact) => a.verified_native_bytes !== undefined && a.target !== undefined && Date.parse(a.expires_at) > Date.now();
  const chosen = raw.filter(a => selected.includes(a.artifact_id));
  const total = chosen.reduce((n, a) => n + (a.verified_native_bytes ?? 0), 0);
  const locked = busy || request.current !== undefined;
  const select = (artifact: Artifact, checked: boolean) => {
    const next = checked ? [...selected, artifact.artifact_id] : selected.filter(id => id !== artifact.artifact_id);
    setSelected(next);
    setMaxBytes(Math.max(1, raw.filter(a => next.includes(a.artifact_id)).reduce((n, a) => n + (a.verified_native_bytes ?? 0), 0)));
  };
  const submit = async () => {
    if (busy || scope.aborted) return;
    if (!request.current) {
      if (!chosen.length || chosen.length > 64 || chosen.some(a => !eligible(a)) || !reason.trim() || !Number.isSafeInteger(maxBytes) || maxBytes < Math.max(1, total) || maxBytes > maximumBytes || !Number.isInteger(seconds) || seconds < 1 || seconds > 28800) return;
      request.current = { case_id: caseID, artifact_digests: chosen.map(a => a.digest).sort(), operations: ['download_artifact'], reason: reason.trim(), max_bytes: maxBytes, expires_in_seconds: seconds, idempotency_key: newID() };
    }
    const controller = new AbortController(); active.current = controller;
    const abort = () => controller.abort(); scope.addEventListener('abort', abort, { once: true });
    setBusy(true); setError(undefined);
    try {
      const result = await client.call('request_raw_access', request.current, session.csrf_token, controller.signal);
      if (controller.signal.aborted) return;
      if (result.status === 'ok') setReply(result.data);
      else if (result.status === 'error') {
        // Only a validated definitive refusal releases this request identity.
        // Transport failures and pending/retryable replies may have persisted it.
        if (result.data.retryable === false) request.current = undefined;
        setError(result.data.message);
      } else setError('The request has not returned a final result. Retry the same request.');
    } catch (e) { if (!controller.signal.aborted) setError(operationMessage(e)); }
    finally { scope.removeEventListener('abort', abort); if (!controller.signal.aborted) setBusy(false); }
  };
  return <section className="review-section" aria-labelledby="raw-access-title">
    <h2 id="raw-access-title" ref={heading} tabIndex={-1}>Request raw download approval</h2>
    <p>Use Download above when you already have covering approval. This request asks an independent reviewer for whole-file downloads of existing evidence; it starts no collection.</p>
    <fieldset disabled={locked || !!reply}><legend>Select existing raw artifacts (up to 64)</legend>
      {raw.map(a => <label key={a.artifact_id}><input type="checkbox" checked={selected.includes(a.artifact_id)} disabled={!eligible(a) || !selected.includes(a.artifact_id) && selected.length >= 64} onChange={e => select(a, e.target.checked)}/>{a.kind} {a.artifact_id} — {a.verified_native_bytes === undefined ? 'verified size unavailable' : `${count(a.verified_native_bytes)} bytes`}{a.target && <> · {a.target.workload_name ?? a.target.workload_uid} in {a.target.namespace ?? a.target.namespace_uid}, Pod {a.target.pod_name ?? a.target.pod_uid}, cluster {a.target.cluster_id}</>}{!eligible(a) && ' (not selectable)'}</label>)}
      <p>Selected native size: {count(total)} bytes.</p>
      <label>Reason for raw download<textarea maxLength={512} value={reason} onChange={e => setReason(e.target.value)}/></label>
      <label>Total download byte budget<input type="number" min={Math.max(1, total)} max={maximumBytes} step={1} value={maxBytes} onChange={e => setMaxBytes(Number(e.target.value))}/></label>
      <label>Approval period in seconds<input type="number" min={1} max={28800} step={1} value={seconds} onChange={e => setSeconds(Number(e.target.value))}/></label>
    </fieldset>
    <p>At most 10000 download operations, bound to this requesting client. Retransmissions consume the byte budget. Downloaded copies are outside Asservat's automatic deletion.</p>
    {error && <p role="alert">{error}</p>}
    {reply ? <p role="status">Approval request: {reply.phase}. <a href={'/approvals/' + reply.grant_id}>Review download approval</a></p> : <Button className="button secondary" isDisabled={busy || (!request.current && (!chosen.length || !reason.trim() || chosen.some(a => !eligible(a)) || !Number.isSafeInteger(maxBytes) || maxBytes < Math.max(1, total) || maxBytes > maximumBytes || !Number.isInteger(seconds) || seconds < 1 || seconds > 28800))} onPress={() => void submit()}>{request.current ? 'Retry same approval request' : 'Request download approval'}</Button>}
  </section>;
}
