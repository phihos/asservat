import { useEffect, useId, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operations, type Operations, type Input, type Data } from '../approvals/http';
import { operationMessage } from '../capture/http';
import type { Artifact } from './http';

const maximumBytes = 1099511627776;
const count = (value: number) => new Intl.NumberFormat().format(value);

// This form retains only metadata and one immutable request after submission.
// An uncertain reply is retried with the same identity, selection and key.
export function RawAccessPanel({ session, scope, caseID, artifacts, prefilledArtifactID, purpose = 'download', onGrant, client = operations, newID = () => crypto.randomUUID() }: { session: Session; scope: AbortSignal; caseID: string; artifacts: Artifact[]; prefilledArtifactID?: string; purpose?: 'download' | 'packet-query' | 'syscall-query' | 'log-query'; onGrant?: (grantID: string) => void; client?: Operations; newID?: () => string }) {
  const titleID = useId();
  const [allowed, setAllowed] = useState<'download' | 'query' | 'both'>(purpose !== 'download' ? 'query' : 'download');
  const query = allowed !== 'download';
  const downloads = allowed !== 'query';
  const defaultBudget = (items: Artifact[], mode = allowed) => Math.max(1, (mode !== 'query' ? items.reduce((n, a) => n + (a.verified_native_bytes ?? 0), 0) : 0) + (mode !== 'download' ? 49152 * items.length : 0));
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [maxBytes, setMaxBytes] = useState(1);
  const [seconds, setSeconds] = useState(3600);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [reply, setReply] = useState<{ grant_id: string; phase: Data<'request_raw_access'>['phase'] | 'Exhausted' }>();
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
      setSelected([artifact.artifact_id]); setMaxBytes(defaultBudget([artifact]));
    }
    if (purpose === 'download') heading.current?.focus();
  }, [prefilledArtifactID, artifacts]);
  useEffect(() => () => active.current?.abort(), [scope]);
  const queryKind = (a: Artifact) => a.kind === 'logs' && a.native_format === 'asservat-logs/v1' ? 'log' : a.kind === 'packetCapture' && a.native_format === 'pcapng-raw' ? 'packet' : a.kind === 'syscallTrace' && a.native_format === 'asservat-syscall-arguments/v1' ? 'syscall' : undefined;
  const raw = artifacts.filter(a => a.data_class === 'raw' && (purpose === 'download' || queryKind(a) === (purpose === 'log-query' ? 'log' : purpose === 'packet-query' ? 'packet' : 'syscall')));
  if (raw.length === 0) return null;
  const eligible = (a: Artifact) => a.verified_native_bytes !== undefined && a.target !== undefined && Date.parse(a.expires_at) > Date.now();
  const chosen = raw.filter(a => selected.includes(a.artifact_id));
  const total = chosen.reduce((n, a) => n + (a.verified_native_bytes ?? 0), 0);
  const chosenKind = chosen.length ? queryKind(chosen[0]) : undefined;
  const queryEligible = chosenKind !== undefined && chosen.every(a => queryKind(a) === chosenKind);
  const queryLabel = chosenKind === 'log' || purpose === 'log-query' ? 'log' : chosenKind === 'syscall' || purpose === 'syscall-query' ? 'syscall argument' : 'packet';
  const minimum = downloads ? Math.max(1, total) : 24576;
  const maximum = downloads ? maximumBytes : 1073741824;
  const invalid = !chosen.length || chosen.length > 64 || chosen.some(a => !eligible(a)) || query && !queryEligible || !reason.trim() || !Number.isSafeInteger(maxBytes) || maxBytes < minimum || maxBytes > maximum || !Number.isInteger(seconds) || seconds < 1 || seconds > 28800;
  const locked = busy || request.current !== undefined;
  const select = (artifact: Artifact, checked: boolean) => {
    const next = checked ? [...selected, artifact.artifact_id] : selected.filter(id => id !== artifact.artifact_id);
    setSelected(next);
    const items = raw.filter(a => next.includes(a.artifact_id));
    const kind = items.length ? queryKind(items[0]) : undefined;
    const mode = kind === undefined || items.some(a => queryKind(a) !== kind) ? 'download' : allowed;
    setAllowed(mode); setMaxBytes(defaultBudget(items, mode));
  };
  const submit = async () => {
    if (busy || scope.aborted) return;
    if (!request.current) {
      if (invalid) return;
      request.current = { case_id: caseID, artifact_digests: chosen.map(a => a.digest).sort(), operations: [...(downloads ? ['download_artifact' as const] : []), ...(query ? [chosenKind === 'log' ? 'get_logs' as const : chosenKind === 'syscall' ? 'syscall_query' as const : 'pcap_query' as const] : [])], reason: reason.trim(), max_bytes: maxBytes, expires_in_seconds: seconds, idempotency_key: newID() };
    }
    const controller = new AbortController(); active.current = controller;
    const abort = () => controller.abort(); scope.addEventListener('abort', abort, { once: true });
    setBusy(true); setError(undefined);
    try {
      const result = await client.call('request_raw_access', request.current, session.csrf_token, controller.signal);
      if (controller.signal.aborted) return;
      if (result.status === 'ok') { setReply(result.data); if (result.data.phase === 'Approved') onGrant?.(result.data.grant_id); }
      else if (result.status === 'error') {
        // Only a validated definitive refusal releases this request identity.
        // Transport failures and pending/retryable replies may have persisted it.
        if (result.data.retryable === false) request.current = undefined;
        setError(result.data.message);
      } else setError('The request has not returned a final result. Retry the same request.');
    } catch (e) { if (!controller.signal.aborted) setError(operationMessage(e)); }
    finally { scope.removeEventListener('abort', abort); if (!controller.signal.aborted) setBusy(false); }
  };
  const checkApproval = async () => {
    if (!reply || busy || scope.aborted) return;
    const controller = new AbortController(); active.current = controller;
    const abort = () => controller.abort(); scope.addEventListener('abort', abort, { once: true });
    setBusy(true); setError(undefined);
    try {
      const result = await client.call('get_grant', { grant_id: reply.grant_id }, session.csrf_token, controller.signal);
      if (controller.signal.aborted) return;
      if (result.status === 'ok' && result.data.grant_id === reply.grant_id) {
        setReply({ grant_id: reply.grant_id, phase: result.data.phase });
        if (result.data.phase === 'Approved') onGrant?.(reply.grant_id);
      } else setError(result.status === 'error' ? result.data.message : 'The approval status is unavailable. Check again.');
    } catch (e) { if (!controller.signal.aborted) setError(operationMessage(e)); }
    finally { scope.removeEventListener('abort', abort); if (!controller.signal.aborted) setBusy(false); }
  };
  return <section className="review-section" aria-labelledby={titleID}>
    <h2 id={titleID} ref={heading} tabIndex={-1}>{query ? `Request saved ${queryLabel} query approval` : 'Request raw download approval'}</h2>
    <p>{query ? `Use existing covering approval when available. This request covers queries of the selected saved ${queryLabel} evidence; it starts no collection.` : 'Use Download above when you already have covering approval. This request asks an independent reviewer for whole-file downloads of existing evidence; it starts no collection.'}</p>
    <fieldset disabled={locked || !!reply}><legend>Select existing raw artifacts (up to 64)</legend>
      {raw.map(a => <label key={a.artifact_id}><input type="checkbox" checked={selected.includes(a.artifact_id)} disabled={!selected.includes(a.artifact_id) && (!eligible(a) || selected.length >= 64)} onChange={e => select(a, e.target.checked)}/>{a.kind} {a.artifact_id} — {a.verified_native_bytes === undefined ? 'verified size unavailable' : `${count(a.verified_native_bytes)} bytes`}{a.target && <> · {a.target.workload_name ?? a.target.workload_uid} in {a.target.namespace ?? a.target.namespace_uid}, Pod {a.target.pod_name ?? a.target.pod_uid}, cluster {a.target.cluster_id}</>}{!eligible(a) && ' (not selectable)'}</label>)}
      <p>Selected native size: {count(total)} bytes.</p>
      {queryEligible && <label>Allowed operations<select value={allowed} onChange={e => { const next = e.target.value as typeof allowed; setAllowed(next); setMaxBytes(defaultBudget(chosen, next)); }}>{purpose === 'download' && <option value="download">Whole-file downloads</option>}<option value="query">Saved {queryLabel} queries</option><option value="both">Downloads and saved {queryLabel} queries</option></select></label>}
      <label>{query ? 'Reason for raw access' : 'Reason for raw download'}<textarea maxLength={512} value={reason} onChange={e => setReason(e.target.value)}/></label>
      <label>{query ? 'Total disclosure byte budget' : 'Total download byte budget'}<input type="number" min={minimum} max={maximum} step={1} value={maxBytes} onChange={e => setMaxBytes(Number(e.target.value))}/></label>
      <label>Approval period in seconds<input type="number" min={1} max={28800} step={1} value={seconds} onChange={e => setSeconds(Number(e.target.value))}/></label>
    </fieldset>
    {query ? <p>At most 10000 selected operations, bound to this requesting client. Each paid query page reserves 24 KiB and one operation, including a reply lost in transit. A query permits at most two paid pages. Downloads and queries consume the same budget when both are selected. Downloaded copies are outside Asservat's automatic deletion.</p> : <p>At most 10000 download operations, bound to this requesting client. Retransmissions consume the byte budget. Downloaded copies are outside Asservat's automatic deletion.</p>}
    {error && <p role="alert">{error}</p>}
    {reply ? <p role="status">Approval request: {reply.phase}. <a href={'/approvals/' + reply.grant_id}>{query ? 'Review query approval' : 'Review download approval'}</a></p> : <Button className="button secondary" isDisabled={busy || (!request.current && invalid)} onPress={() => void submit()}>{request.current ? 'Retry same approval request' : query ? 'Request query approval' : 'Request download approval'}</Button>}
    {reply?.phase === 'Pending' && <Button className="button secondary" isDisabled={busy} onPress={() => void checkApproval()}>Check approval</Button>}
    {reply && reply.phase !== 'Pending' && <Button className="button secondary" isDisabled={busy} onPress={() => { request.current = undefined; setReply(undefined); setError(undefined); }}>Prepare another approval request</Button>}
  </section>;
}
