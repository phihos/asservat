import { useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operationMessage } from '../capture/http';
import { previewClient, validPreviewInput, type Preview, type PreviewClient, type PreviewInput } from './preview-http';

const example = JSON.stringify([{ action: 'create', kind: 'AccessBinding', spec: {
  effect: 'Deny', subjects: [{ kind: 'Group', issuer: 'https://identity.example/realms/company', id: 'team-id' }], roles: ['evidence-reader'],
  scope: { clusterID: '00000000-0000-4000-8000-000000000001', namespaceRef: { name: 'payments', uid: 'namespace-uid' } }, reason: 'Why this change is needed',
} }], null, 2);
const operations: Record<string, string> = { capture: 'Collect', read: 'Read', download: 'Download' };
const unmet: Record<string, string> = {
  PermissionObservationStale: 'permission data is not current',
  ServiceUnavailable: 'permission data could not be read',
  ClusterUnavailable: 'the cluster is not enrolled in this installation',
};
type Delta = Preview['deltas'][number];

function workload(row: { workload_uid: string; other_workloads: boolean }) {
  return row.other_workloads ? 'every other workload' : <span className="identifier">{row.workload_uid}</span>;
}

function basis(rows: Delta['before_basis']) {
  if (rows.length === 0) return null;
  return <ul className="basis">{rows.map((row, index) => <li key={index}>
    {row.effect === 'deny' ? 'Deny' : 'Allow'} {row.role} from {row.proposed ? 'proposed ' : ''}{row.basis_kind} <span className="identifier">{row.basis_uid}</span> (revision <span className="identifier">{row.revision.slice(0, 12)}</span>)
  </li>)}</ul>;
}

// Permission impact preview for fleet operators and configured delegation
// previewers (ADR-237). The proposed changes are evaluated by the server
// against the current accepted permission data; nothing is applied here.
// Changes are made with kubectl or GitOps. Large results arrive in pages.
export function AccessPreviewWorkspace({ session, scope, client = previewClient }: { session: Session; scope: AbortSignal; client?: PreviewClient }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [text, setText] = useState(example);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [preview, setPreview] = useState<Preview>();
  const [request, setRequest] = useState<PreviewInput>();
  const [cursor, setCursor] = useState<string | null>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  const load = async (input: PreviewInput, more: boolean) => {
    setBusy(true);
    try {
      const result = await client.preview(input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') {
        const page = result.data;
        setPreview(previous => more && previous ? { ...page, deltas: [...previous.deltas, ...page.deltas], unavailable: [...previous.unavailable, ...page.unavailable] } : page);
        setCursor(result.next_cursor ?? null);
      } else if (result.status === 'error') { setMessage(result.data.message); setCursor(null); }
      else setMessage('The preview is not ready yet. Try again shortly.');
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error));
    } finally { if (!scope.aborted) setBusy(false); }
  };
  const run = async () => {
    setMessage(undefined); setPreview(undefined); setCursor(null);
    let changes: unknown;
    try { changes = JSON.parse(text); } catch { setMessage('The proposed changes are not valid JSON.'); return; }
    const input = { changes };
    if (!validPreviewInput(input)) {
      setMessage('Enter a JSON list of 1 to 16 changes: create with a complete AccessBinding or PermissionSource spec, update with the object\'s UID and spec, or delete with its UID.');
      return;
    }
    setRequest(input);
    await load(input, false);
  };
  const more = async () => { if (request && cursor) await load({ ...request, cursor }, true); };
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Preview permission changes</h1>
      <p>For fleet operators and configured delegation previewers. Shows whose collect, read and download access the proposed AccessBinding or PermissionSource changes would allow or deny, using the current permission data. Nothing is applied: apply the reviewed objects with kubectl or GitOps.</p>
    </div>
    <section className="review-section" aria-labelledby="proposed-changes">
      <h2 id="proposed-changes">Proposed changes</h2>
      <label htmlFor="access-changes">Changes (JSON list; create, update with uid, or delete with uid)</label>
      <textarea id="access-changes" rows={14} spellCheck={false} value={text} onChange={event => setText(event.target.value)}/>
      <Button className="button" isDisabled={busy} onPress={() => void run()}>{busy ? 'Previewing…' : 'Preview'}</Button>
    </section>
    {message && <p role="alert" className="notice">{message}</p>}
    {preview && <section className="review-section" role="status" aria-label="Preview result">
      <h2>Result</h2>
      <p>{preview.message}</p>
      <p>{preview.targets_evaluated} workload scopes evaluated; {preview.deltas_total} decision changes; {preview.deltas.length + preview.unavailable.length} of {preview.listed_rows} listed rows shown.{preview.fresh_until ? ` Based on permission data current until ${new Date(preview.fresh_until).toLocaleString()}.` : ''}</p>
      {preview.not_evaluated.length > 0 && <ul>{preview.not_evaluated.map((row, index) => <li key={index}>PermissionSource {row.action}{row.uid ? <> <span className="identifier">{row.uid}</span></> : ''}: Indeterminate (inherited permissions are not yet accepted by this installation)</li>)}</ul>}
      {preview.deltas.length > 0 && <table>
        <thead><tr><th scope="col">Workload</th><th scope="col">Subject</th><th scope="col">Operation</th><th scope="col">Now</th><th scope="col">After</th></tr></thead>
        <tbody>{preview.deltas.map((row, index) => <tr key={index}>
          <td>{workload(row)} in namespace <span className="identifier">{row.namespace_uid}</span></td>
          <td>{row.subject.kind} <span className="identifier">{row.subject.id}</span></td>
          <td>{operations[row.operation]}</td>
          <td>{row.before}{row.before_unmet ? ` (${row.before_unmet})` : ''}{basis(row.before_basis)}</td>
          <td>{row.after}{row.after_unmet ? ` (${row.after_unmet})` : ''}{basis(row.after_basis)}</td>
        </tr>)}</tbody>
      </table>}
      {preview.unavailable.length > 0 && <>
        <h3>Not evaluated: Indeterminate ({preview.unavailable_total})</h3>
        <ul>{preview.unavailable.map((row, index) => <li key={index}>{workload(row)} in namespace <span className="identifier">{row.namespace_uid}</span>: {unmet[row.unmet]}</li>)}</ul>
      </>}
      {preview.unmatched.length > 0 && <p>No current assignments for: {preview.unmatched.map(row => `${row.kind} ${row.uid}`).join(', ')}.</p>}
      {cursor && <Button className="button secondary" isDisabled={busy} onPress={() => void more()}>Show more</Button>}
    </section>}
  </div>;
}
