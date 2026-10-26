import { useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operationMessage } from '../capture/http';
import { retentionPreviewClient, validRetentionPreviewInput, type RetentionPreview, type RetentionPreviewClient } from './preview-http';

const example = JSON.stringify([{ action: 'update', uid: 'baseline-policy-uid', spec: {
  scope: {}, purposeRef: 'diagnostics',
  defaults: { evidenceSeconds: 3600, caseMetadataSeconds: 604800, auditMetadataSeconds: 7776000 },
  maxima: { evidenceSeconds: 43200, caseMetadataSeconds: 604800, auditMetadataSeconds: 7776000 },
  rules: [], deletionBudgetSeconds: 3600, legalExceptions: 'disabled',
} }], null, 2);
const classes: Record<string, string> = {
  unknown: 'unknown classification', potentialPersonalData: 'possible personal data', personalData: 'personal data',
  specialCategoryPossible: 'possible special-category data', verifiedNonPersonal: 'verified non-personal',
};
const notEvaluated: Record<string, string> = {
  UnknownObject: 'no accepted policy with this UID in that source',
  SourceAmbiguous: 'the cluster has more than one local policy source',
};
const when = (value?: string) => value ? new Date(value).toLocaleString() : '—';

// Retention impact preview for fleet operators (ADR-240). The proposed
// EvidenceRetentionPolicy changes are applied by the server to the stored
// evidence's current deadlines exactly as reconciliation will; nothing is
// applied here. Changes are made with kubectl or GitOps.
export function RetentionPreviewWorkspace({ session, scope, client = retentionPreviewClient }: { session: Session; scope: AbortSignal; client?: RetentionPreviewClient }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [text, setText] = useState(example);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [preview, setPreview] = useState<RetentionPreview>();
  useEffect(() => { heading.current?.focus(); }, []);
  const run = async () => {
    setMessage(undefined); setPreview(undefined);
    let changes: unknown;
    try { changes = JSON.parse(text); } catch { setMessage('The proposed changes are not valid JSON.'); return; }
    const input = { changes };
    if (!validRetentionPreviewInput(input)) {
      setMessage('Enter a JSON list of 1 to 16 changes: create with a complete EvidenceRetentionPolicy spec, update with the policy\'s UID and spec, or delete with its UID. Add source_cluster_id for a cluster\'s local policy.');
      return;
    }
    setBusy(true);
    try {
      const result = await client.preview(input, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') setPreview(result.data);
      else if (result.status === 'error') setMessage(result.data.message);
      else setMessage('The preview is not ready yet. Try again shortly.');
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error));
    } finally { if (!scope.aborted) setBusy(false); }
  };
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Preview retention changes</h1>
      <p>For fleet operators. Shows how the proposed EvidenceRetentionPolicy changes would shorten the retention of evidence already stored. A longer limit applies only to new collections and never extends a date already set. Nothing is applied: apply the reviewed policy with kubectl or GitOps.</p>
    </div>
    <section className="review-section" aria-labelledby="proposed-retention">
      <h2 id="proposed-retention">Proposed changes</h2>
      <label htmlFor="retention-changes">Changes (JSON list; create, update with uid, or delete with uid; source_cluster_id for a local policy)</label>
      <textarea id="retention-changes" rows={14} spellCheck={false} value={text} onChange={event => setText(event.target.value)}/>
      <Button className="button" isDisabled={busy} onPress={() => void run()}>{busy ? 'Previewing…' : 'Preview'}</Button>
    </section>
    {message && <p role="alert" className="notice">{message}</p>}
    {preview && <section className="review-section" role="status" aria-label="Preview result">
      <h2>Result</h2>
      <p>{preview.message}</p>
      <p>{preview.artifacts_scanned} stored artifacts evaluated{preview.scan_limited ? ' (limit reached; counts are lower bounds)' : ''}: {preview.affected_total} would be shortened, {preview.read_closed_total} would become unreadable at once, {preview.deletion_due_total} would be due for deletion at once, {preview.unknown_total} unknown.</p>
      {preview.affected_total > 0 && <p>Earliest new access end {when(preview.earliest_expires_at)}; earliest new deletion {when(preview.earliest_delete_by)}.</p>}
      {preview.baseline_changed && <p className="notice">The hub would no longer have exactly one baseline policy: new collection would be suspended.</p>}
      {preview.groups.length > 0 && <table>
        <thead><tr><th scope="col">Cluster</th><th scope="col">Class</th><th scope="col">Evaluated</th><th scope="col">Shortened</th><th scope="col">Unreadable at once</th><th scope="col">Deletion due at once</th><th scope="col">Unknown</th><th scope="col">Earliest new deletion</th></tr></thead>
        <tbody>{preview.groups.map((row, index) => <tr key={index}>
          <td><span className="identifier">{row.cluster_id}</span></td>
          <td>{classes[row.privacy_class]}, {row.evidence_type}</td>
          <td>{row.scanned}</td><td>{row.affected}</td><td>{row.read_closed}</td><td>{row.deletion_due}</td><td>{row.unknown}</td>
          <td>{when(row.earliest_delete_by)}</td>
        </tr>)}</tbody>
      </table>}
      {preview.groups_total > preview.groups.length && <p>{preview.groups.length} of {preview.groups_total} groups shown, earliest deletions first.</p>}
      {preview.incomplete_clusters.length > 0 && <>
        <h3>Incomplete clusters ({preview.incomplete_total})</h3>
        <p>The retention policy source of these clusters is not current; their results may change once it is.</p>
        <ul>{preview.incomplete_clusters.map(row => <li key={row.cluster_id}><span className="identifier">{row.cluster_id}</span></li>)}</ul>
      </>}
      {preview.not_evaluated.length > 0 && <>
        <h3>Changes not evaluated</h3>
        <ul>{preview.not_evaluated.map((row, index) => <li key={index}>{row.action}{row.uid ? <> <span className="identifier">{row.uid}</span></> : ''}{row.source_cluster_id ? <> in cluster <span className="identifier">{row.source_cluster_id}</span></> : ' in the hub'}: {notEvaluated[row.reason]}</li>)}</ul>
      </>}
    </section>}
  </div>;
}
