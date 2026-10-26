import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { Evidence } from './evidence';
import type { Artifact, Download } from './http';
import { ContextProjectionView } from '../projection/ContextProjectionView';
import { ContextProjection } from '../projection/projection';
import { SharePanel } from '../sharing/SharePanel';

export const evidenceController = new Evidence();
const date = (value: string) => new Date(value).toLocaleString();
const bytes = (value: number) => new Intl.NumberFormat().format(value) + ' bytes';
const states: Record<Download['state'], string> = { Preparing: 'Preparing the native file', Ready: 'Ready to download', Streaming: 'Sending the file', Completed: 'Transfer recorded', Interrupted: 'Download interrupted', Cancelled: 'Download cancelled', Expired: 'Download expired', Denied: 'Download access unavailable', Failed: 'Download failed' };
const contentNames: Record<string, string> = { userContent: 'user content', credentials: 'credentials', personalIdentifiers: 'personal identifiers', networkAddresses: 'network addresses', paths: 'paths', profileLabels: 'profile labels', unknownApplicationData: 'other application data' };
const terminal = new Set(['Completed', 'Cancelled', 'Expired', 'Denied', 'Failed']);
const kindName = (kind: string) => ['context', 'pod-status'].includes(kind) ? 'Pod status' : kind;
const classLine = (artifact: Artifact) => `${artifact.data_class === 'raw' ? 'Raw evidence' : artifact.data_class === 'extract' ? 'Approved extract' : 'Approved metadata'} · ${artifact.completeness}`;
function SavedPodStatus({ session, scope, caseID, artifactID }: { session: Session; scope: AbortSignal; caseID: string; artifactID: string }) {
  // Each visible artifact owns its view. Mounting reads nothing; the existing
  // view aborts its request and clears its result on unmount or session loss.
  const [controller] = useState(() => new ContextProjection());
  return <ContextProjectionView controller={controller} session={session} scope={scope} caseID={caseID} artifactID={artifactID}/>;
}
function Handling({ artifact }: { artifact: Artifact }) {
  const notice = artifact.handling_notice;
  return <>
    <p>{notice.classification === 'verifiedNonPersonal' ? 'Classified as non-personal data.' : `May contain user data${notice.mayContain.length ? ': ' + notice.mayContain.map(value => contentNames[value]).join(', ') : ''}.`}</p>
    <dl className="facts"><dt>Access until</dt><dd>{date(notice.expiresAt)}</dd><dt>Managed deletion</dt><dd>{notice.deletionState === 'verified' ? 'Deletion verified' : notice.deletionState === 'restrictedPreservation' ? 'Restricted preservation applies' : notice.deletionState === 'overdue' ? 'Deletion overdue; administrator action is needed' : notice.deletionState === 'unknown' ? 'Deletion status is unavailable' : `By ${date(notice.deleteBy)}${notice.deletionState === 'inProgress' ? ' · in progress' : ''}`}</dd></dl>
  </>;
}
export default function EvidenceWorkspace({ session, scope, caseID, controller = evidenceController }: { session: Session; scope: AbortSignal; caseID: string; controller?: Evidence }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => controller.attach(session, scope, caseID), [session, scope, caseID, controller]);
  useEffect(() => { heading.current?.focus(); }, []);
  const download = state.download;
  const pending = !!state.preparingArtifact;
  return <div className="capture-workspace evidence-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Evidence</h1><p>Inspect the saved details, or download the native file for your preferred compatible local tools.</p></div>
    {state.error && <p role="alert" className="notice">{state.error}</p>}
    {!state.details && <section aria-busy={state.busy}>
      {!state.error && <p role="status">{state.busy ? 'Checking your current evidence access…' : 'Evidence details are unavailable.'}</p>}
      <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.refresh()}>Check evidence access</Button>
    </section>}
    {state.details && <>
      {state.details.case.title && <h2>{state.details.case.title}</h2>}
      {state.details.case.access === 'shared' && <p>You see the evidence explicitly shared with you. A share lets you read it; it does not include native download.</p>}
      {state.details.artifacts.length === 0 && <p>No evidence is currently available in this case.</p>}
      {state.details.artifacts.map((artifact, index) => <section className="review-section" key={artifact.artifact_id} aria-labelledby={`artifact-${index}`}>
        <h2 id={`artifact-${index}`}>{kindName(artifact.kind)}</h2>
        <p className="field-help">{classLine(artifact)}</p>
        <Handling artifact={artifact}/>
        {Date.parse(artifact.expires_at) <= Date.now() ? <p>Evidence access has expired.</p> : <>
          {artifact.data_class === 'metadata' && ['context', 'pod-status'].includes(artifact.kind) && <SavedPodStatus session={session} scope={scope} caseID={caseID} artifactID={artifact.artifact_id}/>}
          {state.details?.case.access !== 'shared' && <>
            <Button className="button" isDisabled={state.busy || pending} onPress={() => void controller.prepare(artifact)}>Download</Button>
            <SharePanel session={session} scope={scope} caseID={caseID} artifact={artifact} preview={<>
              <p className="selected-name">{kindName(artifact.kind)}</p><p className="field-help">{classLine(artifact)}</p>
              <Handling artifact={artifact}/>
              {artifact.data_class === 'metadata' && ['context', 'pod-status'].includes(artifact.kind) && <p>The saved pod-status details, as shown above.</p>}
            </>}/>
          </>}
        </>}
        {pending && state.preparingArtifact !== artifact.artifact_id && <p className="field-help">Finish the current download request before preparing another file.</p>}
      </section>)}
      <p className="notice">Downloaded copies are outside Asservat's automatic deletion. Follow your organization's handling and deletion policy.</p>
    </>}
      {pending && <section className="review-section" aria-label="Native download" aria-busy={state.busy}>
        {state.uncertain && <>
          <h2>Confirming the download request</h2><p>The request may have been accepted. Keep this tab open; retry uses the same request and reservation.</p>
          <Button className="button" isDisabled={state.busy} onPress={() => void controller.retryPreparation()}>Retry same download request</Button>
        </>}
        {state.cancellation && <>
          <h2 role="status">{state.cancellation.state === 'Cancelled' ? 'Download cancelled' : 'Download already ended'}</h2>
          <p>This download cannot be started or resumed. Copies already received remain outside Asservat.</p>
          {state.cancellation.audit_state !== 'recorded' && <p className="field-help">The stop is enforced. {state.cancellation.audit_state === 'overdue' ? 'Its audit needs administrator attention.' : 'Its audit confirmation is pending.'}</p>}
          <Button className="button secondary" isDisabled={state.busy} onPress={controller.newDownload}>Return to evidence</Button>
        </>}
        {download && <>
          <h2 aria-live="polite">{state.cancelling && !terminal.has(download.state) ? 'Confirming cancellation' : states[download.state]}</h2>
          {download.state === 'Preparing' && <p>Asservat is verifying the native file. Size, format and checksum appear when preparation finishes.</p>}
          {download.filename !== undefined && <dl className="facts"><dt>Native file</dt><dd>{download.filename}</dd><dt>Format</dt><dd>{download.native_format}</dd><dt>Size</dt><dd>{bytes(download.size_bytes!)}</dd><dt>SHA-256</dt><dd className="identifier">{download.sha256}</dd><dt>Coverage</dt><dd>{download.coverage_notice}</dd></dl>}
          <p>Download access ends {date(download.expires_at)}. Managed evidence access ends {date(download.managed_read_until)}.</p>
          {download.state === 'Completed' && <>
            <p>The server recorded the transfer. Check the file saved by your browser; Asservat cannot confirm local disk storage.</p>
            <p>{download.sha256 ? 'Verify the saved file against the SHA-256 shown above before relying on it.' : 'Native file details and checksum are unavailable in this transfer status.'}</p>
          </>}
          {download.state === 'Interrupted' && <p>Starting again downloads the whole file and may use more transfer allowance. A compatible authenticated client can resume a partial file when permitted.</p>}
          {controller.canStart() && <a className="button" href={download.content_path} download={download.filename} onClick={event => { if (!controller.canStart()) { event.preventDefault(); void controller.checkDownload(); } else controller.startDownload(); }}>{download.state === 'Interrupted' ? 'Download again from beginning' : 'Download native file'}</a>}
          {state.started && <p role="status">Download requested in your browser. Check its downloads for the saved file.</p>}
          {terminal.has(download.state) && <Button className="button secondary" isDisabled={state.busy} onPress={controller.newDownload}>Return to evidence</Button>}
        </>}
        {controller.canRestart() && <>
          <p>Starts the browser download from the beginning and stops the previous request. Both attempts count toward your download limit.</p>
          <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.restartDownload()}>Start a new download</Button>
        </>}
        {state.cancelling && (!download || !terminal.has(download.state)) && <p role="status">Cancellation is not yet confirmed. Retry cancellation uses the original request; it does not start a new download.</p>}
        {(!state.uncertain || controller.canCancel()) && !state.cancellation && (!download || !terminal.has(download.state)) && <div className="actions">
          <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.checkDownload()}>Check download status</Button>
          <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.cancel()}>{state.cancelling ? 'Retry cancellation' : 'Cancel download'}</Button>
        </div>}
      </section>}
    {state.details && <>
      {state.details.timeline.length > 0 && <details className="retention-edit"><summary>Collection timeline</summary><ul>{state.details.timeline.map((event, index) => <li key={index}><time dateTime={event.time}>{date(event.time)}</time> — {event.summary}{event.clock_uncertainty_ms ? ` (clock uncertainty up to ${event.clock_uncertainty_ms} ms)` : ''}</li>)}</ul></details>}
      <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.refresh()}>Refresh evidence details</Button>
    </>}
  </div>;
}
