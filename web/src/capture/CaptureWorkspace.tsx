import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { Investigation, type State } from './investigation';
import type { HistoryEntry, Preview, Progress, Target } from './http';
import { captureIDFromPath } from '../routes';
import { WhyAccess } from '../access/WhyAccess';
import { RecipientsEditor } from '../sharing/SharePanel';

const phases: Record<Progress['phase'], string> = {
  Pending: 'Waiting to start', Validating: 'Checking the request', AwaitingApproval: 'Waiting for approval',
  Armed: 'Ready for a trigger', Queued: 'Waiting for capacity', Running: 'Collecting evidence',
  Finalizing: 'Verifying and publishing evidence', Succeeded: 'Collection complete', Partial: 'Partially complete',
  Failed: 'Collection failed', Cancelled: 'Collection cancelled', Indeterminate: 'Collection outcome is uncertain',
};
function duration(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400} ${seconds === 86400 ? 'day' : 'days'}`;
  if (seconds % 3600 === 0) return `${seconds / 3600} ${seconds === 3600 ? 'hour' : 'hours'}`;
  if (seconds % 60 === 0) return `${seconds / 60} ${seconds === 60 ? 'minute' : 'minutes'}`;
  return `${seconds} seconds`;
}
const exposureNames: Record<string, string> = {
  personalIdentifiers: 'identifiers', networkAddresses: 'network addresses', paths: 'paths',
  userContent: 'user content', credentials: 'credentials', unknownApplicationData: 'other application data',
};
function exposures(values: string[]) { return values.map(value => exposureNames[value] ?? value).join(', '); }

function Assessment({ preview }: { preview: Preview }) {
  const assessment = preview.capture_assessment;
  const pod = preview.selected_pods![0];
  const action = assessment.actions[0];
  return <>
    <section className="review-section" aria-labelledby="scope-heading">
      <h2 id="scope-heading">Selected pod</h2>
      <p className="selected-name">{pod.namespace} / {pod.name}</p>
      <p>{preview.pod_selection === 'explicitPod' ? 'This is the pod you selected.' : 'The first eligible pod by name was selected. This snapshots one pod, not every replica.'} It will not be replaced silently if it disappears.</p>
      <details><summary>Exact identity</summary><dl className="facts">
        <dt>Cluster</dt><dd>{pod.cluster_id}</dd><dt>Pod UID</dt><dd>{pod.uid}</dd>
        <dt>Owning workload</dt><dd>{pod.workload.kind} {pod.workload.name}</dd><dt>Workload UID</dt><dd>{pod.workload.uid}</dd>
      </dl></details>
    </section>
    <section className="review-section" aria-labelledby="impact-heading">
      <h2 id="impact-heading">Workload impact</h2>
      <p>{assessment.combinedImpact.explanation}</p>
      <p>Saved status is limited to 4 KiB. This is an output limit, not a prediction of memory use or overhead. No application process is started.</p>
    </section>
    <section className="review-section" aria-labelledby="handling-heading">
      <h2 id="handling-heading">Data and deletion</h2>
      <p>Saved metadata may include {exposures(action.data.retainedPossible)}. Treat it as potentially sensitive user data.</p>
      {action.data.transientOnly.length > 0 && <p>The API response can also expose {exposures(action.data.transientOnly)} to the collector during processing. These fields are excluded from the saved status projection.</p>}
      <dl className="facts"><dt>Evidence access</dt><dd>Up to {duration(action.retention.accessAgeSeconds)} after submission. Time waiting for collection counts toward this limit.</dd>
        <dt>Managed deletion</dt><dd>Within {duration(action.retention.deleteAgeSeconds)} of that same submission.</dd></dl>
      <p>Administrator limits may shorten access. {action.retention.preservationException !== 'none' && 'An authorized preservation exception may apply. '}Asservat cannot delete copies downloaded to local tools. Restrict access and review evidence before sharing.</p>
    </section>
  </>;
}

const sharingLabels: Record<NonNullable<Progress['sharing']>['state'], string> = {
  Pending: 'The result will be shared with your recipients when it is published.',
  Shared: 'The result is shared with your recipients. Send them the case link.',
  SharingUnavailable: 'The result was not shared. You can still share it from the case page.',
};

const actionLabels: Record<string, string> = { Finalizing: 'Verifying and publishing', TargetGone: 'The selected Pod no longer exists; nothing was collected', Denied: 'Kubernetes denied reading the Pod status; nothing was collected' };
const evidenceLabels: Record<HistoryEntry['evidence_state'], string> = {
  pending: 'Evidence pending', available: 'Evidence available', partial: 'Partial evidence', expired: 'Evidence expired', unavailable: 'No evidence',
};

// Recent captures of this target (ADR-236). "Collect again" restores the
// capture's target and requested retention into a new review; the server
// rechecks current access, limits and the selected pod.
function RecentCaptures({ state, controller }: { state: State; controller: Investigation }) {
  return <section className="review-section" aria-labelledby="recent-heading" aria-busy={state.history === undefined && !state.historyMessage}>
    <h2 id="recent-heading">Recent captures</h2>
    {state.historyMessage ? <p className="notice">{state.historyMessage}</p>
      : state.history === undefined ? <p role="status">Loading recent captures…</p>
      : state.history.length === 0 ? <p>No captures of this target in the last 7 days that you can see.</p>
      : <ul className="recent-captures">{state.history.map(entry => <li key={entry.capture_id}>
        <span><a href={'/captures/' + entry.capture_id}>{new Date(entry.accepted_at).toLocaleString()}</a> · {phases[entry.phase]} · {evidenceLabels[entry.evidence_state]}</span>
        {entry.repeat_state === 'available' && <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.repeat(entry.capture_id)}>Collect again</Button>}
      </li>)}</ul>}
    <p className="field-help">Shows the last 7 days of your own requests and of requests your team could access when they were made. Collecting again reviews the same settings with your current access and limits; nothing is collected until you confirm.</p>
  </section>;
}


export function CaptureWorkspace({ session, scope, controller }: { session: Session; scope: AbortSignal; controller: Investigation }) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [customRetention, setCustomRetention] = useState(false);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => controller.attach(session, scope, captureIDFromPath(window.location.pathname)), [controller, session, scope]);
  const draft = state.draft;
  const setTarget = (key: keyof Target, value: string) => controller.setDraft({ ...draft, target: { ...draft.target, [key]: value } });
  const title = state.stage === 'review' ? 'Review collection' : state.stage === 'reviewed' ? 'Continue your reviewed request' : state.stage === 'progress' ? 'Collection progress' : state.stage === 'uncertain' ? 'Confirming your request' : state.stage === 'closed' ? 'Request closed' : 'Collect evidence';
  useEffect(() => { heading.current?.focus(); }, [state.stage]);
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>{title}</h1>
      {state.stage === 'target' && <p>Choose a production workload or pod, then review the available diagnostics before collecting. To collect automatically on restarts, use <a href="/policies">automatic policies</a>. See <a href="/shares">shared evidence</a>.</p>}
    </div>
    {state.error && <p role="alert" className="notice">{state.error}</p>}
    {state.error && (state.stage === 'target' || state.stage === 'diagnostics' || state.stage === 'review') && draft.target.name && <WhyAccess key={JSON.stringify(draft.target)} session={session} scope={scope} target={draft.target} operation="capture"/>}
    {state.stage === 'target' && <form onSubmit={event => { event.preventDefault(); void controller.discover(); }} aria-busy={state.busy}>
      <fieldset disabled={state.busy}><legend>Target</legend>
        <label>Cluster ID<input name="cluster" value={draft.target.cluster_id} required maxLength={36} pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" placeholder="Registered cluster UUID" onChange={event => setTarget('cluster_id', event.target.value)} autoComplete="off" spellCheck={false}/></label>
        <p className="field-help">Use the cluster ID supplied by your administrator.</p>
        <div className="form-row"><label>Namespace<input name="namespace" value={draft.target.namespace} required maxLength={63} onChange={event => setTarget('namespace', event.target.value)} autoComplete="off" spellCheck={false}/></label>
          <div className="field"><label htmlFor="target-kind">Kind</label><select id="target-kind" value={draft.target.kind} onChange={event => setTarget('kind', event.target.value)}><option>Deployment</option><option>StatefulSet</option><option>Pod</option></select></div></div>
        <label>Workload or pod name<input name="workload" value={draft.target.name} required maxLength={253} onChange={event => setTarget('name', event.target.value)} autoComplete="off" spellCheck={false}/></label>
        <details className="retention-edit"><summary>Change evidence retention</summary>
          <div className="field"><label htmlFor="retention-duration">Requested access duration</label><select id="retention-duration" value={customRetention || !['', '900', '3600', '86400'].includes(draft.retention) ? 'custom' : draft.retention} onChange={event => { setCustomRetention(event.target.value === 'custom'); if (event.target.value !== 'custom') controller.setDraft({ ...draft, retention: event.target.value }); }}><option value="">Administrator default</option><option value="900">15 minutes</option><option value="3600">1 hour</option><option value="86400">1 day</option><option value="custom">Custom duration</option></select></div>
          {(customRetention || !['', '900', '3600', '86400'].includes(draft.retention)) && <label>Custom duration (seconds)<input name="retention" type="number" min="1" max="315360000" step="1" placeholder="Administrator default" value={draft.retention} onChange={event => controller.setDraft({ ...draft, retention: event.target.value })}/></label>}
          <p className="field-help">The review shows the effective access and deletion limits. Administrator policy can require a shorter duration.</p>
        </details>
        <details className="retention-edit"><summary>Share results with…</summary>
          <p>When the capture is published, its result is shared with these users or groups of your identity provider ({session.principal.issuer}), using their stable IDs. Sharing needs the evidence-owner role on the workload; without it the request is refused before anything is collected.</p>
          <RecipientsEditor recipients={draft.sharing ?? []} onChange={sharing => controller.setDraft({ ...draft, sharing })}/>
          <label>Share for (hours)<input name="share-hours" type="number" min={1} max={168} step={1} placeholder="24 after publication" value={draft.shareHours ?? ''} onChange={event => controller.setDraft({ ...draft, shareHours: Number.isNaN(event.target.valueAsNumber) ? undefined : event.target.valueAsNumber })}/></label>
          <p className="field-help">Empty: 24 hours after publication. At most seven days from now, and never past the evidence's access.</p>
        </details>
        <Button type="submit" className="button" isDisabled={state.busy}>{state.busy ? 'Checking diagnostics…' : 'Find diagnostics'}</Button>
      </fieldset>
    </form>}
    {state.stage === 'diagnostics' && <section aria-label="Available diagnostics" aria-busy={state.busy}>
      <p>{draft.target.kind} <strong>{draft.target.namespace} / {draft.target.name}</strong></p>
      {state.diagnostics?.length === 0 && <p>No diagnostics are available for this target.</p>}
      {state.diagnostics?.map((diagnostic, index) => <article className="diagnostic" key={index}>
        <h2>{diagnostic.name}</h2><p>{diagnostic.description}</p>
        {diagnostic.blockers.map((blocker, index) => <p className="notice" key={index}>{blocker.message}</p>)}
        <Button className="button" isDisabled={state.busy || diagnostic.preset_ref?.name !== 'pod-status'} onPress={() => void controller.preview(diagnostic)}>{state.busy ? 'Preparing review…' : 'Review collection'}</Button>
      </article>)}
      <Button className="button secondary" isDisabled={state.busy} onPress={controller.edit}>Change target</Button>
      <RecentCaptures state={state} controller={controller}/>
    </section>}
    {state.stage === 'review' && state.preview && <section aria-label="Collection review" aria-busy={state.busy}>
      {state.repeatedFrom && <p className="notice">Collecting again with the settings of capture <span className="identifier">{state.repeatedFrom}</span>: the same target and requested retention. The pod, access and limits below are checked now.</p>}
      <Assessment preview={state.preview}/>
      {state.preview.blockers.map((blocker, index) => <p className="notice" key={index}>{blocker.message}</p>)}
      {state.preview.blockers.length > 0 && <WhyAccess key={JSON.stringify(draft.target)} session={session} scope={scope} target={draft.target} operation="capture"/>}
      {!state.preview.capture_enabled && state.preview.blockers.length === 0 && <p className="notice">Collection is not enabled for this client. An administrator can check the installation settings.</p>}
      {state.preview.approval_required && <p className="notice">This collection needs approval. Approval requests are not available in this console yet.</p>}
      {state.preview.warnings.map((warning, index) => <p key={index}>{warning}</p>)}
      <p role="status">{state.expired ? 'This preview has expired. Refreshing may select a different pod; check the updated selection.' : state.stale ? 'The impact assessment is older. Collection will recheck current conditions and these exact identities, and stop if the reviewed scope changed.' : 'The assessment is current. Collection rechecks your access and these exact identities.'}</p>
      <div className="actions"><Button className="button" isDisabled={state.busy || (!state.expired && (!state.preview.capture_enabled || state.preview.blockers.length > 0 || state.preview.approval_required))} onPress={() => void (state.expired ? controller.preview() : controller.submit())}>{state.busy ? 'Checking…' : state.expired ? 'Refresh review' : 'Collect pod status'}</Button>
        <Button className="button secondary" isDisabled={state.busy} onPress={controller.edit}>Edit request</Button></div>
    </section>}
    {state.stage === 'reviewed' && <section>
      <p>Your session was checked again, so the previous target details and assessment are hidden. Your original reviewed request is still held in this tab.</p>
      <p role="status">{state.expired ? 'That preview has expired. Prepare a new review before collecting.' : 'Continue to submit that same reviewed request. Asservat rechecks current access, limits and the exact selected pod before accepting it.'}</p>
      <div className="actions">{!state.expired && <Button className="button" isDisabled={state.busy} onPress={() => void controller.submit()}>Continue reviewed request</Button>}
        <Button className="button secondary" isDisabled={state.busy} onPress={controller.edit}>{state.expired ? 'Prepare new review' : 'Edit request'}</Button></div>
    </section>}
    {state.stage === 'uncertain' && <section aria-busy={state.busy}>
      <p role="status">{state.busy ? state.resolving ? 'Resolving the original request…' : 'Submitting the same bounded request…' : 'The request may have been accepted, but its outcome is not confirmed. Retrying checks the same request; it does not create another capture.'}</p>
      <p>Keep this tab open until the result is confirmed. The retry information is held only in this tab.</p>
      <p>If it was accepted, resolving opens its progress. Otherwise Asservat closes the original request so it cannot start a capture, then you can edit it.</p>
      <div className="actions"><Button className="button" isDisabled={state.busy} onPress={() => void controller.retrySubmission()}>{state.busy && !state.resolving ? 'Waiting for confirmation…' : 'Retry same request'}</Button>
        <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.resolveBeforeEditing()}>{state.resolving ? 'Resolving request…' : 'Resolve before editing'}</Button></div>
    </section>}
    {state.stage === 'closed' && <section>
      <p role="status">The original request is closed and cannot start a capture. You can edit your parameters and prepare a new review.</p>
      <Button className="button" onPress={controller.editClosedRequest}>Edit request</Button>
    </section>}
    {state.stage === 'progress' && <section aria-busy={state.busy}>
      <p className="field-help">Capture <span className="identifier">{state.captureID}</span></p>
      {state.progress ? <>
        <h2 aria-live="polite">{phases[state.progress.phase]}</h2>
        {state.progress.phase === 'Pending' && <p>Your request was accepted. Collection has not been confirmed.</p>}
        {state.progress.phase === 'Finalizing' && <p>Uploaded evidence still needs verification and publication before it is available.</p>}
        <ul className="progress-actions">{state.progress.actions.map(action => <li key={action.action_id}><span>{action.action_id === 'pod-status' ? 'Pod status' : action.action_id}</span><span>{actionLabels[action.phase] ?? action.phase}</span></li>)}</ul>
        {state.progress.blockers.map((blocker, index) => <p className="notice" key={index}>{blocker.message}</p>)}
        {state.progress.sharing && <p role="status">{sharingLabels[state.progress.sharing.state]}</p>}
        {state.progress.case_id && <p><a className="button" href={"/cases/" + state.progress.case_id}>View evidence</a></p>}
      </> : !state.error && <p role="status">Checking collection status…</p>}
      {state.canContinue && <div className="actions"><Button className="button" isDisabled={state.busy} onPress={() => void controller.continueAcquisition()}>{state.continuing ? 'Continuing collection…' : 'Continue collection'}</Button><p>Continues the original capture and checks your current access.</p></div>}
      {state.captureID && <p><a href="/captures/new">Start a new investigation</a>. This does not cancel the original collection.</p>}
      <Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.refreshProgress()}>{state.busy ? 'Checking status…' : 'Check status'}</Button>
    </section>}
  </div>;
}
