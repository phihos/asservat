import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Target } from '../capture/http';
import { Recordings, type Repeat } from './recordings';
import type { SavePreview } from './http';

const names: Record<string, string> = { packetCapture: 'Packet recording', syscallTrace: 'Syscall recording' };
const blockers: Record<string, string> = {
  NoHistoryConfigured: 'This source has no configured history. Choose an ordinary future capture separately.',
  SourceExpired: 'The original source authority has expired. Refresh to check current recordings.',
};
function seconds(value: number) { return `${value.toLocaleString()} seconds`; }
function SaveAssessment({ preview }: { preview: SavePreview }) {
  return <section className="review-section" aria-label="Recording save review">
    <h3>Save the selected history</h3>
    <p>{preview.capture_assessment.combinedImpact.explanation}</p>
    <p>The continuing recorder has its own limits. This save adds snapshot copying, encryption and upload; its configured limits do not measure overhead.</p>
    <ul>{preview.windows.map(window => <li key={window.recording_handle}>Save the last {window.before} of {preview.selected_recordings.find(row => row.recording_handle === window.recording_handle)?.pod_name}, ending at the first successful acceptance. No future window is added.</li>)}</ul>
    {preview.capture_assessment.actions.map(action => <div key={action.recording_handle ?? action.actionID}>
      <h4>{action.actionID}{action.recording_handle && <> · {preview.selected_recordings.find(row => row.recording_handle === action.recording_handle)?.pod_name}</>}</h4>
      <p>Possible retained user data: {action.data.retainedPossible.map(value => value.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()).join(', ') || 'See the current data assessment'}.</p>
      {action.data.transientOnly.length > 0 && <p>Processing may transiently expose {action.data.transientOnly.map(value => value.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()).join(', ')}.</p>}
      <dl className="facts"><dt>Evidence access</dt><dd>Up to {seconds(action.retention.accessAgeSeconds)} from original source acquisition.</dd><dt>Managed deletion</dt><dd>Within {seconds(action.retention.deleteAgeSeconds)} of original source acquisition.</dd></dl>
      {action.quantities.filter(quantity => quantity.dimension === 'outputBytes').map((quantity, index) => <p key={index}>Output bound: {quantity.upper.toLocaleString()} bytes ({quantity.basis === 'configuredLimit' ? 'configured limit' : quantity.basis}). {quantity.coverage}</p>)}
    </div>)}
    <p>Retention already counts the age of saved source data. Current rules and the original source audience still apply. Policy recurring sharing instructions are not inherited. Asservat cannot delete downloaded local copies.</p>
    <p>The preview does not pin history or reserve capacity. Rotation or network delay may produce missing coverage. The saved interval ends at the server’s actual acceptance time, which a retry cannot change.</p>
    <p>Preview expires at {new Date(preview.expires_at).toLocaleTimeString()}.</p>
    {preview.blockers.map(code => <p className="notice" key={code}>{blockers[code] ?? code}</p>)}
    {!preview.capture_enabled && <p className="notice">Saving is not enabled for this client. An administrator can check the installation settings.</p>}
  </section>;
}

export function RecordingsPanel({ session, scope, target, repeat, submit, controller: provided }: {
  session: Session; scope: AbortSignal; target: Target; repeat?: Repeat;
  submit: (previewID: string, captureID: string, expiresAt: string) => Promise<void>;
  controller?: Recordings;
}) {
  const [owned] = useState(() => new Recordings());
  const controller = provided ?? owned;
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const targetKey = JSON.stringify(target), repeatKey = JSON.stringify(repeat);
  useEffect(() => controller.attach(session, scope, target, repeat), [controller, session, scope, targetKey, repeatKey]);
  const caps = state.selected.length ? state.selected.map(row => row.incident_pod_cap) : state.rows?.map(row => row.incident_pod_cap) ?? [];
  const cap = caps.length && (state.selected.length > 0 || new Set(caps).size === 1) ? Math.min(...caps) : undefined;
  return <section className="recordings-panel" aria-labelledby="recordings-heading" aria-busy={state.busy}>
    <h2 id="recordings-heading">Save existing recordings now</h2>
    <p>{target.kind} <strong>{target.namespace} / {target.name}</strong></p>
    {repeat && <p className="notice">Choose current sources to repeat capture {repeat.captureID}. Old handles, sharing instructions and source epochs are not reused.</p>}
    <p>Choose already authorized recordings from one policy. This saves their retained window; it does not run the policy’s other actions.</p>
    {cap !== undefined && <p>Current incident limit: {cap} {cap === 1 ? 'pod' : 'pods'}, up to 16 sources. Selection is never reduced silently.</p>}
    {state.error && <p role="alert" className="notice">{state.error}</p>}
    {state.expired && <p role="status">The recording selection expired. Refresh to select current sources.</p>}
    {!state.rows && state.busy && <p role="status">Checking eligible recordings…</p>}
    {state.rows?.length === 0 && <p>No eligible recordings are available for this target.</p>}
    {state.rows && state.rows.length > 0 && <fieldset disabled={state.busy}><legend>Current recording sources</legend>
      {state.rows.map((row, index) => <article className="diagnostic" key={row.recording_handle ?? `${row.policy_uid}:${row.pod_uid}:${row.action_id}:${index}`}>
        <label><input type="checkbox" checked={state.selected.some(selected => selected.recording_handle === row.recording_handle)} disabled={!row.recording_handle || !row.save_eligible || row.blockers.length > 0 || state.expired} onChange={event => { controller.select(row, event.currentTarget.checked); if (controller.snapshot().selected.length > 0 && !controller.snapshot().error) void controller.review(); }}/> {row.pod_name} · {row.action_id}</label>
        <p>{names[row.kind] ?? row.kind} · policy {row.policy_uid}</p>
        <p>Source state: {row.state}. History: {row.history}. Configured maximum lookback: {row.maximum_before}. Incident pod cap: {row.incident_pod_cap}.</p>
        {row.history === 'Unknown' && <p>Available history and gaps have not been measured. A running source or this list is not proof of complete coverage.</p>}
        {row.blockers.map(code => <p className="notice" key={code}>{blockers[code] ?? code}</p>)}
      </article>)}
    </fieldset>}
    {state.rows && !state.captureEnabled && <p className="notice">Saving is not enabled for this client. Inventory does not grant permission to collect.</p>}
    {state.expiresAt && <p className="field-help">These source handles expire at {new Date(state.expiresAt).toLocaleTimeString()}. They do not reserve retained history.</p>}
    {state.selected.length > 0 && <form onSubmit={event => { event.preventDefault(); void controller.review(); }}>
      <fieldset disabled={state.busy}><legend>Save window</legend>
        <label>Shorter lookback (optional)<input value={state.before} maxLength={16} placeholder="Policy-configured maximum" onChange={event => controller.setBefore(event.currentTarget.value)}/></label>
        <p className="field-help">For example, 10s. Leave empty to use each source’s configured lookback. Only a shorter positive window is allowed.</p>
        {(!state.preview || state.before !== '') && <Button className="button" type="submit" isDisabled={state.busy || !state.captureEnabled || state.expired}>Review save</Button>}
        <Button className="button secondary" onPress={controller.clear}>Clear selection</Button>
      </fieldset>
    </form>}
    {state.preview && <><SaveAssessment preview={state.preview}/><Button className="button" isDisabled={!controller.submittable} onPress={() => void controller.save(submit)}>{state.preview.windows.length === 1 ? `Save last ${state.preview.windows[0].before} now` : 'Save selected recordings now'}</Button></>}
    <div className="actions"><Button className="button secondary" isDisabled={state.busy} onPress={() => void controller.load()}>Refresh recordings and clear selection</Button>
      {state.cursor && <Button className="button secondary" isDisabled={state.busy || state.selected.length > 0} onPress={() => void controller.load(state.cursor)}>Next recordings</Button>}
    </div>
    {state.cursor && state.selected.length > 0 && <p>Clear the current selection before moving to the next page.</p>}
  </section>;
}
