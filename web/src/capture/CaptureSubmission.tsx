import { useState } from 'react';
import { Button } from 'react-aria-components';
import { requestablePreview, type Investigation, type State } from './investigation';
import type { Input, Preview } from './http';

type AccessOperation = NonNullable<Preview['result_access_actions']>[number]['operations'][number];
const operationOrder: AccessOperation[] = ['download_artifact', 'pcap_query', 'syscall_query'];
const queryOperation = (operation: AccessOperation) => operation === 'pcap_query' || operation === 'syscall_query';

type Props = { preview: Preview; state: State; controller: Investigation };
// Choices come from the reviewed server plan. They describe available options;
// the submission and reviewer still check the exact actor, actions and scope.
export function CaptureSubmission({ preview, state, controller }: Props) {
  const choices = preview.result_access_actions ?? [];
  const [include, setInclude] = useState(false);
  const [mode, setMode] = useState<'download' | 'query' | 'both'>('download');
  const [selected, setSelected] = useState(choices.map(choice => choice.action_id));
  const [maxBytes, setMaxBytes] = useState(Math.max(1, preview.max_bytes));
  const [seconds, setSeconds] = useState(3600);
  const [maxOperations, setMaxOperations] = useState(100);
  const enabled = (operation: AccessOperation, selectedMode: typeof mode) => selectedMode === 'download' ? operation === 'download_artifact' : selectedMode === 'query' ? queryOperation(operation) : true;
  const eligible = choices.filter(choice => choice.operations.some(operation => enabled(operation, mode)));
  const chosen = eligible.filter(choice => selected.includes(choice.action_id));
  const operations = operationOrder.filter(operation => enabled(operation, mode) && chosen.some(choice => choice.operations.includes(operation)));
  const packetQueries = choices.some(choice => choice.operations.includes('pcap_query'));
  const syscallQueries = choices.some(choice => choice.operations.includes('syscall_query'));
  const queryLabel = packetQueries && syscallQueries ? 'Saved packet and syscall argument queries' : syscallQueries ? 'Saved syscall argument queries' : 'Saved packet queries';
  const invalid = include && (!chosen.length || mode === 'both' && (!operations.includes('download_artifact') || !operations.some(queryOperation)) || !Number.isSafeInteger(maxBytes) || maxBytes < (mode === 'query' ? 24576 : 1) || maxBytes > 274877906944 || !Number.isInteger(seconds) || seconds < 1 || seconds > 28800 || !Number.isInteger(maxOperations) || maxOperations < 1 || maxOperations > 10000);
  const changeMode = (next: typeof mode) => {
    setMode(next);
    const nextChoices = choices.filter(choice => choice.operations.some(operation => enabled(operation, next)));
    const queryChoices = nextChoices.filter(choice => choice.operations.some(queryOperation));
    setSelected(nextChoices.map(choice => choice.action_id));
    setMaxBytes(Math.max(1, (next !== 'query' ? preview.max_bytes : 0) + (next !== 'download' ? queryChoices.length * 49152 : 0)));
  };
  const label = (id: string) => {
    const source = preview.profile_composition?.actionMap.find(action => action.actionID === id);
    return source ? `${source.componentID} / ${source.localActionID}` : id;
  };
  const submit = () => {
    if (state.expired) { void controller.preview(); return; }
    if (invalid) return;
    const access: Input<'request_capture'>['result_access'] = include ? {
      actionIds: chosen.map(choice => choice.action_id), operations, maxArtifacts: chosen.length,
      maxBytes, maxOperations, notAfter: new Date(Date.now() + seconds * 1000).toISOString(),
    } : undefined;
    void controller.submit(access);
  };
  return <div>
    {choices.length > 0 && <fieldset disabled={state.busy}>
      <legend>Follow-up access for you</legend>
      <label><input type="checkbox" checked={include} onChange={event => setInclude(event.target.checked)}/>Include follow-up access in this approval</label>
      {include && <>
        <p>The same independent review covers collection and your selected result access through this browser client. Current permissions, source retention and expiry still apply. This grants no sharing rights.</p>
        <label>Follow-up operations<select value={mode} onChange={event => changeMode(event.target.value as typeof mode)}>
          <option value="download">Whole-file downloads</option>
          {(packetQueries || syscallQueries) && <><option value="query">{queryLabel}</option><option value="both">Downloads and {queryLabel.toLowerCase()}</option></>}
        </select></label>
        {eligible.map(choice => <label key={choice.action_id}><input type="checkbox" checked={selected.includes(choice.action_id)} onChange={event => setSelected(event.target.checked ? [...selected, choice.action_id] : selected.filter(id => id !== choice.action_id))}/>{label(choice.action_id)}</label>)}
        <label>Shared disclosure byte budget<input type="number" min={mode === 'query' ? 24576 : 1} max={274877906944} step={1} value={maxBytes} onChange={event => setMaxBytes(Number(event.target.value))}/></label>
        <label>Follow-up operation limit<input type="number" min={1} max={10000} step={1} value={maxOperations} onChange={event => setMaxOperations(Number(event.target.value))}/></label>
        <label>Follow-up access period in seconds<input type="number" min={1} max={28800} step={1} value={seconds} onChange={event => setSeconds(Number(event.target.value))}/></label>
        <p>Only the selected published results can use this shared pool. Each paid query page reserves 24 KiB and one operation, including a lost reply; a query permits at most two paid pages. Downloads spend their transferred bytes. Query-only access need not cover the whole native file.</p>
      </>}
    </fieldset>}
    <Button className="button" isDisabled={state.busy || (!state.expired && (!requestablePreview(preview) || invalid))} onPress={submit}>{state.busy ? 'Checking…' : state.expired ? 'Refresh review' : preview.approval_required ? 'Request approval' : preview.profile_composition ? 'Collect evidence' : 'Collect pod status'}</Button>
  </div>;
}
