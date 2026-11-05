import { useEffect, useState, useSyncExternalStore } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Artifact } from '../evidence/http';
import type { Operations as ApprovalOperations } from '../approvals/http';
import { RawAccessPanel } from '../evidence/RawAccessPanel';
import { PacketQuery, packetFields, type PacketField, type PacketQuerySource } from './packet-query';

type Props = { controller: PacketQuery; session: Session; scope: AbortSignal; caseID: string; artifact: Artifact; approvalClient?: ApprovalOperations };
const defaults: PacketField[] = ['packet_index', 'packet_time', 'source_address', 'destination_address', 'source_port', 'destination_port', 'protocol'];
const number = (text: string) => text.trim() ? Number(text) : NaN;
export function PacketQueryView(props: Props) {
  return <SavedPacketQuery key={JSON.stringify([props.caseID, props.artifact.artifact_id, props.artifact.digest, props.artifact.data_class])} {...props}/>;
}
function SavedPacketQuery({ controller, session, scope, caseID, artifact, approvalClient }: Props) {
  const raw = artifact.data_class === 'raw';
  const source: PacketQuerySource = { caseID, artifactID: artifact.artifact_id, version: artifact.digest, captureMode: raw ? 'rawPackets' : 'networkHeaders' };
  const snapshot = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const attached = controller.isAttachedTo(session, scope, source);
  const state = attached ? snapshot : { phase: 'idle' as const };
  useEffect(() => controller.attach(session, scope, source), [controller, session, scope, caseID, artifact.artifact_id, artifact.digest, raw]);
  const [fields, setFields] = useState<PacketField[]>(defaults);
  const [filter, setFilter] = useState(''); const [start, setStart] = useState(''); const [end, setEnd] = useState('');
  const [packets, setPackets] = useState('100'); const [scan, setScan] = useState('8388608');
  const [flags, setFlags] = useState(false); const [mask, setMask] = useState('18'); const [value, setValue] = useState('16');
  const [offset, setOffset] = useState('0'); const [length, setLength] = useState('64');
  const [grant, setGrant] = useState<{ id: string; session: Session; scope: AbortSignal }>();
  const [error, setError] = useState('');
  const grantID = grant?.session === session && grant.scope === scope && !scope.aborted ? grant.id : undefined;
  const changed = () => { controller.close(); setError(''); };
  const busy = state.phase === 'loading'; const result = state.result;
  return <section aria-label="Saved packet query" aria-busy={busy}>
    <h3>Query saved packets</h3>
    <p>Inspect selected fields from this saved artifact. Filters use the supported tcpdump/libpcap syntax, with numeric addresses and ports. Wireshark display filters, names and bracket predicates are not supported.</p>
    {raw && <>
      <p>Every query over raw packets requires packet-query approval, including header-only selections. Returned bytes may contain user data. This does not grant native download access.</p>
      <RawAccessPanel session={session} scope={scope} caseID={caseID} artifacts={[artifact]} prefilledArtifactID={artifact.artifact_id} purpose="packet-query" onGrant={id => setGrant({ id, session, scope })} client={approvalClient}/>
      {grantID && <p role="status">Packet-query approval is available. Current access and its remaining allowance are checked when you run.</p>}
    </>}
    <form onSubmit={event => { event.preventDefault(); if (raw && !grantID) { setError('Obtain packet-query approval before running.'); return; } setError(''); void controller.run({ fields, max_packets: number(packets), max_scan_bytes: number(scan), ...(filter ? { packet_filter: filter } : {}), ...(start ? { start_time: start } : {}), ...(end ? { end_time: end } : {}), ...(flags ? { tcp_flags: { mask: number(mask), value: number(value) } } : {}), ...(fields.includes('frame_prefix_hex') ? { frame_prefix: { offset: number(offset), length: number(length) } } : {}), ...(raw ? { grant_id: grantID } : {}) }); }}>
      <fieldset disabled={busy}><legend>Packet query selection</legend>
        <label>tcpdump/libpcap packet filter<input value={filter} maxLength={512} placeholder="tcp and port 443" onChange={event => { changed(); setFilter(event.target.value); }}/></label>
        <fieldset><legend>Fields in result order</legend>{packetFields.filter(field => raw || field !== 'frame_prefix_hex').map(field => <label key={field}><input type="checkbox" checked={fields.includes(field)} onChange={() => { changed(); setFields(previous => previous.includes(field) ? previous.filter(f => f !== field) : [...previous, field]); }}/>{field}</label>)}</fieldset>
        <label>Start packet time (UTC, optional)<input value={start} placeholder="2026-11-05T12:00:00Z" onChange={event => { changed(); setStart(event.target.value); }}/></label>
        <label>End packet time (UTC, exclusive, optional)<input value={end} placeholder="2026-11-05T12:01:00Z" onChange={event => { changed(); setEnd(event.target.value); }}/></label>
        <label>Maximum returned records<input type="number" min="1" max="100" required value={packets} onChange={event => { changed(); setPackets(event.target.value); }}/></label>
        <label>Maximum saved bytes to scan<input type="number" min="1" max="1073741824" required value={scan} onChange={event => { changed(); setScan(event.target.value); }}/></label>
        <label><input type="checkbox" checked={flags} onChange={event => { changed(); setFlags(event.target.checked); }}/>Filter TCP flags</label>
        {flags && <><label>TCP flag mask<input type="number" min="1" max="511" required value={mask} onChange={event => { changed(); setMask(event.target.value); }}/></label><label>TCP flag value<input type="number" min="0" max="511" required value={value} onChange={event => { changed(); setValue(event.target.value); }}/></label><p className="field-help">Match (flags &amp; mask) = value. FIN 1, SYN 2, RST 4, PSH 8, ACK 16, URG 32, ECE 64, CWR 128, NS 256. Incomplete and non-TCP headers do not match.</p></>}
        {raw && fields.includes('frame_prefix_hex') && <><label>Saved-frame byte offset<input type="number" min="0" max="1499" required value={offset} onChange={event => { changed(); setOffset(event.target.value); }}/></label><label>Saved-frame byte length<input type="number" min="1" max="64" required value={length} onChange={event => { changed(); setLength(event.target.value); }}/></label><p className="field-help">Offsets start at the captured frame, not an inferred payload start. Offset plus length must be at most 1500. Missing bytes are unavailable; short prefixes are not padded.</p></>}
      </fieldset>
      <p className="field-help">Scan work counts captured bytes of all visited records, including nonmatches. The remaining saved file is still verified before any result appears. Editing closes the current view.</p>
      <Button type="submit" className="button secondary" isDisabled={!attached || busy || ['pending', 'uncertain'].includes(state.phase) || raw && !grantID || !fields.length}>Run packet query</Button>
    </form>
    {error && <p role="alert">{error}</p>}
    {state.phase === 'loading' && <p role="status">Checking access and querying the saved packets…</p>}
    {state.phase === 'pending' && <><p role="status">The original packet query is being prepared.</p><Button className="button secondary" isDisabled={!state.canCheck} onPress={() => void controller.check()}>Check packet query</Button></>}
    {state.phase === 'uncertain' && <><p role="alert">The query response was not received. It may already be charged. Retry the same request to recover its original query; editing starts a separate query.</p><Button className="button secondary" onPress={() => void controller.retryBegin()}>Retry same packet query</Button></>}
    {state.phase === 'expired' && <p role="status">This packet query view has expired. Run explicitly to request a fresh view.</p>}
    {state.phase === 'unavailable' && <p role="alert">The packet query is unavailable. Check the supported filter, fields, time bounds and any required approval.</p>}
    {state.phase === 'result' && result && <>
      <dl className="facts"><dt>Visited saved records</dt><dd>{result.scanned_packets.toLocaleString()}</dd><dt>Captured bytes scanned</dt><dd>{result.scanned_bytes.toLocaleString()}</dd></dl>
      <p>Packet timestamps and saved prefixes do not establish clock accuracy or complete network coverage. Unavailable fields are not zero. TCP sequence, acknowledgement and window values are the stored values, without stream reconstruction or inferred scaling.</p>
      {result.row_limit_reached && <p>The returned-record limit stopped logical scanning; additional matches are unknown.</p>}
      {result.scan_limit_reached && <p>The captured-byte scan limit stopped logical scanning; additional matches are unknown.</p>}
      {result.output_limit_reached && <p>The output-size limit stopped logical scanning; additional matches are unknown.</p>}
      {result.rows.length ? <table className="profile-summary" aria-label="Saved packet query rows"><thead><tr>{result.fields.map(field => <th key={field} scope="col">{field}</th>)}</tr></thead><tbody>{result.rows.map((row, index) => <tr key={index}>{row.map((cell, column) => <td key={column}>{cell === null ? 'Unavailable' : cell}</td>)}</tr>)}</tbody></table> : <p>No matching records were returned within this scan.</p>}
      {state.warnings?.map((warning, i) => <p key={i}>{warning}</p>)}
    </>}
    {state.phase !== 'idle' && <Button className="button secondary" onPress={controller.close}>Close packet query</Button>}
  </section>;
}
