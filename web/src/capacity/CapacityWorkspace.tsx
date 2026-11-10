import { useEffect, useRef, useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import { operationMessage } from '../capture/http';
import { liveCapacityClient, validLiveCapacityInput, type LiveCapacity, type LiveCapacityClient } from './capacity-http';

const when = (value: string) => new Date(value).toLocaleString();

export function CapacityWorkspace({ session, scope, client = liveCapacityClient }: { session: Session; scope: AbortSignal; client?: LiveCapacityClient }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [clusterID, setClusterID] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [snapshot, setSnapshot] = useState<LiveCapacity>();
  useEffect(() => { heading.current?.focus(); }, []);
  const run = async () => {
    setMessage(undefined); setSnapshot(undefined);
    const input = { cluster_id: clusterID };
    if (!validLiveCapacityInput(input)) { setMessage('Enter one valid cluster ID.'); return; }
    setBusy(true);
    try {
      const result = await client.read(clusterID, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') setSnapshot(result.data);
      else if (result.status === 'error') setMessage(result.data.message);
      else setMessage('Live-view capacity is not ready yet. Try again shortly.');
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error));
    } finally { if (!scope.aborted) setBusy(false); }
  };
  const activity = snapshot ? [
    ['Active viewers', snapshot.active_viewers],
    ...(snapshot.live ? [
      ['Active cohorts', snapshot.live.cohorts], ['Scan events', snapshot.live.scan_events], ['Scan bytes', snapshot.live.scan_bytes],
      ['Scan CPU nanoseconds', snapshot.live.scan_cpu_nanos], ['Delivered rows', snapshot.live.delivered_rows],
      ['Delivered encoded bytes', snapshot.live.delivered_bytes], ['Refused cohort admissions', snapshot.live.refused_admissions],
      ['Source-loss events', snapshot.live.lost_events], ['Transport-dropped rows', snapshot.live.dropped_rows],
      ['Buffered pending rows', snapshot.live.pending_rows],
    ] : []),
  ] : [];
  const rates = snapshot ? [
    ['Scan events/second', snapshot.rates.scan_events_per_second], ['Scan bytes/second', snapshot.rates.scan_bytes_per_second],
    ['Scan CPU nanoseconds/second', snapshot.rates.scan_cpu_nanos_per_second], ['Delivered rows/second', snapshot.rates.delivered_rows_per_second],
    ['Delivered encoded bytes/second', snapshot.rates.delivered_bytes_per_second], ['Refused cohort admissions/second', snapshot.rates.refused_admissions_per_second],
    ['Source-loss events/second', snapshot.rates.lost_events_per_second], ['Transport-dropped rows/second', snapshot.rates.dropped_rows_per_second],
  ] : [];
  return <div className="capture-workspace">
    <div className="page-intro"><h1 ref={heading} tabIndex={-1}>Capacity and fairness</h1>
      <p>For fleet operators. Read content-minimized live-view runtime totals and rates for one cluster. Counters cover current node reports; rates appear only when every current live-enabled node has a valid report predecessor. No acquisition occurs and this page never polls in the background.</p>
    </div>
    <form className="review-section" onSubmit={event => { event.preventDefault(); void run(); }}>
      <label htmlFor="capacity-cluster">Cluster ID</label>
      <input id="capacity-cluster" required value={clusterID} maxLength={36} pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" onChange={event => { setClusterID(event.currentTarget.value); setSnapshot(undefined); setMessage(undefined); }}/>
      <Button className="button" type="submit" isDisabled={busy}>{busy ? 'Reading…' : 'Read live capacity'}</Button>
    </form>
    {message && <p role="alert" className="notice">{message}</p>}
    {snapshot && <section className="review-section" role="status" aria-label="Live capacity result">
      <h2>Live-view runtime</h2>
      <p>{snapshot.message}</p>
      <p>Observed {when(snapshot.observed_at)}; fresh until {when(snapshot.fresh_until)}. {snapshot.nodes} current live-enabled node reports.</p>
      {activity.length > 0 && <><p>Active viewers, active cohorts and buffered pending rows are current gauges. Active viewers counts unexpired Active, Paused and Disconnected watch records with current owner credentials. Pending rows are shared-buffer occupancy, not exact per-viewer lag. Other values are cumulative process totals.</p><table aria-label="Live runtime totals and gauges"><thead><tr><th scope="col">Measure</th><th scope="col">Value</th></tr></thead><tbody>{activity.map(([label, value]) => <tr key={label}><td>{label}</td><td>{value.toLocaleString()}</td></tr>)}</tbody></table></>}
      {snapshot.rates_complete ? <table aria-label="Live runtime rates"><thead><tr><th scope="col">Rate</th><th scope="col">Per second</th></tr></thead><tbody>{rates.map(([label, value]) => <tr key={label}><td>{label}</td><td>{value.toLocaleString()}</td></tr>)}</tbody></table> : <p>Cluster-wide rates are unavailable for {snapshot.rates_unavailable} current live-enabled nodes.</p>}
    </section>}
  </div>;
}
