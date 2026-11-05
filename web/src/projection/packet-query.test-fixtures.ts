// Synthetic tests only; no production import.
import { readFileSync } from 'node:fs';
import { id, profileVersion, queryHandle } from './test-fixtures';
import type { PacketField, PacketQuerySelection } from './packet-query';
export { id, profileVersion, queryHandle, session, SyntheticProjection } from './test-fixtures';
export const source = { caseID: id(2), artifactID: id(3), version: profileVersion, captureMode: 'networkHeaders' as const };
export const selection: PacketQuerySelection = { fields: ['packet_index', 'source_port'], max_packets: 100, max_scan_bytes: 8388608 };
const example = (name:string) => JSON.parse(readFileSync(new URL('../../../examples/'+name, import.meta.url), 'utf8'));
export function packetPage(raw = false, fields: PacketField[] = selection.fields) {
 const p = example('mcp-packet-query-metadata-result.json');
 p.data.capture_mode = raw ? 'rawPackets' : 'networkHeaders'; p.data_class = raw ? 'raw' : 'extract';
 p.data.fields = fields; p.data.rows = [fields.map(f => f === 'packet_index' ? 1 : f === 'source_port' ? 0 : f === 'packet_time' ? '2026-11-05T09:00:00Z' : f === 'protocol' ? 'TCP' : f === 'source_address' ? '192.0.2.1' : f === 'destination_address' ? '192.0.2.2' : f === 'destination_port' ? 443 : null), fields.map(f => f === 'packet_index' ? 2 : null)];
 p.provenance = [{ artifactID: id(3), digest: profileVersion }]; return p;
}
export function packetPending() {const p = packetPage(); p.data_class='metadata';p.status='pending';p.provenance=[];p.data={query_handle:queryHandle,retry_after_seconds:1,query_observed_at:p.data.query_observed_at,query_expires_at:p.data.query_expires_at};return p;}
export function packetPoll(page = packetPage()) {return {...page,provenance:[],data:{query_handle:queryHandle,tool_name:'pcap_query',result:page,query_observed_at:page.data.query_observed_at,query_expires_at:page.data.query_expires_at}};}
