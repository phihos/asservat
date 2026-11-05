import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { Evidence } from './evidence';
import { SyntheticEvidence, session, caseResult, id } from './test-fixtures';
import { packetSummary, profileVersion } from '../projection/test-fixtures';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it.each(['ordinary', 'shared'])('offers only an explicit metadata saved-packet query with %s access', async access => {
  const client = new SyntheticEvidence(), value = caseResult(); if (value.status !== 'ok') throw new Error();
  value.data.case.access = access as 'ordinary' | 'shared'; Object.assign(value.data.artifacts[0], { kind: 'packetCapture', native_format: 'pcapng', data_class: 'metadata', artifact_id: id(3), digest: profileVersion });
  client.responder = () => value; const controller = new Evidence(client); const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(packetSummary()), { headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetcher);
  render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  const inspect = await screen.findByRole('button', { name: 'Inspect saved packets' }); expect(fetcher).not.toHaveBeenCalled(); expect(client.calls.map(call => call.name)).toEqual(['get_case']);
  fireEvent.click(inspect); await screen.findByRole('table', { name: 'Saved packet conversations' });
  expect(fetcher).toHaveBeenCalledOnce(); expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/get_pcap_summary');
  expect(client.calls.map(call => call.name)).toEqual(['get_case']); expect(screen.getByRole('button', { name: 'Download' })).toBeTruthy(); controller.reset();
});
it.each([['raw', 'pcapng'], ['raw', 'rawPcapng'], ['extract', 'http-headers/v1'], ['metadata', 'unknown']])('does not offer packet inspection for %s/%s', async (dataClass, format) => {
  const client = new SyntheticEvidence(), value = caseResult(); if (value.status !== 'ok') throw new Error();
  Object.assign(value.data.artifacts[0], { kind: 'packetCapture', native_format: format, data_class: dataClass }); client.responder = () => value;
  const controller = new Evidence(client); render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  await screen.findByRole('button', { name: 'Download' }); expect(screen.queryByRole('button', { name: 'Inspect saved packets' })).toBeNull(); expect(client.calls).toHaveLength(1); controller.reset();
});
it('offers a raw aggregate only on ordinary access, with an accurate raw packet label', async () => {
  const client = new SyntheticEvidence(), value = caseResult(); if (value.status !== 'ok') throw new Error();
  Object.assign(value.data.artifacts[0], { kind: 'packetCapture', native_format: 'pcapng-raw', data_class: 'raw', artifact_id: id(3), digest: profileVersion });
  client.responder = () => value; const controller = new Evidence(client);
  const summary = packetSummary(); Object.assign(summary.data, { capture_mode: 'rawPackets', packets: 5, unclassified_packets: 2 });
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify(summary), { headers: { 'Content-Type': 'application/json' } })); vi.stubGlobal('fetch', fetcher);
  render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  const inspect = await screen.findByRole('button', { name: 'Inspect saved packets' });
  expect(screen.getByRole('heading', { name: 'Packet capture (raw packets)' })).toBeTruthy(); expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(inspect); await screen.findByRole('table', { name: 'Saved packet conversations' }); expect(screen.getByText('Unclassified saved records')).toBeTruthy();
  expect(fetcher).toHaveBeenCalledOnce(); controller.reset();
});
it('never offers the raw aggregate through a shared case', async () => {
  const client = new SyntheticEvidence(), value = caseResult(); if (value.status !== 'ok') throw new Error(); value.data.case.access = 'shared';
  Object.assign(value.data.artifacts[0], { kind: 'packetCapture', native_format: 'pcapng-raw', data_class: 'raw' }); client.responder = () => value;
  const controller = new Evidence(client); render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  await screen.findByRole('button', { name: 'Download' }); expect(screen.queryByRole('button', { name: 'Inspect saved packets' })).toBeNull(); controller.reset();
});

it('offers the saved packet query and invokes only that explicit operation', async () => {
 const client=new SyntheticEvidence(),value=caseResult();if(value.status!=='ok')throw Error();Object.assign(value.data.artifacts[0],{artifact_id:id(3),kind:'packetCapture',native_format:'pcapng',data_class:'metadata',digest:profileVersion});client.responder=()=>value;
 const page=packetSummary();
 const fetcher=vi.fn().mockImplementation(async (_url,options)=>{const input=JSON.parse(options.body);return new Response(JSON.stringify({...page,data:{capture_mode:'networkHeaders',fields:input.fields,rows:[input.fields.map((field:string)=>field==='packet_index'?1:field==='packet_time'?'2026-10-18T12:00:00Z':field==='source_address'?'192.0.2.1':field==='destination_address'?'192.0.2.2':field==='protocol'?'TCP':0)],scanned_bytes:54,scanned_packets:1,row_limit_reached:false,scan_limit_reached:false,output_limit_reached:false,query_observed_at:page.data.query_observed_at,query_expires_at:page.data.query_expires_at}}),{headers:{'Content-Type':'application/json'}})});vi.stubGlobal('fetch',fetcher);
 const controller=new Evidence(client);render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);const run=await screen.findByRole('button',{name:'Run packet query'});expect(fetcher).not.toHaveBeenCalled();fireEvent.click(run);await screen.findByRole('table',{name:'Saved packet query rows'});expect(fetcher).toHaveBeenCalledOnce();expect(fetcher.mock.calls[0][0]).toBe('/api/v1/operations/pcap_query');expect(client.calls.every(call=>call.name==='get_case')).toBe(true);controller.reset();
});
