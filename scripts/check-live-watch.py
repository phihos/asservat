#!/usr/bin/env python3
"""Contract and synthetic timeline checks; does not prove runtime enforcement."""
import copy,json
from pathlib import Path
from datetime import datetime
from jsonschema import Draft202012Validator,FormatChecker,ValidationError
from referencing import Registry,Resource
R=Path(__file__).resolve().parents[1];B='https://asservat.io/spec/v1/'
read=lambda p:json.loads((R/p).read_text())
schemas={s['$id']:s for s in (json.loads(p.read_text()) for p in (R/'specs/contracts').glob('*.schema.json'))}
registry=Registry().with_resources((k,Resource.from_contents(v)) for k,v in schemas.items())
tools={t['name']:t for t in read('specs/contracts/mcp-tools.json')['tools']};checks=0

def validate(value,schema):Draft202012Validator(schema,registry=registry,format_checker=FormatChecker()).validate(value)
def reject(value,schema,mutation):
 global checks
 bad=copy.deepcopy(value);mutation(bad)
 try:validate(bad,schema)
 except ValidationError:checks+=1
 else:raise AssertionError('Invalid live contract accepted')
open_request=read('examples/mcp-live-open-input.json');open_schema=tools['open_live_watch']['inputSchema']
for field in ['raw','body','argv','container','grant_id','policy_trigger','capture_filter','sharing','after','renew']:
 reject(open_request,open_schema,lambda d,f=field:d.update({f:True}))
for projection in ['rawPackets','syscallArguments','memory']:
 reject(open_request,open_schema,lambda d,p=projection:d.update(projection=p))
reject(open_request,open_schema,lambda d:d.update(duration_seconds=3601))
reject(open_request,open_schema,lambda d:d.update(source_handles=['same','same']))
reject(open_request,open_schema,lambda d:d.update(source_handles=[str(x) for x in range(17)]))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'body','op':'eq','value':'secret'}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'syscall','op':'regex','value':'.*'}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'status','op':'eq','value':503}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'error','op':'eq','value':True}]*17}))
packet_open=copy.deepcopy(open_request);packet_open.update(projection='packetMetadata',display_filter={'all':[{'field':'remote_ip','op':'eq','value':'192.0.2.10'}]});validate(packet_open,open_schema);checks+=1
reject(packet_open,open_schema,lambda d:d['display_filter']['all'][0].update(value='example.invalid'))
read_input=read('examples/mcp-live-read-input.json');read_schema=tools['read_live_watch']['inputSchema']
reject(read_input,read_schema,lambda d:d.update(wait_ms=5001))
reject(read_input,read_schema,lambda d:d.update(limit=101))
reject(read_input,read_schema,lambda d:d.pop('cursor'))
u=read('examples/mcp-live-update-input.json');us=tools['update_live_watch']['inputSchema']
reject(u,us,lambda d:d.update(duration_seconds=3600))
reject(u,us,lambda d:d.update(projection='httpHeaders'))
reject(u,us,lambda d:d.pop('expected_revision'))
reject(u,us,lambda d:d.pop('mode'))
for filename,field in [('mcp-live-http-result.json','body'),('mcp-live-packet-result.json','bytes'),('mcp-live-read-result.json','arguments')]:
 value=read('examples/'+filename);validate(value,tools['read_live_watch']['outputSchema']);checks+=1
 reject(value,tools['read_live_watch']['outputSchema'],lambda d,f=field:d['data']['rows'][0]['fields'].update({f:'forbidden'}))
 reject(value,tools['read_live_watch']['outputSchema'],lambda d:d['data']['rows'][0].pop('expires_at'))

def timeline(fixture):
 w,b=fixture['watch'],fixture['batch'];ts=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
 assert b['watch_id']==w['watch_id'] and b['revision']==w['revision']
 assert len(set(w['source_session_ids']))==len(w['source_session_ids'])
 assert b['output_bytes_spent']<=w['limits']['max_output_bytes']
 assert ts(w['accepted_at'])<ts(w['expires_at'])
 assert (ts(w['expires_at'])-ts(w['accepted_at'])).total_seconds()<=w['limits']['duration_seconds']
 assert b['state']=='Active' or not b['rows']
 ids=set()
 for row in b['rows']:
  assert row['source_session_id'] in w['source_session_ids']
  assert row['projection']==w['projection']
  assert row['row_id']==row['source_session_id']+':'+str(row['source_sequence']) and row['row_id'] not in ids
  ids.add(row['row_id'])
  assert ts(b['interval_from'])<=ts(row['observed_at'])<=ts(b['interval_until'])
  assert ts(row['observed_at'])<=ts(row['received_at'])<=ts(b['received_at'])<ts(row['expires_at'])<=ts(w['expires_at'])
  assert (ts(row['expires_at'])-ts(row['observed_at'])).total_seconds()<=w['limits']['row_max_age_seconds']
f=read('examples/live-watch.json');validate(f,schemas[B+'live-watch.schema.json']);timeline(f);checks+=1
for change in [lambda d:d['batch']['rows'][0].update(expires_at='2026-10-09T12:06:00Z'),lambda d:d['batch']['rows'][0].update(source_session_id='00000000-0000-4000-8000-000000000999'),lambda d:d['batch'].update(state='Paused'),lambda d:d['batch'].update(output_bytes_spent=16777217),lambda d:d['watch'].update(expires_at='2026-10-09T13:05:00Z'),lambda d:d['batch']['rows'].append(copy.deepcopy(d['batch']['rows'][0]))]:
 bad=copy.deepcopy(f);change(bad)
 try:timeline(bad)
 except AssertionError:checks+=1
 else:raise AssertionError('Invalid live timeline accepted')
assert set(tools['open_live_watch']['inputSchema']['properties'])=={'source_handles','projection','display_filter','duration_seconds','max_output_bytes','idempotency_key'}
print(f'PASS: {checks} live schema/timeline checks; raw content, hidden predicates, renewed lifetimes, invalid replay and scope drift rejected. Runtime checks remain pending.')
