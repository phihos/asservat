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
open_request=read('examples/mcp-live-open-input.json');open_schema=tools['watch_live']['inputSchema']
# ADR-335 D9: no watch duration or lifetime output cap; the watch closes after 10 idle minutes.
for field in ['raw','body','argv','container','grant_id','policy_trigger','capture_filter','sharing','after','renew','duration_seconds','max_output_bytes']:
 reject(open_request,open_schema,lambda d,f=field:d.update({f:True}))
for projection in ['rawPackets','syscallArguments','memory']:
 reject(open_request,open_schema,lambda d,p=projection:d.update(projection=p))
reject(open_request,open_schema,lambda d:d.update(source_handles=['same','same']))
reject(open_request,open_schema,lambda d:d.update(source_handles=[str(x) for x in range(17)]))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'body','op':'eq','value':'secret'}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'syscall','op':'regex','value':'.*'}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'status','op':'eq','value':503}]}))
reject(open_request,open_schema,lambda d:d.update(display_filter={'all':[{'field':'error','op':'eq','value':True}]*17}))
packet_open=copy.deepcopy(open_request);packet_open.update(projection='packetMetadata',display_filter={'all':[{'field':'remote_ip','op':'eq','value':'192.0.2.10'}]});validate(packet_open,open_schema);checks+=1
reject(packet_open,open_schema,lambda d:d['display_filter']['all'][0].update(value='example.invalid'))
read_input=read('examples/mcp-live-read-input.json');read_schema=tools['watch_live']['inputSchema']
reject(read_input,read_schema,lambda d:d.update(action='open'))
reject(open_request,open_schema,lambda d:d.update(action='read'))
reject(read_input,read_schema,lambda d:d.update(wait_ms=30001))
reject(read_input,read_schema,lambda d:d.update(limit=101))
reject(read_input,read_schema,lambda d:d.pop('cursor'))
u=read('examples/mcp-live-update-input.json');us=tools['watch_live']['inputSchema']
reject(u,us,lambda d:d.update(duration_seconds=3600))
reject(u,us,lambda d:d.update(projection='httpHeaders'))
reject(u,us,lambda d:d.pop('expected_revision'))
reject(u,us,lambda d:d.pop('mode'))
for filename,field in [('mcp-live-http-result.json','body'),('mcp-live-packet-result.json','bytes'),('mcp-live-read-result.json','arguments')]:
 value=read('examples/'+filename);validate(value,tools['watch_live']['outputSchema']);checks+=1
 reject(value,tools['watch_live']['outputSchema'],lambda d,f=field:d['data']['rows'][0]['fields'].update({f:'forbidden'}))
 reject(value,tools['watch_live']['outputSchema'],lambda d:d['data']['rows'][0].pop('expires_at'))

def timeline(fixture):
 w,b=fixture['watch'],fixture['batch'];ts=lambda s:datetime.fromisoformat(s.replace('Z','+00:00'))
 assert b['watch_id']==w['watch_id'] and b['revision']==w['revision']
 assert len(set(w['source_session_ids']))==len(w['source_session_ids'])
 assert 'expires_at' not in w and 'duration_seconds' not in w['limits'] and 'max_output_bytes' not in w['limits']
 assert 0<(ts(w['idle_expires_at'])-ts(w['accepted_at'])).total_seconds()<=600
 assert b['state']=='Active' or not b['rows']
 ids=set()
 for row in b['rows']:
  assert row['source_session_id'] in w['source_session_ids']
  assert row['projection']==w['projection']
  assert row['row_id']==row['source_session_id']+':'+str(row['source_sequence']) and row['row_id'] not in ids
  ids.add(row['row_id'])
  assert ts(b['interval_from'])<=ts(row['observed_at'])<=ts(b['interval_until'])
  assert ts(row['observed_at'])<=ts(row['received_at'])<=ts(b['received_at'])<ts(row['expires_at'])
f=read('examples/live-watch.json');validate(f,schemas[B+'live-watch.schema.json']);timeline(f);checks+=1
for change in [lambda d:d['batch']['rows'][0].update(expires_at=d['batch']['received_at']),lambda d:d['batch']['rows'][0].update(source_session_id='00000000-0000-4000-8000-000000000999'),lambda d:d['batch'].update(state='Paused'),lambda d:d['watch'].update(idle_expires_at='2026-10-09T13:05:00Z'),lambda d:d['watch'].update(expires_at='2026-10-09T13:05:00Z'),lambda d:d['batch']['rows'].append(copy.deepcopy(d['batch']['rows'][0]))]:
 bad=copy.deepcopy(f);change(bad)
 try:timeline(bad)
 except AssertionError:checks+=1
 else:raise AssertionError('Invalid live timeline accepted')
# The browser receives the same row, gap and state types as SSE events.
event_schema={'$ref':B+'live-watch.schema.json#/$defs/event'}
row=f['batch']['rows'][0]
event={'event_id':row['row_id'],'watch_id':f['watch']['watch_id'],'revision':f['watch']['revision'],'type':'row','row':row,'handling':f['batch']['handling']}
validate(event,event_schema);checks+=1
state={**{k:v for k,v in event.items() if k!='row'},'type':'state','state':{'state':'Paused','sources':f['batch']['sources'],'output_bytes_spent':f['batch']['output_bytes_spent']}}
validate(state,event_schema);checks+=1
reject(event,event_schema,lambda d:d.update(type='gap'))
reject(event,event_schema,lambda d:d.update(state=state['state']))
reject(event,event_schema,lambda d:d['row']['fields'].update(body='forbidden'))
reject(state,event_schema,lambda d:d['state'].update(retry_after_ms=1000))
open_branch=next(r['then'] for r in tools['watch_live']['inputSchema']['allOf'] if r['if']['properties']['action']['const']=='open')
assert set(open_branch['properties'])=={'action','source_handles','projection','display_filter','idempotency_key'}
assert 'list_live_sources' not in tools and not any(n.endswith('_live_watch') for n in tools)
print(f'PASS: {checks} live schema/timeline checks; raw content, hidden predicates, lifetime caps, invalid replay and scope drift rejected. Runtime checks remain pending.')
