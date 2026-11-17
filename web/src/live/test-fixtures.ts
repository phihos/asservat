// Synthetic boundary fixtures only; never imported by product code.
import type{Operation,Input,Output,Operations,Watch,Row,Batch,Source}from'./http';
export{session,id}from'../evidence/test-fixtures';
import{id}from'../evidence/test-fixtures';
export const target={cluster:'local',namespace:'payments',kind:'Deployment' as const,name:'api'};
export const at='2026-11-05T12:00:00.000Z';const time=(ms:number)=>new Date(Date.parse(at)+ms).toISOString();
export const handling={transient:true as const,may_contain_user_data:true as const,raw_available_live:false as const,external_copies_recallable:false as const,save_semantics:'freshCurrentWindow' as const};
export function source():Source{return{recording_handle:'current-handle',owner_kind:'policy',policy_name:'payments-recorder',pod_name:'api-0',action_id:'packets',kind:'packetCapture',state:'Ready',history:'Unknown',maximum_before:'30s',save_eligible:true,save_via:'recordingSave',live_projections:['packetMetadata'],blockers:[],incident_pod_cap:1,hard_end:time(60_000),policy_uid:'policy',pod_uid:id(3)}}
export function page(recordings:Source[]=[source()]){return{kind:'recordingPage' as const,recordings,capture_enabled:true,expires_at:time(60_000)}}
export function watch():Watch{return{watch_id:id(4),revision:1,state:'Active',source_session_ids:[id(2)],projection:'packetMetadata',accepted_at:at,idle_expires_at:time(30_000),source_hard_end:time(60_000),limits:{bytes_per_second:64<<10,max_rows_per_batch:100,max_buffer_bytes:1<<20,replay_seconds:5},cursor:'cursor0',handling}}
export function row(sequence=1):Row{return{row_id:`source:${sequence}`,source_session_id:id(2),source_sequence:sequence,observed_at:at,received_at:at,expires_at:time(5_000),clock_uncertainty_ms:1,filter_generation:0,projection:'packetMetadata',pod_uid:id(3),fields:{protocol:'TCP',peer_uid:null,remote_ip:'192.0.2.1',remote_port:0,direction:'unknown',wire_bytes:0,pid:null}}}
export function batch(rows:Row[]=[row()]):Batch{return{watch_id:id(4),revision:1,batch_id:id(5),state:'Active',rows,sources:[{source_session_id:id(2),state:'Ready',filter_generation:0,last_observed_at:at,coverage:'unknown'}],gaps:[{reason:'sensorLoss',source_session_id:id(2),count:null,from:at,until:at}],interval_from:at,interval_until:at,received_at:at,output_bytes_spent:4096,handling}}
export function envelope(data:unknown,read=false){return{schema_version:'mcp-result/v1',request_id:id(8),status:'ok',data_class:read?'extract':'metadata',data,truncated:false,next_cursor:read?'cursor1':null,narrowing_hint:null,warnings:[],provenance:[]}}
// op names the call: list (list_recordings) or the watch_live action.
export type Op='list'|'open'|'read'|'update'|'close';
export class SyntheticLive implements Operations{
 calls:{name:Operation;op:Op;input:unknown;signal:AbortSignal}[]=[];
 responder:(op:Op,input:unknown)=>unknown|Promise<unknown>=(op)=>op==='list'?envelope(page()):op==='read'?envelope(batch(),true):envelope(watch());
 async call<N extends Operation>(name:N,input:Input<N>,_csrf:string,signal:AbortSignal):Promise<Output<N>>{const op:Op=name==='list_recordings'?'list':(input as {action:Op}).action;this.calls.push({name,op,input:structuredClone(input),signal});return await this.responder(op,input)as Output<N>}
}
