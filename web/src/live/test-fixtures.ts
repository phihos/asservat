// Synthetic boundary fixtures only; never imported by product code.
import type{Operation,Input,Output,Operations,Watch,Row,Batch,Source}from'./http';
export{session,id}from'../evidence/test-fixtures';
import{id}from'../evidence/test-fixtures';
export const target={cluster_id:id(1),namespace:'payments',kind:'Deployment' as const,name:'api'};
export const at='2026-11-05T12:00:00.000Z';const time=(ms:number)=>new Date(Date.parse(at)+ms).toISOString();
export const handling={transient:true as const,may_contain_user_data:true as const,managed_row_max_age_seconds:30,raw_available_live:false as const,external_copies_recallable:false as const,save_semantics:'freshCurrentWindow' as const};
export function source():Source{return{source_handle:'current-handle',handle_expires_at:time(60_000),source_session_id:id(2),workload_uid:'workload',pod_uid:id(3),action_id:'packets',owner_kind:'policy',owner_id:'policy',state:'Ready',projections:['packetMetadata'],eligible:true,blocker_codes:[],save_via:'recordingSave',lease_until:time(30_000)}}
export function watch():Watch{return{watch_id:id(4),revision:1,state:'Active',source_session_ids:[id(2)],projection:'packetMetadata',accepted_at:at,expires_at:time(60_000),idle_expires_at:time(30_000),limits:{duration_seconds:60,max_output_bytes:16<<20,bytes_per_second:64<<10,max_rows_per_batch:100,max_buffer_bytes:1<<20,row_max_age_seconds:30,replay_seconds:5},cursor:'cursor0',handling}}
export function row(sequence=1):Row{return{row_id:`source:${sequence}`,source_session_id:id(2),source_sequence:sequence,observed_at:at,received_at:at,expires_at:time(5_000),clock_uncertainty_ms:1,filter_generation:0,projection:'packetMetadata',pod_uid:id(3),fields:{protocol:'TCP',peer_uid:null,remote_ip:'192.0.2.1',remote_port:0,direction:'unknown',wire_bytes:0,pid:null}}}
export function batch(rows:Row[]=[row()]):Batch{return{watch_id:id(4),revision:1,batch_id:id(5),state:'Active',rows,sources:[{source_session_id:id(2),state:'Ready',filter_generation:0,last_observed_at:at,coverage:'unknown'}],gaps:[{reason:'sensorLoss',source_session_id:id(2),count:null,from:at,until:at}],interval_from:at,interval_until:at,received_at:at,output_bytes_spent:4096,retry_after_ms:1000,handling}}
export function envelope(data:unknown,read=false){return{schema_version:'mcp-result/v1',request_id:id(8),status:'ok',data_class:read?'extract':'metadata',data,truncated:false,next_cursor:read?'cursor1':null,narrowing_hint:null,warnings:[],provenance:[]}}
export class SyntheticLive implements Operations{
 calls:{name:Operation;input:unknown;signal:AbortSignal}[]=[];
 responder:(name:Operation,input:unknown)=>unknown|Promise<unknown>=(name)=>name==='list_live_sources'?envelope({sources:[source()]}):name==='read_live_watch'?envelope(batch(),true):envelope(watch());
 async call<N extends Operation>(name:N,input:Input<N>,_csrf:string,signal:AbortSignal):Promise<Output<N>>{this.calls.push({name,input:structuredClone(input),signal});return await this.responder(name,input)as Output<N>}
}
