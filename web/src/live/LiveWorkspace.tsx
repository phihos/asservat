import{useState}from'react';
import{Button}from'react-aria-components';
import type{Session}from'../auth/session';
import{LivePanel}from'./LivePanel';
import type{LiveWatch,Target}from'./watch';
export function LiveWorkspace({session,scope,controller}:{session:Session;scope:AbortSignal;controller?:LiveWatch}){
 const[draft,setDraft]=useState<Target>({cluster:'',namespace:'',kind:'Deployment',name:''});
 const[target,setTarget]=useState<Target>();
 return<div className="capture-workspace"><div className="page-intro"><h1>Observe existing recordings</h1><p>Choose an authorized workload or Pod, then explicitly find existing sources. Opening this page does not start or query a recorder. Session checks still occur.</p><p>Live rows are approved transient projections. To inspect raw bytes, save evidence and obtain the required access separately. <a href="/captures/new">Collect evidence or save current recordings</a>.</p></div>
 <form className="review-section" onSubmit={event=>{event.preventDefault();setTarget(structuredClone(draft))}}><fieldset><legend>Whole-Pod source scope</legend>
 <label>Cluster<input required value={draft.cluster} pattern="[a-z0-9]([\-a-z0-9]*[a-z0-9])?" maxLength={63} placeholder="local" onChange={e=>setDraft({...draft,cluster:e.currentTarget.value})}/></label>
 <label>Namespace<input required value={draft.namespace} maxLength={63} onChange={e=>setDraft({...draft,namespace:e.currentTarget.value})}/></label>
 <label>Target kind<select value={draft.kind} onChange={e=>setDraft({...draft,kind:e.currentTarget.value as Target['kind']})}><option>Deployment</option><option>StatefulSet</option><option>Pod</option></select></label>
 <label>Workload or pod name<input required value={draft.name} maxLength={253} onChange={e=>setDraft({...draft,name:e.currentTarget.value})}/></label>
 </fieldset><p>Source selection is whole Pod. Changing the target closes the previous view and requires explicit source selection again.</p><Button type="submit" className="button secondary">Use this target</Button></form>
 {target&&<LivePanel session={session} scope={scope} target={target} controller={controller}/>}
 </div>
}
