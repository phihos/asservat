import{cleanup,fireEvent,render,screen,waitFor}from'@testing-library/react';
import{afterEach,expect,it}from'vitest';
import{LiveWorkspace}from'./LiveWorkspace';
import{LiveWatch}from'./watch';
import{SyntheticLive,session,target,source,envelope}from'./test-fixtures';
import{returnPath}from'../routes';
afterEach(cleanup);
it('keeps navigation and target editing passive until explicit inventory, without target/source URL state',async()=>{const api=new SyntheticLive();api.responder=()=>envelope({sources:[source()]});const scope=new AbortController();render(<LiveWorkspace session={session} scope={scope.signal} controller={new LiveWatch(api)}/>);expect(api.calls).toHaveLength(0);expect(screen.queryByRole('button',{name:'Find live sources'})).toBeNull();fireEvent.change(screen.getByLabelText('Cluster ID'),{target:{value:target.cluster_id}});fireEvent.change(screen.getByLabelText('Namespace'),{target:{value:target.namespace}});fireEvent.change(screen.getByLabelText('Workload or pod name'),{target:{value:target.name}});fireEvent.click(screen.getByRole('button',{name:'Use this target'}));expect(api.calls).toHaveLength(0);fireEvent.click(screen.getByRole('button',{name:'Find live sources'}));await waitFor(()=>expect(api.calls).toHaveLength(1));expect(api.calls[0]).toMatchObject({name:'list_live_sources',input:{target_ref:target,limit:20}});expect(returnPath('/live')).toBe('/live');expect(returnPath('/live?source_handle=private')).toBe('/');expect(returnPath('/live/')).toBe('/');scope.abort()});
