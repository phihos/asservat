import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import EvidenceWorkspace from './EvidenceWorkspace';
import { result } from '../capture/test-fixtures';
import { Evidence } from './evidence';
import { SyntheticEvidence, session, caseResult, downloadResult, cancelled, completed, id } from './test-fixtures';
import { caseIDFromPath, returnPath } from '../routes';
const controllers: Evidence[] = [];
afterEach(() => { cleanup(); for (const controller of controllers) controller.reset(); controllers.length = 0; vi.useRealTimers(); });
async function mount(client = new SyntheticEvidence()) {
  let nextID = 100;
  const controller = new Evidence(client, () => id(nextID++)); controllers.push(controller);
  render(<EvidenceWorkspace controller={controller} session={session} scope={new AbortController().signal} caseID={id(2)}/>);
  return { client, controller };
}
it('shows an unavailable service without fictitious artifacts or native links', async () => {
  const client = new SyntheticEvidence(); client.responder = () => { throw new Error('private failed database'); }; await mount(client);
  expect((await screen.findByRole('alert')).textContent).toContain('evidence service is unavailable');
  expect(screen.queryByRole('button', { name: 'Download' })).toBeNull();
  expect(screen.queryByText('private failed database')).toBeNull();
});
it.each(['context', 'pcapng', 'ELF core', 'runtime dump', 'pprof', 'logs', 'syscalls', 'new-artifact-format'])('offers native download for %s without a debugger whitelist', async kind => {
  const client = new SyntheticEvidence(); const value = caseResult(); if (value.status !== 'ok') throw new Error(); value.data.artifacts[0].kind = kind;
  client.responder = () => value; await mount(client);
  expect(await screen.findByRole('button', { name: 'Download' })).toBeTruthy();
  expect(screen.getByText(/preferred compatible local tools/)).toBeTruthy();
  expect(screen.queryByText(/GDB|gdb/)).toBeNull();
  expect(screen.getByText(/Downloaded copies are outside/)).toBeTruthy();
});
it('supplies only the verified local attachment path when ready', async () => {
  await mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Download' }));
  const link = await screen.findByRole('link', { name: 'Download native file' });
  expect(link.getAttribute('href')).toBe(`/api/v1/downloads/${id(4)}/content`);
  expect(link.getAttribute('download')).toBe('artifact-3.json');
  expect(screen.getByText('512 bytes')).toBeTruthy();
  expect(screen.getByText('a'.repeat(64))).toBeTruthy();
  expect(screen.getByText(/Selected pod-status metadata only/)).toBeTruthy();
});
it('keeps request recovery visible even if case access becomes unavailable', async () => {
  const { client, controller } = await mount(); await screen.findByRole('button', { name: 'Download' });
  client.responder = () => { throw new Error('unknown commit'); };
  fireEvent.click(screen.getByRole('button', { name: 'Download' }));
  await screen.findByRole('button', { name: 'Retry same download request' });
  await act(() => controller.refresh());
  expect(screen.getByRole('button', { name: 'Retry same download request' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download' })).toBeNull();
});
it('shows an ended session with its checksum but without a link or cancellation', async () => {
  const { client, controller } = await mount(); await screen.findByRole('button', { name: 'Download' });
  fireEvent.click(screen.getByRole('button', { name: 'Download' }));
  await screen.findByRole('link', { name: 'Download native file' });
  client.responder = () => completed();
  await act(() => controller.checkDownload());
  expect(screen.getByRole('heading', { name: 'Transfer recorded' })).toBeTruthy();
  expect(screen.getByText('a'.repeat(64))).toBeTruthy();
  expect(screen.getByText(/cannot confirm local disk storage/)).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'Download native file' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Cancel download' })).toBeNull();
});
it('recognizes exact case navigation only', () => {
  expect(caseIDFromPath('/cases/' + id(2))).toBe(id(2)); expect(returnPath('/cases/' + id(2))).toBe('/cases/' + id(2));
  for (const path of ['/cases', '/cases/' + id(2) + '?token=x', '//outside.invalid', '/cases/' + id(2) + '/content']) expect(returnPath(path)).toBe('/');
});

it('keeps unknown cancellation prominent even when a status read still says ready', async () => {
  const { client, controller } = await mount(); await screen.findByRole('button', { name: 'Download' });
  fireEvent.click(screen.getByRole('button', { name: 'Download' }));
  await screen.findByRole('link', { name: 'Download native file' });
  client.responder = (_name, input) => { if ((input as { action: string }).action === 'cancel') throw new Error('lost reply'); return downloadResult(); };
  fireEvent.click(screen.getByRole('button', { name: 'Cancel download' }));
  await screen.findByRole('button', { name: 'Retry cancellation' });
  await act(() => controller.checkDownload());
  expect(screen.getByRole('heading', { name: 'Confirming cancellation' })).toBeTruthy();
  expect(screen.getByText(/Cancellation is not yet confirmed/)).toBeTruthy();
  expect(screen.queryByRole('link', { name: 'Download native file' })).toBeNull();
});

it('removes the idle download affordance at artifact expiry without a new request', async () => {
  vi.useFakeTimers();
  const client = new SyntheticEvidence();
  const result = caseResult(); if (result.status !== 'ok') throw new Error();
  const artifact = result.data.artifacts[0];
  artifact.expires_at = artifact.handling_notice.expiresAt = new Date(Date.now() + 1000).toISOString();
  client.responder = () => result;
  let controller!: Evidence;
  await act(async () => { ({ controller } = await mount(client)); });
  expect(screen.getByRole('button', { name: 'Download' })).toBeTruthy();
  await act(() => vi.advanceTimersByTimeAsync(1000));
  expect(screen.queryByRole('button', { name: 'Download' })).toBeNull();
  expect(screen.getByText('Evidence access has expired.')).toBeTruthy();
  expect(client.calls.map(call => call.name)).toEqual(['get_case']);
  await act(() => vi.advanceTimersByTimeAsync(60_000));
  expect(client.calls).toHaveLength(1);
  expect(controller.snapshot().details!.artifacts[0].expires_at).toBe(artifact.expires_at);
});

it('offers an explicit new download after the native link was requested while status is still Ready', async () => {
  const { client, controller } = await mount();
  await screen.findByRole('button', { name: 'Download' });
  client.responder = () => downloadResult();
  fireEvent.click(screen.getByRole('button', { name: 'Download' }));
  const link = await screen.findByRole('link', { name: 'Download native file' });
  expect(screen.queryByRole('button', { name: 'Start a new download' })).toBeNull();
  // Native attachment failures do not produce an operation callback to React.
  // Prevent jsdom navigation only; exercise the real explicit link click handler.
  link.addEventListener('click', event => event.preventDefault(), { once: true });
  fireEvent.click(link);
  expect(controller.snapshot().started).toBe(true);
  expect(controller.snapshot().download?.state).toBe('Ready');
  expect(controller.snapshot().error).toBeUndefined();
  expect(client.calls.map(c => c.name)).toEqual(['get_case', 'download_artifact']);
  const restart = screen.queryByRole('button', { name: 'Start a new download' });
  expect(restart).not.toBeNull();
  client.responder = (_name, input) => (input as { action: string }).action === 'cancel' ? cancelled() : downloadResult();
  fireEvent.click(restart!);
  await waitFor(() => expect(client.calls.map(c => (c.input as { action?: string }).action)).toEqual([undefined, 'prepare', 'cancel', 'prepare']));
  expect(client.calls[3].input).not.toEqual(client.calls[1].input);
});

it('offers a separate existing-raw approval form without replacing a covering download', async () => {
  const client = new SyntheticEvidence(); const value = caseResult(); if (value.status !== 'ok') throw new Error();
  value.data.artifacts[0].data_class = 'raw'; value.data.artifacts[0].kind = 'syscallTrace';
  value.data.artifacts[0].verified_native_bytes = 512;
  value.data.artifacts[0].target = { cluster_id: id(1), namespace_uid: 'ns', workload_uid: 'workload', pod_uid: 'pod' };
  client.responder = () => value; await mount(client);
  expect(await screen.findByRole('heading', { name: 'Request raw download approval' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Download' })).toBeTruthy();
  expect(screen.getByRole('checkbox')).toHaveProperty('disabled', false);
  expect(client.calls.map(c => c.name)).toEqual(['get_case']);
});

function rawCaseForApproval() {
 const value=caseResult(); if(value.status!=='ok')throw new Error();
 Object.assign(value.data.artifacts[0],{data_class:'raw',kind:'syscallTrace',verified_native_bytes:512,target:{cluster_id:id(1),namespace_uid:'ns',workload_uid:'workload',pod_uid:'pod'}});
 return value;
}
it('Download opens exact-size prefilled review only for typed missing approval and retains its preparation key',async()=>{
 const client=new SyntheticEvidence();const value=rawCaseForApproval();
 client.responder=name=>name==='get_case'?value:{...result({code:'RawApprovalRequired',message:'Whole-file approval required',retryable:false}),status:'error'};
 await mount(client);fireEvent.click(await screen.findByRole('button',{name:'Download'}));
 await waitFor(()=>expect(screen.getByRole('checkbox')).toHaveProperty('checked',true));
 expect(screen.getByRole('heading',{name:'Request raw download approval'})).toBe(document.activeElement);
 expect(screen.getByLabelText('Total download byte budget')).toHaveProperty('value','512');
 expect(screen.getByText(/after approval, retry this same download request/)).toBeTruthy();
 const first=client.calls.find(c=>c.name==='download_artifact')!;
 client.responder=()=>downloadResult();fireEvent.click(screen.getByRole('button',{name:'Retry same download request'}));
 await screen.findByRole('heading',{name:'Ready to download'});
 const prepares=client.calls.filter(c=>c.name==='download_artifact');expect(prepares).toHaveLength(2);expect(prepares[1].input).toEqual(first.input);
});
it('does not infer an approval request from unavailable service or denied ordinary rights',async()=>{
 const client=new SyntheticEvidence();const value=rawCaseForApproval();
 client.responder=name=>name==='get_case'?value:{...result({code:'NotAvailable',message:'Access unavailable',retryable:true}),status:'error'};
 await mount(client);fireEvent.click(await screen.findByRole('button',{name:'Download'}));
 await screen.findByRole('alert');expect(screen.getByRole('checkbox')).toHaveProperty('checked',false);
 expect(screen.getByRole('heading',{name:'Request raw download approval'})).not.toBe(document.activeElement);
 expect(screen.getByRole('button',{name:'Retry same download request'})).toBeTruthy();
});
it.each(['ordinary','shared'])('offers saved raw logs through ordinary artifact access (%s)',async access=>{const client=new SyntheticEvidence();const p=caseResult();if(p.status!=='ok')throw Error();p.data.case.access=access as 'ordinary'|'shared';p.data.artifacts[0]={...p.data.artifacts[0],kind:'logs',native_format:'asservat-logs/v1',data_class:'raw',verified_native_bytes:4096,target:{cluster_id:id(1),namespace_uid:'ns',workload_uid:'workload',pod_uid:'pod'}};client.responder=()=>p;await mount(client);await screen.findByRole('button',{name:'Download'});if(access==='ordinary'){expect(screen.getByRole('button',{name:'Inspect saved logs'})).toHaveProperty('disabled',true);expect(screen.getByRole('heading',{name:'Request saved log query approval'})).toBeTruthy();}else expect(screen.queryByRole('button',{name:'Inspect saved logs'})).toBeNull();expect(client.calls.some(c=>c.name==='download_artifact')).toBe(false);});
