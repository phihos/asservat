import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProfileCatalog, componentID, defaultBounds, seconds, type CatalogDraft, type Composition } from './ProfileCatalog';
import { SyntheticOperations, profileResult, session, target } from './test-fixtures';

describe('ProfileCatalog', () => {
  afterEach(cleanup);
  it('edits complete argument settings, preserves false through the draft and omits unchanged defaults', async () => {
    const profile = profileResult('syscall-activity');
    if (profile.status !== 'ok') throw new Error();
    const definition = profile.data.definition;
    definition.editableFields.push({ actionID: 'syscalls', field: 'syscallArguments', label: 'Argument capture' });
    Object.assign(definition.recipe.actions[0].parameters, { mode: 'arguments', arguments: { maxBytesPerEvent: 128, captureBuffers: true } });
    let draft: CatalogDraft = { added: [{ id: 'calls', ref: profile.data.profile_ref, definition, values: {} }], bounds: { bytes: '8388608', duration: '15s' } };
    const client = new SyntheticOperations();
    client.responder = () => import('./test-fixtures').then(m => m.profilesResult());
    const onPreview = vi.fn<(c: Composition) => void>();
    const view = () => <ProfileCatalog session={session} scope={new AbortController().signal} target={target} busy={false} onPreview={onPreview} client={client} initial={draft} onDraft={next => { draft = next; }}/>;
    const first = render(view());
    expect((screen.getByLabelText('Maximum argument bytes per event') as HTMLInputElement).value).toBe('128');
    expect((screen.getByLabelText('Capture buffer contents') as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
    expect(onPreview.mock.calls.at(-1)![0].components[0].overrides).toBeUndefined();
    fireEvent.change(screen.getByLabelText('Maximum argument bytes per event'), { target: { value: '64' } });
    fireEvent.click(screen.getByLabelText('Capture buffer contents'));
    first.unmount();
    render(view());
    expect((screen.getByLabelText('Maximum argument bytes per event') as HTMLInputElement).value).toBe('64');
    expect((screen.getByLabelText('Capture buffer contents') as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
    expect(onPreview.mock.calls.at(-1)![0].components[0].overrides).toEqual([{ actionID: 'syscalls', field: 'syscallArguments', value: { maxBytesPerEvent: 64, captureBuffers: false } }]);
    onPreview.mockClear();
    for (const value of ['0', '4097', '1.5', '']) {
      fireEvent.change(screen.getByLabelText('Maximum argument bytes per event'), { target: { value } });
      fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
      expect(onPreview).not.toHaveBeenCalled();
      expect(screen.getByRole('status').textContent).toBe('Argument bytes per event must be a whole number from 1 to 4096.');
    }
    for (const value of ['1', '4096']) {
      fireEvent.change(screen.getByLabelText('Maximum argument bytes per event'), { target: { value } });
      fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
      expect(onPreview.mock.calls.at(-1)![0].components[0].overrides![0].value).toEqual({ maxBytesPerEvent: Number(value), captureBuffers: false });
    }
    fireEvent.change(screen.getByLabelText('Maximum argument bytes per event'), { target: { value: '128' } });
    fireEvent.click(screen.getByLabelText('Capture buffer contents'));
    fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
    expect(onPreview.mock.calls.at(-1)![0].components[0].overrides).toBeUndefined();
    await waitFor(() => expect(client.calls).toHaveLength(2));
  });
  it('composes selected profiles with changed scalar fields and default bounds (REQ-CPR-005)', async () => {
    const client = new SyntheticOperations();
    client.responder = name => name === 'list_capture_profiles' ? import('./test-fixtures').then(m => m.profilesResult()) : profileResult('network-connections');
    const onPreview = vi.fn<(c: Composition) => void>();
    render(<ProfileCatalog session={session} scope={new AbortController().signal} target={target} busy={false} onPreview={onPreview} client={client}/>);
    const add = await screen.findAllByRole('button', { name: 'Add profile' });
    fireEvent.click(add[0]);
    const after = await screen.findByLabelText(/Next interval/);
    expect(after.getAttribute('placeholder')).toBe('10s');
    fireEvent.change(after, { target: { value: '5s' } });
    fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
    await waitFor(() => expect(onPreview).toHaveBeenCalled());
    const c = onPreview.mock.calls[0][0];
    expect(c.components).toEqual([{ id: 'network-connections', profileRef: { catalog: 'builtin', name: 'network-connections', version: 'v1' }, overrides: [{ actionID: 'sample', field: 'packetAfter', value: '5s' }] }]);
    expect(c.maxTotalBytes).toBe(16 << 20);
    expect(c.maxDuration).toBe('20s');
    expect(client.calls.map(call => call.name)).toEqual(['list_capture_profiles', 'get_capture_profile']);
  });
  it('proposes the coupled 0s history window for onTrigger and keeps edits made while another profile loads', async () => {
    const client = new SyntheticOperations();
    let release: () => void = () => {};
    const gate = new Promise<void>(resolve => { release = resolve; });
    let fetched = 0;
    client.responder = async name => {
      if (name === 'list_capture_profiles') return (await import('./test-fixtures')).profilesResult();
      fetched++;
      if (fetched === 2) await gate;
      return profileResult(fetched === 1 ? 'network-connections' : 'syscall-activity');
    };
    const onPreview = vi.fn<(c: Composition) => void>();
    render(<ProfileCatalog session={session} scope={new AbortController().signal} target={target} busy={false} onPreview={onPreview} client={client}/>);
    const add = await screen.findAllByRole('button', { name: 'Add profile' });
    fireEvent.click(add[0]);
    const mode = await screen.findByLabelText(/When recording starts/);
    fireEvent.click(add[1]);
    await waitFor(() => expect(client.calls.map(c => c.name)).toEqual(['list_capture_profiles', 'get_capture_profile', 'get_capture_profile']));
    fireEvent.change(mode, { target: { value: 'onTrigger' } });
    release();
    fireEvent.click(await screen.findByRole('button', { name: 'Set history window to 0s' }));
    await screen.findByRole('heading', { level: 4, name: /System calls of all pod processes/ });
    fireEvent.click(screen.getByRole('button', { name: 'Review combined recording' }));
    await waitFor(() => expect(onPreview).toHaveBeenCalled());
    const [net, calls] = onPreview.mock.calls[0][0].components;
    expect(net.overrides).toEqual([{ actionID: 'sample', field: 'packetBefore', value: '0s' }, { actionID: 'sample', field: 'actionExecutionMode', value: 'onTrigger' }]);
    expect(calls.id).toBe('syscall-activity');
  });
  it('derives unique short component IDs and aggregate bounds', () => {
    expect(componentID('a-very-long-profile-name-beyond-limits', [])).toHaveLength(22);
    expect(componentID('net', ['net'])).toBe('net-2');
    expect(seconds('2m')).toBe(120);
    const net = profileResult('network-connections').data as unknown as { definition: never };
    const calls = profileResult('syscall-activity').data as unknown as { definition: never };
    const b = defaultBounds([{ id: 'n', ref: { catalog: 'builtin', name: 'n', version: 'v1' }, definition: net.definition, values: {} }, { id: 's', ref: { catalog: 'builtin', name: 's', version: 'v1' }, definition: calls.definition, values: {} }]);
    expect(b.bytes).toBe(32 << 20);
  });
});

it('authors finite logs windows and combined stream as typed edits with reviewed defaults', async () => {
 const reply=profileResult('network-connections');if(reply.status!=='ok')throw Error();const definition=reply.data.definition;
 Object.assign(definition,{displayName:'Finite whole-Pod logs',editableFields:[{actionID:'logs',field:'logBefore',label:'Historical window'},{actionID:'logs',field:'logAfter',label:'After-trigger window'},{actionID:'logs',field:'logStream',label:'Log stream'},{actionID:'logs',field:'actionTimeout',label:'Completion deadline'}]});
 Object.assign(definition.recipe.actions[0],{id:'logs',kind:'logs',parameters:{before:'10s',after:'0s',stream:'both'},executionMode:'onTrigger',limits:{maxBytes:10485760,timeout:'10s'}});
 const draft:CatalogDraft={added:[{id:'saved',ref:{catalog:'builtin',name:'finite-logs',version:'v1'},definition,values:{}}],bounds:{bytes:'10485760',duration:'40s'}};
 const client=new SyntheticOperations();client.responder=()=>import('./test-fixtures').then(m=>m.profilesResult());const onPreview=vi.fn<(c:Composition)=>void>();
 render(<ProfileCatalog session={session} scope={new AbortController().signal} target={target} busy={false} onPreview={onPreview} client={client} initial={draft}/>);
 expect(screen.getByLabelText('Historical window').getAttribute('placeholder')).toBe('10s');expect(screen.getByLabelText('After-trigger window').getAttribute('placeholder')).toBe('0s');expect(screen.getByLabelText('Log stream').getAttribute('placeholder')).toBe('both');
 fireEvent.change(screen.getByLabelText('Historical window'),{target:{value:'1h'}});fireEvent.change(screen.getByLabelText('After-trigger window'),{target:{value:'30s'}});fireEvent.change(screen.getByLabelText('Completion deadline'),{target:{value:'40s'}});
 fireEvent.click(screen.getByRole('button',{name:'Review combined recording'}));
 expect(onPreview.mock.calls.at(-1)![0].components[0].overrides).toEqual([{actionID:'logs',field:'logBefore',value:'1h'},{actionID:'logs',field:'logAfter',value:'30s'},{actionID:'logs',field:'actionTimeout',value:'40s'}]);
 await waitFor(()=>expect(client.calls.length).toBeGreaterThan(0));cleanup();
});
