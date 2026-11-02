import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ProfileCatalog, componentID, defaultBounds, seconds, type Composition } from './ProfileCatalog';
import { SyntheticOperations, profileResult, session, target } from './test-fixtures';

describe('ProfileCatalog', () => {
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
