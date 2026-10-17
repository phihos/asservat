import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SessionGate } from './SessionGate';
import { BrowserSession } from './session';

const controllers: BrowserSession[] = [];
afterEach(() => { cleanup(); for (const controller of controllers) controller.close(); vi.unstubAllGlobals(); });
function mount() {
  const controller = new BrowserSession(); controllers.push(controller);
  render(<SessionGate controller={controller}>{() => <h1>Protected workspace</h1>}</SessionGate>);
  return controller;
}
const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
it('offers a same-origin sign-in and no protected navigation without a session', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 401 })));
  mount();
  const signIn = await screen.findByRole('link', { name: 'Sign in' });
  expect(signIn.getAttribute('href')).toBe('/auth/login?return_to=%2F');
  expect(screen.queryByText('Protected workspace')).toBeNull();
});
it('provides retry and outage-safe sign-out without rendering server error text', async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response('upstream secret', { status: 503 }));
  vi.stubGlobal('fetch', fetcher); mount();
  expect(await screen.findByRole('heading', { name: 'Unable to check your session' })).toBeTruthy();
  expect(screen.queryByText(/upstream secret/)).toBeNull();
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeTruthy();
  fetcher.mockResolvedValueOnce(new Response(null, { status: 401 }));
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  expect(await screen.findByRole('heading', { name: 'Sign in to Asservat' })).toBeTruthy();
});
it('immediately removes the protected view on logout and preserves a failed logout explanation', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(json({ csrf_token: 'C'.repeat(43) })).mockResolvedValueOnce(json({
    principal: { issuer: 'https://identity.invalid', subject_id: 'developer', kind: 'user' }, roles: [],
    csrf_token: 'C'.repeat(43), expires_at: new Date(Date.now() + 60_000).toISOString(), step_up: 'unavailable',
  }));
  vi.stubGlobal('fetch', fetcher); mount();
  expect(await screen.findByText('Protected workspace')).toBeTruthy();
  fetcher.mockResolvedValueOnce(new Response(null, { status: 503 }));
  fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
  await waitFor(() => expect(screen.queryByText('Protected workspace')).toBeNull());
  expect(await screen.findByRole('heading', { name: 'Sign-out could not be confirmed' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Retry sign-out' })).toBeTruthy();
});
