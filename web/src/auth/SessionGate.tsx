import { useEffect, useSyncExternalStore, type ReactNode } from 'react';
import { Button } from 'react-aria-components';
import { BrowserSession, type Session } from './session';
import { returnPath } from '../routes';

export function SessionGate({ controller, children }: {
  controller: BrowserSession;
  children: (session: Session, scope: AbortSignal) => ReactNode;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  useEffect(() => {
    void controller.resume();
    const visibility = () => { if (document.visibilityState === 'hidden') controller.suspend(); else void controller.resume(); };
    const restored = (event: PageTransitionEvent) => { if (event.persisted) { controller.suspend(); void controller.resume(); } };
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('pagehide', controller.suspend);
    window.addEventListener('pageshow', restored);
    return () => {
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('pagehide', controller.suspend);
      window.removeEventListener('pageshow', restored);
      controller.suspend();
    };
  }, [controller]);

  if (state.phase === 'active') return <>
    <header className="app-header"><a className="brand" href="/">Asservat</a><Button className="button secondary" onPress={() => { void controller.logout(); }}>Sign out</Button></header>
    <main id="main" className="workspace">{children(state.session, state.scope)}</main>
  </>;

  const busy = state.phase === 'checking' || state.phase === 'signingOut';
  const unavailable = state.phase === 'unavailable';
  const failedLogout = unavailable && state.reason === 'logoutFailed';
  return <main id="main" className="entry">
    <a className="brand" href="/">Asservat</a>
    <section aria-labelledby="entry-title" aria-busy={busy}>
      <h1 id="entry-title">{busy ? (state.phase === 'signingOut' ? 'Signing out…' : 'Checking your session…') : unavailable ? (failedLogout ? 'Sign-out could not be confirmed' : 'Unable to check your session') : 'Sign in to Asservat'}</h1>
      {busy ? <p role="status">{state.phase === 'signingOut' ? 'Removing your Asservat session.' : 'Connecting securely to your workspace.'}</p> : unavailable ? <>
        <p role="alert">{failedLogout ? 'This browser has cleared the view, but your server session may still be active. Retry sign-out when the connection is available.' : 'Your workspace is hidden until access can be checked. Check your connection and try again.'}</p>
        <div className="actions">
          <Button className="button" onPress={() => { void (failedLogout ? controller.logout() : controller.resume()); }}>{failedLogout ? 'Retry sign-out' : 'Try again'}</Button>
          {!failedLogout && <Button className="button secondary" onPress={() => { void controller.logout(); }}>Sign out</Button>}
        </div>
      </> : <>
        <p>{state.reason === 'expired' ? 'Your session has expired. Sign in again to continue.' : 'Collect debugging evidence and investigate it with your team.'}</p>
        <a className="button" href={'/auth/login?return_to=' + encodeURIComponent(returnPath(window.location.pathname))}>Sign in</a>
      </>}
    </section>
  </main>;
}
