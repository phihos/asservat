import { lazy, Suspense } from 'react';
import { EvidenceBoundary } from './evidence-boundary';
import { caseIDFromPath } from './routes';
import { createRoot } from 'react-dom/client';
import { SessionGate } from './auth/SessionGate';
import { BrowserSession } from './auth/session';
import { CaptureWorkspace } from './capture/CaptureWorkspace';
import { Investigation } from './capture/investigation';
import { PolicyWorkspace } from './policy/PolicyWorkspace';
import { Policies } from './policy/policies';
import './styles.css';

const caseID = caseIDFromPath(window.location.pathname);
// The evidence validators/view are separate chunks and load only on case navigation.
let evidenceModule: Promise<typeof import('./evidence/EvidenceWorkspace')> | undefined;
const EvidenceWorkspace = lazy(() => evidenceModule ??= import('./evidence/EvidenceWorkspace'));
const controller = new BrowserSession();
const investigation = new Investigation();
const policies = new Policies();
const policyPage = window.location.pathname === '/policies';
controller.subscribe(() => {
  const state = controller.snapshot();
  if (state.phase === 'signedOut' || state.phase === 'signingOut') { investigation.reset(); policies.reset(); if (evidenceModule) void evidenceModule.then(module => module.evidenceController.reset()).catch(() => undefined); }
});
const root = document.getElementById('root');
if (!root) throw new Error('Missing console root');
createRoot(root).render(<>
  <a className="skip-link" href="#main">Skip to content</a>
  <SessionGate controller={controller}>{(session, scope) => <Suspense fallback={<p role="status">Loading evidence view…</p>}>{caseID ? <EvidenceBoundary path={"/cases/" + caseID}><EvidenceWorkspace session={session} scope={scope} caseID={caseID}/></EvidenceBoundary> : policyPage ? <PolicyWorkspace session={session} scope={scope} controller={policies}/> : <CaptureWorkspace session={session} scope={scope} controller={investigation}/>}</Suspense>}</SessionGate>
</>);
