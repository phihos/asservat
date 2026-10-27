import { lazy, Suspense } from 'react';
import { EvidenceBoundary } from './evidence-boundary';
import { approvalIDFromPath, caseIDFromPath } from './routes';
import { createRoot } from 'react-dom/client';
import { SessionGate } from './auth/SessionGate';
import { BrowserSession } from './auth/session';
import { CaptureWorkspace } from './capture/CaptureWorkspace';
import { Investigation } from './capture/investigation';
import { PolicyWorkspace } from './policy/PolicyWorkspace';
import { Policies } from './policy/policies';
import { SharesWorkspace } from './sharing/SharesWorkspace';
import { AccessPreviewWorkspace } from './access/AccessPreviewWorkspace';
import { RetentionPreviewWorkspace } from './retention/RetentionPreviewWorkspace';
import { ApprovalsWorkspace } from './approvals/ApprovalsWorkspace';
import { Shares } from './sharing/shares';
import './styles.css';

const caseID = caseIDFromPath(window.location.pathname);
// The evidence validators/view are separate chunks and load only on case navigation.
let evidenceModule: Promise<typeof import('./evidence/EvidenceWorkspace')> | undefined;
const EvidenceWorkspace = lazy(() => evidenceModule ??= import('./evidence/EvidenceWorkspace'));
const controller = new BrowserSession();
const investigation = new Investigation();
const policies = new Policies();
const shares = new Shares();
const policyPage = window.location.pathname === '/policies';
const sharesPage = window.location.pathname === '/shares';
const accessPreviewPage = window.location.pathname === '/access-preview';
const retentionPreviewPage = window.location.pathname === '/retention-preview';
const approvalID = approvalIDFromPath(window.location.pathname);
const approvalsPage = window.location.pathname === '/approvals' || approvalID !== undefined;
controller.subscribe(() => {
  const state = controller.snapshot();
  if (state.phase === 'signedOut' || state.phase === 'signingOut') { investigation.reset(); policies.reset(); shares.reset(); if (evidenceModule) void evidenceModule.then(module => module.evidenceController.reset()).catch(() => undefined); }
});
const root = document.getElementById('root');
if (!root) throw new Error('Missing console root');
createRoot(root).render(<>
  <a className="skip-link" href="#main">Skip to content</a>
  <SessionGate controller={controller}>{(session, scope) => <Suspense fallback={<p role="status">Loading evidence view…</p>}>{caseID ? <EvidenceBoundary path={"/cases/" + caseID}><EvidenceWorkspace session={session} scope={scope} caseID={caseID}/></EvidenceBoundary> : policyPage ? <PolicyWorkspace session={session} scope={scope} controller={policies}/> : sharesPage ? <SharesWorkspace session={session} scope={scope} controller={shares}/> : accessPreviewPage ? <AccessPreviewWorkspace session={session} scope={scope}/> : retentionPreviewPage ? <RetentionPreviewWorkspace session={session} scope={scope}/> : approvalsPage ? <ApprovalsWorkspace session={session} scope={scope} grantID={approvalID}/> : <CaptureWorkspace session={session} scope={scope} controller={investigation}/>}</Suspense>}</SessionGate>
</>);
