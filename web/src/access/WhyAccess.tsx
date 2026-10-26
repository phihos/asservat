import { useState } from 'react';
import { Button } from 'react-aria-components';
import type { Session } from '../auth/session';
import type { Target } from '../capture/http';
import { operationMessage } from '../capture/http';
import { client as defaultClient, type AccessOperation, type Client, type Explanation } from './http';

const decisions: Record<Explanation['decision'], string> = {
  Allow: 'You have this access',
  Deny: 'You do not have this access',
  Indeterminate: 'Your access cannot be decided right now',
};

// "Why?" next to an unavailable or blocked operation (ADR-234). It asks the
// server to explain only the signed-in user's own access to this workload;
// nothing is requested until the user asks.
export function WhyAccess({ session, scope, target, operation, client = defaultClient }: { session: Session; scope: AbortSignal; target: Target; operation: AccessOperation; client?: Client }) {
  const [busy, setBusy] = useState(false);
  const [explanation, setExplanation] = useState<Explanation>();
  const [message, setMessage] = useState<string>();
  const explain = async () => {
    setBusy(true); setMessage(undefined); setExplanation(undefined);
    try {
      const result = await client.explain({ target_ref: target, operation }, session.csrf_token, scope);
      if (scope.aborted) return;
      if (result.status === 'ok') setExplanation(result.data);
      else if (result.status === 'error') setMessage(result.data.message);
      else setMessage('The explanation is not ready yet. Try again shortly.');
    } catch (error) {
      if (!scope.aborted) setMessage(operationMessage(error));
    } finally { if (!scope.aborted) setBusy(false); }
  };
  return <div className="why-access">
    <Button className="link-button" isDisabled={busy} onPress={() => void explain()}>{busy ? 'Checking your access…' : 'Why?'}</Button>
    {message && <p role="status">{message}</p>}
    {explanation && <section role="status" aria-label="Access explanation">
      <p><strong>{decisions[explanation.decision]}</strong>. {explanation.message}</p>
      {explanation.missing_scope && <p>Missing client scope: <span className="identifier">{explanation.missing_scope}</span></p>}
      {explanation.decision !== 'Allow' && <p>Roles that allow this: {explanation.required_roles.join(', ')}.</p>}
      {explanation.assignments.length > 0 && <ul>{explanation.assignments.map(a => <li key={a.assignment_id}>
        {a.effect === 'deny' ? 'Deny' : 'Allow'} {a.role} for your {a.subject_kind === 'Group' ? 'group' : 'account'} from {a.basis_kind} <span className="identifier">{a.basis_uid}</span> (assignment <span className="identifier">{a.assignment_id}</span>, revision <span className="identifier">{a.revision.slice(0, 12)}</span>)
      </li>)}</ul>}
    </section>}
  </div>;
}
