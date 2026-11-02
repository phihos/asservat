import { diffPlans, unchanged, type Change, type PlanSnapshot, type PreviousPlan } from './plan-diff';

function Changes({ caption, changes }: { caption: string; changes: Change[] }) {
  return <table className="plan-diff">
    <caption>{caption}</caption>
    <thead><tr><th scope="col">Setting</th><th scope="col">Before</th><th scope="col">After</th></tr></thead>
    <tbody>{changes.map(c => <tr key={c.label}><th scope="row">{c.label}</th><td>{c.before}</td><td>{c.after}</td></tr>)}</tbody>
  </table>;
}

// Compact before/after view of an edited plan (REQ-CPR-005). The server's
// review below remains authoritative for access, limits and approval.
export function PlanDiff({ previous, current }: { previous: PreviousPlan; current: PlanSnapshot }) {
  const diff = diffPlans(previous.plan, current);
  return <section className="review-section" aria-labelledby="plan-diff-heading">
    <h2 id="plan-diff-heading">Changes from the previous plan</h2>
    <p className="field-help">{previous.from === 'settings' ? <>Compared with the saved settings of capture <span className="identifier">{previous.captureID}</span>.</> : 'Compared with your previous review of this target.'}
      {!diff.costsCompared && ' Saved settings carry no cost assessment, so only settings and bounds are compared; the current assessment is below.'}</p>
    {unchanged(diff) ? <p>No changes from the previous plan.</p> : <>
      {diff.actions.length > 0 && <ul className="plan-diff-actions">{diff.actions.map(a => <li key={a.actionID}>
        <strong>{a.alias}</strong> · {a.status === 'added' ? 'Added' : a.status === 'removed' ? 'Removed' : 'Changed'}
        {a.changes.length > 0 && <Changes caption={`Changes to ${a.alias}`} changes={a.changes}/>}
      </li>)}</ul>}
      {diff.bounds.length > 0 && <Changes caption="Profiles and plan bounds" changes={diff.bounds}/>}
      {diff.costs.length > 0 && <Changes caption="Ongoing and per-incident costs" changes={diff.costs}/>}
    </>}
  </section>;
}
