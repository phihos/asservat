package capture

import (
	"bytes"

	value "asservat.local/asservat/internal/domain/capture"
)

// ReviewedCompositionGroupChild reports whether a is exactly child index of
// the reviewed composition group p (ADR-276): the human requester, the
// child's own identities, single-recording scope and retention review, the
// group's case and storage, and a plan whose scope the parent lists.
func ReviewedCompositionGroupChild(p value.ContextPreview, index int, a value.Admission) bool {
	g := p.CompositionGroup
	if g == nil || !ValidContextPreview(p) || index < 0 || index >= len(g.Children) || a.RecordingSave != nil || a.Plan.Input.Snapshot != nil || (a.Plan.Input.Recorder == nil) == (a.Plan.Input.Logs == nil) || a.Plan.Input.Profile != nil {
		return false
	}
	c := g.Children[index]
	r := a.Plan.Input.Retention
	return a.RootID == p.RootID && a.Requester() == p.Actor && a.Plan.Input.Executor == p.Actor &&
		a.Plan.ScopeDigest == c.ScopeDigest && bytes.Equal(a.Plan.CanonicalScope, c.CanonicalScope) &&
		a.Plan.Input.CaptureID == c.CaptureID && a.CaseID == p.CaseID && a.OccurrenceID == c.OccurrenceID &&
		a.Registration.Location.ArtifactID == c.ArtifactID && a.Registration.Location.AttemptID == c.AttemptID &&
		a.Plan.Input.Target.Request == p.Target &&
		r.PurposeRef == c.Retention.PurposeRef && r.RequestedSeconds == c.Retention.RequestedSeconds && r.MaximumSeconds == c.Retention.MaximumSeconds && r.DeletionBudgetSeconds == c.Retention.DeletionBudgetSeconds &&
		a.Registration.StoreID == p.Storage.StoreID && a.Registration.AllocationID == p.Storage.AllocationID && a.Registration.PoolRevision == p.Storage.PoolRevision && a.Registration.AllocationRevision == p.Storage.AllocationRevision
}
