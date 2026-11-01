package capture

import (
	"bytes"
	"context"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type RecordingSaveGroupPreviewStore interface {
	CreateRecordingGroupPreview(context.Context, value.ContextPreview) error
	ReadRecordingGroupPreview(context.Context, string, string, identity.Principal) (value.ContextPreview, error)
}
type RecordingSaveGroupAdmissions interface {
	AdmitRecordingSaveGroup(context.Context, value.RecordingSaveGroupAdmission) (value.Accepted, error)
}

// ReviewedRecordingSaveGroupChild validates one exact child against the single
// protected group review. Acceptance clocks are sampled once by SQL; the preview
// fixes identities, windows and reviewed limits rather than a future t0.
func ReviewedRecordingSaveGroupChild(p value.ContextPreview, a value.Admission) bool {
	if p.Group == nil || !ValidContextPreview(p) || a.RecordingSave == nil || a.RootID != p.RootID || a.Requester() != p.Actor || a.Plan.Input.Executor != p.Group.Executor || a.Plan.ScopeDigest != p.ScopeDigest || !bytes.Equal(a.Plan.CanonicalScope, p.CanonicalScope) {
		return false
	}
	s := a.Plan.Input.Snapshot
	if s == nil || s.Group == nil || s.Group.ParentCaptureID != p.CaptureID || s.Group.SelectionDigest != p.ScopeDigest || s.Group.ChildCount != len(p.Group.Children) || s.Group.ChildIndex < 0 || s.Group.ChildIndex >= len(p.Group.Children) {
		return false
	}
	c := p.Group.Children[s.Group.ChildIndex]
	q, w := s.Request, c.Request
	// Only first-acceptance t0/dispatch/processing clocks may be reanchored.
	q.T0, q.IssuedAt, q.StartBy, q.ProcessingUntil = w.T0, w.IssuedAt, w.StartBy, w.ProcessingUntil
	if !q.Equal(w) || a.Plan.Input.CaptureID != c.CaptureID || a.CaseID != p.CaseID || a.OccurrenceID != c.OccurrenceID || a.Registration.Location.ArtifactID != c.ArtifactID || a.Registration.Location.AttemptID != c.AttemptID || s.PolicyUID != p.Group.PolicyUID || s.ExecutionDigest != p.Group.ExecutionDigest || s.ActionID != c.Reference.ActionID || s.SourceTarget == nil || s.SourceTarget.Request.PodUID != c.Reference.PodUID {
		return false
	}
	if _, err := compiler.ReadRecordingSaveChildScopeIdentity(p.CanonicalScope, p.ScopeDigest, *s.Group, c.CaptureID); err != nil {
		return false
	}
	r := a.Plan.Input.Retention
	if a.Plan.Input.Capability.Revision != c.CapabilityRevision || r.PolicyRevision != c.Retention.PolicyRevision || r.PurposeRef != c.Retention.PurposeRef || r.RequestedSeconds != c.Retention.RequestedSeconds || r.MaximumSeconds != c.Retention.MaximumSeconds || r.DeletionBudgetSeconds != c.Retention.DeletionBudgetSeconds {
		return false
	}
	d, err := compiler.SourceAudienceDigest(a.Eligibility.DefaultAudience)
	return err == nil && d == c.AudienceDigest && d != (artifact.Digest{}) && a.Registration.StoreID == p.Storage.StoreID && a.Registration.AllocationID == p.Storage.AllocationID && a.Registration.PoolRevision == p.Storage.PoolRevision && a.Registration.AllocationRevision == p.Storage.AllocationRevision
}
