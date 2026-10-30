package capture

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const MaxRecordingSaveGroupChildren = 16

// RecordingSaveGroupPreview is passive selection metadata. Original immutable
// source audiences/targets are resolved again by Reference, never duplicated as
// authority here. Relative retention and its protected revision bind the review.
type RecordingSaveGroupPreview struct {
	Executor              identity.Principal
	PolicyName, PolicyUID string
	ExecutionDigest       artifact.Digest
	Children              []RecordingSaveGroupChild
}
type RecordingSaveGroupChild struct {
	Reference                                                    RecordingReference
	CaptureID, ArtifactID, AttemptID, OccurrenceID, AssessmentID string
	Request                                                      artifact.SourceSnapshotRequest
	AudienceDigest                                               artifact.Digest
	CapabilityRevision                                           identity.Revision
	Retention                                                    RecordingSaveRetentionReview
}
type RecordingSaveRetentionReview struct {
	PurposeRef                                              string
	RequestedSeconds, MaximumSeconds, DeletionBudgetSeconds int64
	PolicyRevision                                          identity.Revision
}

func (r RecordingSaveRetentionReview) Valid() bool {
	return identity.Text(r.PurposeRef, 128) && r.RequestedSeconds >= 1 && r.RequestedSeconds <= 315360000 && r.MaximumSeconds >= 1 && r.MaximumSeconds <= 315360000 && r.DeletionBudgetSeconds >= 1 && r.DeletionBudgetSeconds <= 86400 && r.DeletionBudgetSeconds < r.MaximumSeconds && r.PolicyRevision.Valid()
}
func (g *RecordingSaveGroupPreview) Clone() *RecordingSaveGroupPreview {
	if g == nil {
		return nil
	}
	out := *g
	out.Children = slices.Clone(g.Children)
	return &out
}
func (g *RecordingSaveGroupPreview) valid(p ContextPreview) bool {
	if g == nil || len(g.Children) < 2 || len(g.Children) > MaxRecordingSaveGroupChildren || !g.Executor.Valid() || g.Executor != authorization.PolicyPrincipal(p.InstallationID, g.PolicyUID) || !identity.Text(g.PolicyName, 63) || !identity.Text(g.PolicyUID, 64) || g.ExecutionDigest == (artifact.Digest{}) {
		return false
	}
	if p.ArtifactID != "" || p.AttemptID != "" || p.OccurrenceID != "" || p.Pin != (artifact.PinnedPod{}) || len(p.Audience) != 0 || p.Intent.Snapshot != nil || p.Intent.Diagnostic != "" || p.Intent.Composition != nil || !p.Intent.Target.Valid() {
		return false
	}
	if !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) || !authorization.UUID(p.IssuerEpoch) || !p.Actor.Valid() || !p.Storage.Valid() || p.ScopeDigest == (artifact.Digest{}) || len(p.CanonicalScope) == 0 || len(p.CanonicalScope) > MaxContextPreviewScope || p.AssessmentRulesDigest == (artifact.Digest{}) || !previewTime(p.CreatedAt) || !previewTime(p.Deadline) || !p.Deadline.After(p.CreatedAt) || !previewTime(p.SelectionUntil) || !p.SelectionUntil.After(p.CreatedAt) || p.SelectionUntil.After(p.CreatedAt.Add(time.Minute)) || p.SelectionUntil.After(p.Deadline) {
		return false
	}
	if p.Target.PodUID != "" || p.Target.PodName != "" || !identity.Text(p.Target.Namespace.UID, 64) || !identity.Text(p.Target.Workload.UID, 64) || p.Target.ClusterID != p.Intent.Target.ClusterID || p.Target.Namespace.Name != p.Intent.Target.Namespace || p.Target.Workload.Name != p.Intent.Target.Name || p.Target.Workload.Kind != p.Intent.Target.Kind || p.Intent.HistoryAuthored != nil || p.Intent.Reason != nil && (!p.Intent.Reason.Valid() || p.Deadline.After(p.Intent.Reason.ExpiresAt)) || p.Intent.Sharing != nil && !p.Intent.Sharing.Valid() || p.Intent.RepeatedFrom != nil && (!authorization.UUID(p.Intent.RepeatedFrom.CaptureID) || p.Deadline.After(p.Intent.RepeatedFrom.ExpiresAt)) {
		return false
	}
	ids := map[string]bool{}
	for _, id := range []string{p.ID, p.CaptureID, p.CaseID, p.AssessmentID} {
		if !authorization.UUID(id) || ids[id] {
			return false
		}
		ids[id] = true
	}
	seenActions := map[string]bool{}
	var previous string
	for _, c := range g.Children {
		r := c.Reference
		if !r.Valid() || r.PolicyUID != g.PolicyUID || r.ExecutionDigest != g.ExecutionDigest || r.SourceID <= previous || seenActions[r.PodUID+"\x00"+r.ActionID] || !c.Request.Valid() || c.Request.SourceID != r.SourceID || c.Request.Fence != r.Fence || c.Request.SourceBindingDigest != r.BindingDigest || c.Request.After != 0 || c.Request.Before <= 0 || !c.Request.T0.Equal(p.CreatedAt) || c.Request.ProcessingUntil.After(p.Deadline) || c.AudienceDigest == (artifact.Digest{}) || !c.CapabilityRevision.Valid() || !c.Retention.Valid() {
			return false
		}
		previous = r.SourceID
		seenActions[r.PodUID+"\x00"+r.ActionID] = true
		for _, id := range []string{c.CaptureID, c.ArtifactID, c.AttemptID, c.OccurrenceID, c.AssessmentID, c.Request.SnapshotID} {
			if !authorization.UUID(id) || ids[id] {
				return false
			}
			ids[id] = true
		}
	}
	return true
}

// RecordingSaveGroupAdmission is one root-locked admission, not N public calls.
// The current independently checked child facts are transient; Preview is the
// single compact protected blueprint against which they must all be compared.
type RecordingSaveGroupAdmission struct {
	Preview                ContextPreview
	RootID, IdempotencyKey string
	SubmissionDigest       artifact.Digest
	Recovery               artifact.RecoveryProof
	Children               []Admission
}

// RecordingSaveGroupAccepted has no parent artifact/attempt. Every effect uses
// a real independently funded child capture and its original accepted t0.
type RecordingSaveGroupAccepted struct {
	CaseID   string
	Children []Accepted
}
